#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:BaselinePath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:ParameterPath = Join-Path $script:SampleRoot 'tests' 'fixtures' 'com003' 'parameters.gateway.complete.json'
    $script:ModuleName = 'ExchangeOnlineBaseline.Common'
    $script:SuppliedSecret = 'secops@contoso.example'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function Get-FreshResolution {
        [CmdletBinding()]
        param()

        return Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'
    }

    function Measure-FileCount {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        return @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue).Count
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-004-A4 non-persistence of resolved configuration and secrets' {

    BeforeEach {
        $global:BaselinePersistenceAttempt = [System.Collections.Generic.List[string]]::new()

        foreach ($writer in @('Set-Content', 'Add-Content', 'Out-File', 'Export-Clixml', 'Export-Csv', 'New-TemporaryFile')) {
            Mock -CommandName $writer -ModuleName $script:ModuleName -MockWith {
                $global:BaselinePersistenceAttempt.Add($PesterBoundParameters.PSCommandName)
            }
        }

        $script:OriginalTemp = $env:TEMP
        $script:OriginalTmp = $env:TMP
        $script:RedirectedTemp = Join-Path $TestDrive ('temp-{0}' -f [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:RedirectedTemp -Force | Out-Null
        $env:TEMP = $script:RedirectedTemp
        $env:TMP = $script:RedirectedTemp

        $script:WorkingDirectory = Join-Path $TestDrive ('work-{0}' -f [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:WorkingDirectory -Force | Out-Null
    }

    AfterEach {
        $env:TEMP = $script:OriginalTemp
        $env:TMP = $script:OriginalTmp
        Remove-Variable -Name 'BaselinePersistenceAttempt' -Scope Global -Force -ErrorAction SilentlyContinue
    }

    Context 'Negative: canonicalization must not persist anything' {

        It 'does not invoke Set-Content while producing a canonical text' {
            # Arrange
            $configuration = (Get-FreshResolution).Configuration

            # Act
            $null = ConvertTo-CanonicalJson -InputObject $configuration

            # Assert
            Should -Invoke -CommandName 'Set-Content' -ModuleName $script:ModuleName -Times 0 -Exactly
        }

        It 'does not invoke Out-File while producing a canonical text' {
            # Arrange
            $configuration = (Get-FreshResolution).Configuration

            # Act
            $null = ConvertTo-CanonicalJson -InputObject $configuration

            # Assert
            Should -Invoke -CommandName 'Out-File' -ModuleName $script:ModuleName -Times 0 -Exactly
        }

        It 'does not create a file in the redirected temporary directory while producing a canonical text' {
            # Arrange
            $configuration = (Get-FreshResolution).Configuration

            # Act
            $null = ConvertTo-CanonicalJson -InputObject $configuration

            # Assert
            (Measure-FileCount -Path $script:RedirectedTemp) | Should -Be 0
        }
    }

    Context 'Negative: hashing must not persist anything' {

        It 'does not invoke Set-Content while hashing a resolution' {
            # Arrange
            $resolution = Get-FreshResolution

            # Act
            $null = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            Should -Invoke -CommandName 'Set-Content' -ModuleName $script:ModuleName -Times 0 -Exactly
        }

        It 'does not invoke Add-Content while hashing a resolution' {
            # Arrange
            $resolution = Get-FreshResolution

            # Act
            $null = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            Should -Invoke -CommandName 'Add-Content' -ModuleName $script:ModuleName -Times 0 -Exactly
        }

        It 'does not invoke Out-File while hashing a resolution' {
            # Arrange
            $resolution = Get-FreshResolution

            # Act
            $null = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            Should -Invoke -CommandName 'Out-File' -ModuleName $script:ModuleName -Times 0 -Exactly
        }

        It 'does not invoke Export-Clixml while hashing a resolution' {
            # Arrange
            $resolution = Get-FreshResolution

            # Act
            $null = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            Should -Invoke -CommandName 'Export-Clixml' -ModuleName $script:ModuleName -Times 0 -Exactly
        }

        It 'does not invoke Export-Csv while hashing a resolution' {
            # Arrange
            $resolution = Get-FreshResolution

            # Act
            $null = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            Should -Invoke -CommandName 'Export-Csv' -ModuleName $script:ModuleName -Times 0 -Exactly
        }

        It 'does not invoke New-TemporaryFile while hashing a resolution' {
            # Arrange
            $resolution = Get-FreshResolution

            # Act
            $null = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            Should -Invoke -CommandName 'New-TemporaryFile' -ModuleName $script:ModuleName -Times 0 -Exactly
        }
    }

    Context 'Negative: no supplied value may reach disk' {

        It 'does not leave an administrator-supplied value in the redirected temporary directory' {
            # Arrange
            $resolution = Get-FreshResolution

            # Act
            $null = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            @(Get-ChildItem -LiteralPath $script:RedirectedTemp -Recurse -File -Force -ErrorAction SilentlyContinue | Select-String -SimpleMatch -Pattern $script:SuppliedSecret) | Should -BeNullOrEmpty
        }

        It 'does not leave an administrator-supplied value in the working directory' {
            # Arrange
            Push-Location -LiteralPath $script:WorkingDirectory

            # Act
            try { $null = Get-BaselineConfigurationHash -Resolution (Get-FreshResolution) } finally { Pop-Location }

            # Assert
            @(Get-ChildItem -LiteralPath $script:WorkingDirectory -Recurse -File -Force -ErrorAction SilentlyContinue | Select-String -SimpleMatch -Pattern $script:SuppliedSecret) | Should -BeNullOrEmpty
        }
    }

    Context 'Positive: a full cycle persists nothing' {

        It 'resolves, canonicalizes and hashes with no file-writing command invoked and no file created' {
            # Arrange
            Push-Location -LiteralPath $script:WorkingDirectory

            # Act
            try {
                $resolution = Get-FreshResolution
                $null = ConvertTo-CanonicalJson -InputObject $resolution.Configuration
                $null = Get-BaselineConfigurationHash -Resolution $resolution
            }
            finally {
                Pop-Location
            }

            # Assert
            ('Writers={0};TempFiles={1};WorkingFiles={2}' -f $global:BaselinePersistenceAttempt.Count, (Measure-FileCount -Path $script:RedirectedTemp), (Measure-FileCount -Path $script:WorkingDirectory)) | Should -BeExactly 'Writers=0;TempFiles=0;WorkingFiles=0'
        }
    }
}
