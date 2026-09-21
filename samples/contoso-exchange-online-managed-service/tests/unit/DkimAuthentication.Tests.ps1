#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-DkimConfig {
        param(
            [string]$Domain = 'contoso.example',
            [object]$Enabled = $true,
            [object]$Status = 'Valid',
            [object]$Selector1CNAME = 'selector1-contoso._domainkey.contoso.onmicrosoft.example',
            [object]$Selector2CNAME = 'selector2-contoso._domainkey.contoso.onmicrosoft.example',
            [object]$Selector1KeySize = 2048,
            [object]$Selector2KeySize = 2048,
            [hashtable]$Remove = @{}
        )

        $config = [ordered]@{
            DomainName       = $Domain
            Enabled          = $Enabled
            Status           = $Status
            Selector1CNAME   = $Selector1CNAME
            Selector2CNAME   = $Selector2CNAME
            Selector1KeySize = $Selector1KeySize
            Selector2KeySize = $Selector2KeySize
            RotateOnDate     = '2027-01-01T00:00:00Z'
        }
        foreach ($name in $Remove.Keys) { $config.Remove($name) }
        return [pscustomobject]$config
    }

    function New-DkimDnsAnswer {
        param(
            [string]$Name = 'selector1._domainkey.contoso.example',
            [object]$Authoritative = $true,
            [object]$CanonicalName = 'selector1-contoso._domainkey.contoso.onmicrosoft.example',
            [object]$TTL = 3600
        )

        return [pscustomobject]@{
            Name          = $Name
            Authoritative = $Authoritative
            CanonicalName = $CanonicalName
            TTL           = $TTL
        }
    }

    function New-DkimEvidenceFixture {
        param(
            [string[]]$SendingDomain = @('contoso.example'),
            [scriptblock]$ConfigCollection,
            [scriptblock]$DnsCollection
        )

        if (-not $PSBoundParameters.ContainsKey('ConfigCollection')) {
            $ConfigCollection = { param($Domain) New-DkimConfig -Domain $Domain }
        }
        if (-not $PSBoundParameters.ContainsKey('DnsCollection')) {
            $DnsCollection = {
                param($Name)
                $selector = if ($Name.StartsWith('selector1.', [System.StringComparison]::OrdinalIgnoreCase)) { 'selector1' } else { 'selector2' }
                New-DkimDnsAnswer -Name $Name -CanonicalName "$selector-contoso._domainkey.contoso.onmicrosoft.example"
            }
        }

        return Get-DkimEvidence -SendingDomain $SendingDomain `
            -DkimSigningConfigCollection $ConfigCollection -SelectorDnsCollection $DnsCollection
    }

    function New-DesiredDkimState {
        return [pscustomobject]@{ enabled = $true; keySize = 2048 }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'AUTH-001 DKIM authentication' {
    Context 'Negative: the registered DKIM surface must ship' {
        It 'exports the collector and evaluator declared for AUTH-001' {
            # Arrange
            $expected = @('Get-DkimEvidence', 'Test-DkimControl')

            # Act
            $actual = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $expected -ErrorAction SilentlyContinue).Name

            # Assert
            $actual | Should -Be $expected
        }
    }

    Context 'Negative: collection prerequisites are mandatory' {
        It 'refuses a collection with no sending domain' {
            # Arrange
            $domains = @()

            # Act
            $act = { Get-DkimEvidence -SendingDomain $domains -DkimSigningConfigCollection { } -SelectorDnsCollection { } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DkimSendingDomainRequired*'
        }

        It 'refuses duplicate sending domains after normalization' {
            # Arrange
            $domains = @('contoso.example', ' CONTOSO.EXAMPLE. ')

            # Act
            $act = { Get-DkimEvidence -SendingDomain $domains -DkimSigningConfigCollection { } -SelectorDnsCollection { } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DkimSendingDomainDuplicate*contoso.example*'
        }

        It 'refuses a collection with no injected signing-config seam' {
            # Arrange
            $configCollection = $null

            # Act
            $act = { Get-DkimEvidence -SendingDomain 'contoso.example' -DkimSigningConfigCollection $configCollection -SelectorDnsCollection { } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DkimSigningConfigCollectionRequired*'
        }

        It 'refuses a collection with no injected authoritative-DNS seam' {
            # Arrange
            $dnsCollection = $null

            # Act
            $act = { Get-DkimEvidence -SendingDomain 'contoso.example' -DkimSigningConfigCollection { } -SelectorDnsCollection $dnsCollection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DkimSelectorDnsCollectionRequired*'
        }
    }

    Context 'Negative: every sending domain and raw source answer must survive collection' {
        It 'records a signing-config refusal as uncollected evidence' {
            # Arrange
            $refusing = { param($Domain) throw "config refused for $Domain" }

            # Act
            $evidence = New-DkimEvidenceFixture -ConfigCollection $refusing

            # Assert
            "$($evidence.Collected)|$($evidence.FailureReason)" | Should -BeLike 'False|CollectionFailed:*config refused for contoso.example*'
        }

        It 'records an authoritative-DNS refusal as uncollected evidence' {
            # Arrange
            $refusing = { param($Name) throw "DNS refused for $Name" }

            # Act
            $evidence = New-DkimEvidenceFixture -DnsCollection $refusing

            # Assert
            "$($evidence.Collected)|$($evidence.FailureReason)" | Should -BeLike 'False|CollectionFailed:*DNS refused for selector1._domainkey.contoso.example*'
        }

        It 'does not omit a requested sending domain or either selector lookup' {
            # Arrange
            $script:configCalls = [System.Collections.Generic.List[string]]::new()
            $script:dnsCalls = [System.Collections.Generic.List[string]]::new()
            $config = {
                param($Domain)
                $script:configCalls.Add($Domain)
                $token = $Domain.Split('.')[0]
                New-DkimConfig -Domain $Domain `
                    -Selector1CNAME "selector1-$token._domainkey.tenant.example" `
                    -Selector2CNAME "selector2-$token._domainkey.tenant.example"
            }
            $dns = {
                param($Name)
                $script:dnsCalls.Add($Name)
                $parts = $Name.Split('.')
                New-DkimDnsAnswer -Name $Name -CanonicalName "$($parts[0])-$($parts[2])._domainkey.tenant.example"
            }

            # Act
            $evidence = New-DkimEvidenceFixture -SendingDomain @('contoso.example', 'fabrikam.example') -ConfigCollection $config -DnsCollection $dns

            # Assert
            @($evidence.Value.Domain) | Should -Be @('contoso.example', 'fabrikam.example')
            $script:configCalls | Should -Be @('contoso.example', 'fabrikam.example')
            $script:dnsCalls | Should -Be @(
                'selector1._domainkey.contoso.example', 'selector2._domainkey.contoso.example',
                'selector1._domainkey.fabrikam.example', 'selector2._domainkey.fabrikam.example'
            )
        }

        It 'retains unfiltered signing-config and DNS members without folding a verdict' {
            # Arrange
            $config = { param($Domain) New-DkimConfig -Domain $Domain }
            $dns = { param($Name) New-DkimDnsAnswer -Name $Name }

            # Act
            $evidence = New-DkimEvidenceFixture -ConfigCollection $config -DnsCollection $dns

            # Assert
            $evidence.Value[0].SigningConfiguration.RotateOnDate | Should -Be '2027-01-01T00:00:00Z'
            $evidence.Value[0].Selector1Dns.TTL | Should -Be 3600
            $evidence.Value[0].Selector2Dns.TTL | Should -Be 3600
            @($evidence.Value[0].PSObject.Properties.Name) | Should -Not -Contain 'Status'
            @($evidence.Value[0].PSObject.Properties.Name) | Should -Not -Contain 'Compliant'
        }
    }

    Context 'Negative: incomplete or ambiguous DKIM evidence fails closed' {
        It 'fails when a sending domain has no signing configuration' {
            # Arrange
            $evidence = New-DkimEvidenceFixture -ConfigCollection { param($Domain) $null }

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike 'Fail|DkimSigningConfigurationMissing:*contoso.example*'
        }

        It 'errors when a sending domain has duplicate signing configurations' {
            # Arrange
            $evidence = New-DkimEvidenceFixture -ConfigCollection {
                param($Domain)
                $first = New-DkimConfig -Domain $Domain
                $second = New-DkimConfig -Domain $Domain
                @($first, $second)
            }

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike 'Error|DkimSigningConfigurationDuplicate:*contoso.example*'
        }

        It 'errors when a signing configuration is malformed' {
            # Arrange
            $evidence = New-DkimEvidenceFixture -ConfigCollection { param($Domain) New-DkimConfig -Domain $Domain -Remove @{ Selector2CNAME = $true } }

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike "Error|DkimEvidenceMalformed:*contoso.example*Selector2CNAME*"
        }

        It 'fails when signing is disabled' {
            # Arrange
            $evidence = New-DkimEvidenceFixture -ConfigCollection { param($Domain) New-DkimConfig -Domain $Domain -Enabled $false }

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike 'Fail|DkimSigningDisabled:*contoso.example*'
        }

        It 'fails when Exchange reports a status other than Valid' {
            # Arrange
            $evidence = New-DkimEvidenceFixture -ConfigCollection { param($Domain) New-DkimConfig -Domain $Domain -Status 'CnameMissing' }

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike "Fail|DkimSigningInvalid:*contoso.example*CnameMissing*"
        }

        It 'errors when a selector answer is not authoritative' {
            # Arrange
            $dns = { param($Name) New-DkimDnsAnswer -Name $Name -Authoritative ($Name -notlike 'selector2.*') }
            $evidence = New-DkimEvidenceFixture -DnsCollection $dns

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike 'Error|DkimDnsNonAuthoritative:*contoso.example*selector2*'
        }

        It 'fails when a selector resolves to a target other than the Exchange configuration' {
            # Arrange
            $dns = {
                param($Name)
                $target = if ($Name -like 'selector1.*') { 'wrong._domainkey.tenant.example' } else { 'selector2-contoso._domainkey.contoso.onmicrosoft.example' }
                New-DkimDnsAnswer -Name $Name -CanonicalName $target
            }
            $evidence = New-DkimEvidenceFixture -DnsCollection $dns

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike 'Fail|DkimSelectorMismatch:*contoso.example*selector1*wrong._domainkey.tenant.example*'
        }

        It 'fails when a selector key is absent from authoritative DNS' {
            # Arrange
            $dns = { param($Name) New-DkimDnsAnswer -Name $Name -CanonicalName $(if ($Name -like 'selector1.*') { $null } else { 'selector2-contoso._domainkey.contoso.onmicrosoft.example' }) }
            $evidence = New-DkimEvidenceFixture -DnsCollection $dns

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike 'Fail|DkimSelectorKeyAbsent:*contoso.example*selector1*'
        }

        It 'fails when either selector key is shorter than 2048 bits' {
            # Arrange
            $evidence = New-DkimEvidenceFixture -ConfigCollection { param($Domain) New-DkimConfig -Domain $Domain -Selector2KeySize 1024 }

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike 'Fail|DkimKeyTooShort:*contoso.example*selector2*1024*2048*'
        }

        It 'errors when an evidence record omits a requested domain observation' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'AUTH-001' -Source 'ExchangeOnline+AuthoritativeDns' `
                -Command 'Get-DkimSigningConfig; Resolve-DnsName -Type CNAME' -Value @()

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.Status)|$($result.Reason)" | Should -BeLike 'Error|DkimEvidenceIncomplete:*no sending-domain observations*'
        }
    }

    Context 'Positive: every sending domain has complete authoritative 2048-bit DKIM evidence' {
        It 'passes one complete all-domain fixture' {
            # Arrange
            $config = {
                param($Domain)
                $token = $Domain.Split('.')[0]
                New-DkimConfig -Domain $Domain `
                    -Selector1CNAME "selector1-$token._domainkey.tenant.example" `
                    -Selector2CNAME "selector2-$token._domainkey.tenant.example"
            }
            $dns = {
                param($Name)
                $parts = $Name.Split('.')
                New-DkimDnsAnswer -Name $Name -CanonicalName "$($parts[0])-$($parts[2])._domainkey.tenant.example"
            }
            $evidence = New-DkimEvidenceFixture -SendingDomain @('contoso.example', 'fabrikam.example') `
                -ConfigCollection $config -DnsCollection $dns

            # Act
            $result = Test-DkimControl -Evidence $evidence -DesiredState (New-DesiredDkimState)

            # Assert
            "$($result.ControlId)|$($result.Status)|$($result.GoLiveSuccess)|$($result.Evidence.ControlId)" |
                Should -Be 'AUTH-001|Pass|True|AUTH-001'
        }
    }
}
