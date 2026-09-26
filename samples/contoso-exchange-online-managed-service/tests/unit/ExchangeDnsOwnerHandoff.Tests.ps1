#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:AsOfUtc = [datetimeoffset]'2026-09-25T12:00:00Z'
    $script:TenantId = '00000000-0000-0000-0000-000000000001'
    $script:DomainInventory = @(
        [pscustomobject]@{ DomainName = 'contoso.example'; ParentDomain = $null; Sending = $true }
        [pscustomobject]@{ DomainName = 'mail.contoso.example'; ParentDomain = 'contoso.example'; Sending = $true }
    )

    function Copy-DnsOwnerHandoff {
        param([Parameter(Mandatory)][object]$InputObject)

        $InputObject | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
    }

    function New-DnsOwnerHandoff {
        $ownerProof = [pscustomobject]@{
            Owner = 'Synthetic DNS owner'
            Reference = 'fixture:RAID-D04:change-127'
            TenantId = $script:TenantId
            Domain = 'contoso.example'
            SuppliedAtUtc = '2026-09-24T09:00:00Z'
            ExpiresAtUtc = '2026-10-25T09:00:00Z'
        }
        $attestation = [pscustomobject]@{
            StagedAtUtc = '2026-09-24T10:00:00Z'
            PropagationCheckedAtUtc = '2026-09-24T11:00:00Z'
            CutoverApprovedAtUtc = '2026-09-24T12:00:00Z'
            RollbackTestedAtUtc = '2026-09-24T13:00:00Z'
        }

        [pscustomobject]@{
            Domain = 'contoso.example'
            TenantId = $script:TenantId
            Mx = [pscustomobject]@{
                Hosts = @('contoso-example.mail.protection.outlook.com')
                Provenance = 'MicrosoftProvided'
                Reference = 'fixture:exchange-admin-center:mx'
                SuppliedAtUtc = '2026-09-24T09:00:00Z'
            }
            Autodiscover = [pscustomobject]@{ Target = 'autodiscover.outlook.com'; OwnerProof = $ownerProof }
            Spf = [pscustomobject]@{ Record = 'v=spf1 include:spf.protection.outlook.com -all'; OwnerProof = $ownerProof }
            Dmarc = [pscustomobject]@{
                RecordName = '_dmarc.contoso.example'
                PolicyDomain = 'contoso.example'
                Inherited = $false
                Record = 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@contoso.example'
                OwnerProof = $ownerProof
            }
            MtaSts = [pscustomobject]@{
                RecordName = '_mta-sts.contoso.example'
                PolicyUri = 'https://mta-sts.contoso.example/.well-known/mta-sts.txt'
                OwnerProof = $ownerProof
            }
            TlsRpt = [pscustomobject]@{
                RecordName = '_smtp._tls.contoso.example'
                Record = 'v=TLSRPTv1; rua=mailto:tlsrpt@contoso.example'
                OwnerProof = $ownerProof
            }
            Reporting = [pscustomobject]@{
                AggregateAddress = 'dmarc@contoso.example'
                TlsReportAddress = 'tlsrpt@contoso.example'
                OwnerProof = $ownerProof
            }
            OwnerProof = $ownerProof
            Attestation = $attestation
        }
    }

    function New-DnsOwnerHandoffPage {
        $parent = New-DnsOwnerHandoff
        $child = Copy-DnsOwnerHandoff $parent
        $child.Domain = 'mail.contoso.example'
        $child.OwnerProof.Domain = 'mail.contoso.example'
        $child.Dmarc.PolicyDomain = 'contoso.example'
        $child.Dmarc.Inherited = $true

        [pscustomobject]@{
            Items = @($parent, $child)
            Complete = $true
            NextLink = $null
        }
    }

    function Invoke-DnsOwnerHandoffFixture {
        param([Parameter(Mandatory)][scriptblock]$Collection)

        $evidence = Get-DnsOwnerHandoffEvidence -DomainInventory $script:DomainInventory -HandoffCollection $Collection
        Test-DnsOwnerHandoffControl -Evidence $evidence -TenantId $script:TenantId -AsOfUtc $script:AsOfUtc -MaximumProofAge ([timespan]::FromDays(30))
    }
}

AfterAll {
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-011-A03 authoritative DNS-owner handoff contract' {
    It 'returns Unverified for <Case>' -ForEach @(
        @{
            Case = 'invented MX provenance from accepted-domain state'
            Reason = 'DnsMxProvenanceInvalid'
            Change = { param($page) $page.Items[0].Mx.Provenance = 'Get-AcceptedDomain' }
        }
        @{
            Case = 'wrong parent for inherited subdomain DMARC'
            Reason = 'DnsDmarcInheritanceInvalid'
            Change = { param($page) $page.Items[1].Dmarc.PolicyDomain = 'fabrikam.example' }
        }
        @{
            Case = 'missing owner proof'
            Reason = 'DnsOwnerProofMissing'
            Change = { param($page) $page.Items[0].OwnerProof = $null }
        }
        @{
            Case = 'stale owner proof'
            Reason = 'DnsOwnerProofStale'
            Change = { param($page) $page.Items[0].OwnerProof.SuppliedAtUtc = '2026-07-01T09:00:00Z' }
        }
        @{
            Case = 'owner proof bound to another domain'
            Reason = 'DnsOwnerProofBindingMismatch'
            Change = { param($page) $page.Items[0].OwnerProof.Domain = 'fabrikam.example' }
        }
        @{
            Case = 'incomplete raw identity'
            Reason = 'DnsOwnerHandoffIncomplete'
            Change = { param($page) $page.Items[1].PSObject.Properties.Remove('Domain') }
        }
        @{
            Case = 'raw collection error'
            Reason = 'DnsOwnerHandoffCollectionFailed'
            Collection = { throw 'synthetic owner registry unavailable' }
        }
        @{
            Case = 'paged raw collection'
            Reason = 'DnsOwnerHandoffPagingIncomplete'
            Change = { param($page) $page.Complete = $false; $page.NextLink = 'fixture:page-2' }
        }
        @{
            Case = 'ambiguous normalized identity'
            Reason = 'DnsOwnerHandoffIdentityAmbiguous'
            Change = { param($page) $duplicate = Copy-DnsOwnerHandoff $page.Items[0]; $duplicate.Domain = ' CONTOSO.EXAMPLE. '; $page.Items += $duplicate }
        }
    ) {
        # Arrange
        if ($null -ne $_.Collection) {
            $collection = $_.Collection
        }
        else {
            $page = New-DnsOwnerHandoffPage
            & $_.Change $page
            $collection = { $page }.GetNewClosure()
        }

        # Act
        $result = Invoke-DnsOwnerHandoffFixture -Collection $collection

        # Assert
        $result.Status | Should -Be 'Unverified'
        $result.Reason | Should -BeLike "$($_.Reason):*"
        $result.Status | Should -Not -Be 'Pass'
    }

    It 'validates a complete synthetic handoff while retaining external DNS readiness as Unverified' {
        # Arrange
        $page = New-DnsOwnerHandoffPage
        $collection = { $page }.GetNewClosure()

        # Act
        $result = Invoke-DnsOwnerHandoffFixture -Collection $collection

        # Assert
        $result.Status | Should -Be 'Unverified'
        $result.Reason | Should -BeLike 'ExternalDnsPrerequisiteUnverified:*RAID-D04*'
        $result.Status | Should -Not -Be 'Pass'
        @($result.Normalized).Count | Should -Be 2
        @($result.Normalized.Mx.Provenance | Select-Object -Unique) | Should -Be @('MicrosoftProvided')
        @($result.Normalized.Dmarc | Where-Object Inherited).PolicyDomain | Should -Be @('contoso.example')
        @($result.Normalized.Autodiscover.Target | Select-Object -Unique) | Should -Be @('autodiscover.outlook.com')
        @($result.Normalized.Attestation.PSObject.Properties.Name | Sort-Object -Unique) | Should -Be @(
            'CutoverApprovedAtUtc'
            'PropagationCheckedAtUtc'
            'RollbackTestedAtUtc'
            'StagedAtUtc'
        )
        @($result.Normalized | Where-Object { -not $_.Spf -or -not $_.MtaSts -or -not $_.TlsRpt -or -not $_.Reporting }).Count | Should -Be 0
    }
}