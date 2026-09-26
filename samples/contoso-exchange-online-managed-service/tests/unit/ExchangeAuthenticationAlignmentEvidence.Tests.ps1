#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:AsOfUtc = [datetimeoffset]'2026-09-25T12:00:00Z'
    $script:TenantId = '00000000-0000-0000-0000-000000000001'
    $script:DomainInventory = @(
        [pscustomobject]@{
            DomainName = 'contoso.example'
            Sending = $true
            SendingSystem = 'ExchangeOnline'
            SenderSource = [pscustomobject]@{ Reference = 'fixture:sender-scope:contoso'; SuppliedAtUtc = '2026-09-24T08:00:00Z' }
        }
        [pscustomobject]@{
            DomainName = 'fabrikam.example'
            Sending = $true
            SendingSystem = 'ExchangeOnline'
            SenderSource = [pscustomobject]@{ Reference = 'fixture:sender-scope:fabrikam'; SuppliedAtUtc = '2026-09-24T08:00:00Z' }
        }
    )

    function Copy-AuthenticationAlignmentFixture {
        param([Parameter(Mandatory)][object]$InputObject)

        $InputObject | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
    }

    function New-DkimAlignmentEvidence {
        [pscustomobject]@{
            ControlId = 'AUTH-001'
            Collected = $true
            Value = @(
                [pscustomobject]@{
                    Domain = 'contoso.example'
                    SigningConfiguration = [pscustomobject]@{ Enabled = $true; Status = 'Valid' }
                    Selector1Dns = [pscustomobject]@{ CanonicalName = 'selector1-contoso._domainkey.contoso.onmicrosoft.example' }
                    Selector2Dns = [pscustomobject]@{ CanonicalName = 'selector2-contoso._domainkey.contoso.onmicrosoft.example' }
                }
                [pscustomobject]@{
                    Domain = 'fabrikam.example'
                    SigningConfiguration = [pscustomobject]@{ Enabled = $true; Status = 'Valid' }
                    Selector1Dns = [pscustomobject]@{ CanonicalName = 'selector1-fabrikam._domainkey.fabrikam.onmicrosoft.example' }
                    Selector2Dns = [pscustomobject]@{ CanonicalName = 'selector2-fabrikam._domainkey.fabrikam.onmicrosoft.example' }
                }
            )
        }
    }

    function New-DnsAlignmentEvidence {
        [pscustomobject]@{
            ControlId = 'EXR-011-A03'
            Collected = $true
            Normalized = @(
                [pscustomobject]@{
                    Domain = 'contoso.example'
                    Spf = [pscustomobject]@{ Record = 'v=spf1 include:spf.protection.outlook.com -all'; OwnerProof = 'fixture:RAID-D04:contoso' }
                    Dmarc = [pscustomobject]@{ PolicyDomain = 'contoso.example'; Record = 'v=DMARC1; p=reject; sp=reject; pct=100'; OwnerProof = 'fixture:RAID-D04:contoso' }
                }
                [pscustomobject]@{
                    Domain = 'fabrikam.example'
                    Spf = [pscustomobject]@{ Record = 'v=spf1 include:spf.protection.outlook.com -all'; OwnerProof = 'fixture:RAID-D04:fabrikam' }
                    Dmarc = [pscustomobject]@{ PolicyDomain = 'fabrikam.example'; Record = 'v=DMARC1; p=reject; sp=reject; pct=100'; OwnerProof = 'fixture:RAID-D04:fabrikam' }
                }
            )
            Attestation = [pscustomobject]@{
                StagedAtUtc = '2026-09-24T09:00:00Z'
                PropagationCheckedAtUtc = '2026-09-24T10:00:00Z'
                CutoverApprovedAtUtc = '2026-09-24T11:00:00Z'
                RollbackTestedAtUtc = '2026-09-24T11:30:00Z'
            }
        }
    }

    function New-AuthenticationMessageProof {
        param(
            [string]$Domain,
            [string]$Selector = 'selector1'
        )

        $localPart = $Domain.Split('.')[0]
        [pscustomobject]@{
            Domain = $Domain
            MessageId = "<$localPart-authentication-proof@example.test>"
            ReceivedAtUtc = '2026-09-25T11:30:00Z'
            ReceivedHeaders = @('from synthetic.example (192.0.2.10) by fixture.exchange.example with ESMTPS')
            Sender = [pscustomobject]@{
                Address = "probe@$Domain"
                Scope = 'ExchangeOnline'
                Authorized = $true
                Reference = "fixture:sender-scope:$localPart"
            }
            AuthenticationResults = [pscustomobject]@{
                Spf = [pscustomobject]@{ Result = 'pass'; Domain = $Domain; Aligned = $true }
                Dkim = [pscustomobject]@{ Result = 'pass'; Domain = $Domain; Selector = $Selector; Aligned = $true }
                Dmarc = [pscustomobject]@{ Result = 'pass'; Domain = $Domain; Aligned = $true }
            }
        }
    }

    function New-AuthenticationMessagePage {
        [pscustomobject]@{
            Items = @(
                New-AuthenticationMessageProof -Domain 'contoso.example'
                New-AuthenticationMessageProof -Domain 'fabrikam.example'
            )
            Complete = $true
            NextLink = $null
        }
    }

    function Invoke-AuthenticationAlignmentFixture {
        param(
            [Parameter(Mandatory)][scriptblock]$Collection,
            [object]$DkimEvidence = (New-DkimAlignmentEvidence),
            [object]$DnsEvidence = (New-DnsAlignmentEvidence)
        )

        $evidence = Get-AuthenticationAlignmentEvidence -DomainInventory $script:DomainInventory `
            -DkimEvidence $DkimEvidence -DnsOwnerHandoffEvidence $DnsEvidence `
            -MessageProofCollection $Collection
        Test-AuthenticationAlignmentControl -Evidence $evidence -TenantId $script:TenantId `
            -AsOfUtc $script:AsOfUtc -MaximumProofAge ([timespan]::FromDays(1))
    }
}

AfterAll {
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-011-A04 offline message authentication and alignment evidence' {
    It 'fails closed for <Case>' -ForEach @(
        @{
            Case = 'received-header domain outside the complete sending denominator'
            Reason = 'AuthenticationAlignmentDomainMismatch'
            Change = { param($fixture) $fixture.Page.Items[0].Domain = 'other.example' }
        }
        @{
            Case = 'DKIM selector different from the exact Exchange signing state'
            Reason = 'AuthenticationAlignmentSelectorMismatch'
            Change = { param($fixture) $fixture.Page.Items[0].AuthenticationResults.Dkim.Selector = 'selector3' }
        }
        @{
            Case = 'DKIM signing state is not enabled and valid'
            Reason = 'AuthenticationDkimSigningStateInvalid'
            Change = { param($fixture) $fixture.Dkim.Value[0].SigningConfiguration.Status = 'CnameMissing' }
        }
        @{
            Case = 'missing received-message proof for one denominator domain'
            Reason = 'AuthenticationMessageProofMissing'
            Change = { param($fixture) $fixture.Page.Items = @($fixture.Page.Items[0]) }
        }
        @{
            Case = 'stale received-message proof'
            Reason = 'AuthenticationMessageProofStale'
            Change = { param($fixture) $fixture.Page.Items[0].ReceivedAtUtc = '2026-09-20T11:30:00Z' }
        }
        @{
            Case = 'SPF authentication failure'
            Reason = 'AuthenticationSpfFailed'
            Change = { param($fixture) $fixture.Page.Items[0].AuthenticationResults.Spf.Result = 'fail' }
        }
        @{
            Case = 'DKIM authentication failure'
            Reason = 'AuthenticationDkimFailed'
            Change = { param($fixture) $fixture.Page.Items[0].AuthenticationResults.Dkim.Result = 'fail' }
        }
        @{
            Case = 'DMARC authentication failure'
            Reason = 'AuthenticationDmarcFailed'
            Change = { param($fixture) $fixture.Page.Items[0].AuthenticationResults.Dmarc.Result = 'fail' }
        }
        @{
            Case = 'SPF domain alignment failure'
            Reason = 'AuthenticationSpfAlignmentFailed'
            Change = { param($fixture) $fixture.Page.Items[0].AuthenticationResults.Spf.Aligned = $false }
        }
        @{
            Case = 'DKIM domain alignment failure'
            Reason = 'AuthenticationDkimAlignmentFailed'
            Change = { param($fixture) $fixture.Page.Items[0].AuthenticationResults.Dkim.Aligned = $false }
        }
        @{
            Case = 'DMARC domain alignment failure'
            Reason = 'AuthenticationDmarcAlignmentFailed'
            Change = { param($fixture) $fixture.Page.Items[0].AuthenticationResults.Dmarc.Aligned = $false }
        }
        @{
            Case = 'sender outside the authorized Exchange sender scope'
            Reason = 'AuthenticationSenderUnauthorized'
            Change = { param($fixture) $fixture.Page.Items[0].Sender.Authorized = $false }
        }
        @{
            Case = 'message proof with incomplete raw identity'
            Reason = 'AuthenticationAlignmentEvidenceIncomplete'
            Change = { param($fixture) $fixture.Page.Items[0].PSObject.Properties.Remove('MessageId') }
        }
        @{
            Case = 'message-proof collection error'
            Reason = 'AuthenticationAlignmentCollectionFailed'
            Collection = { throw 'synthetic message archive unavailable' }
        }
        @{
            Case = 'incomplete paged message-proof collection'
            Reason = 'AuthenticationAlignmentPagingIncomplete'
            Change = { param($fixture) $fixture.Page.Complete = $false; $fixture.Page.NextLink = 'fixture:page-2' }
        }
        @{
            Case = 'ambiguous normalized message identity'
            Reason = 'AuthenticationAlignmentIdentityAmbiguous'
            Change = { param($fixture) $duplicate = Copy-AuthenticationAlignmentFixture $fixture.Page.Items[0]; $duplicate.Domain = ' CONTOSO.EXAMPLE. '; $fixture.Page.Items += $duplicate }
        }
        @{
            Case = 'independent SPF proof bound to another domain'
            Reason = 'AuthenticationSpfEvidenceMismatch'
            Change = { param($fixture) $fixture.Dns.Normalized[0].Domain = 'other.example' }
        }
        @{
            Case = 'independent DMARC proof bound to another policy domain'
            Reason = 'AuthenticationDmarcEvidenceMismatch'
            Change = { param($fixture) $fixture.Dns.Normalized[0].Dmarc.PolicyDomain = 'other.example' }
        }
        @{
            Case = 'missing independent cutover approval'
            Reason = 'AuthenticationCutoverEvidenceMissing'
            Change = { param($fixture) $fixture.Dns.Attestation.CutoverApprovedAtUtc = $null }
        }
    ) {
        # Arrange
        $fixture = [pscustomobject]@{
            Page = New-AuthenticationMessagePage
            Dkim = New-DkimAlignmentEvidence
            Dns = New-DnsAlignmentEvidence
        }
        if ($null -ne $_.Collection) {
            $collection = $_.Collection
        }
        else {
            & $_.Change $fixture
            $collection = { $fixture.Page }.GetNewClosure()
        }

        # Act
        $result = Invoke-AuthenticationAlignmentFixture -Collection $collection `
            -DkimEvidence $fixture.Dkim -DnsEvidence $fixture.Dns

        # Assert
        $result.Status | Should -BeIn @('Fail', 'Error')
        $result.Reason | Should -BeLike "$($_.Reason):*"
        $result.Status | Should -Not -Be 'Pass'
    }

    It 'passes one complete synthetic all-domain offline contract without claiming live delivery' {
        # Arrange
        $page = New-AuthenticationMessagePage
        $collection = { $page }.GetNewClosure()

        # Act
        $result = Invoke-AuthenticationAlignmentFixture -Collection $collection

        # Assert
        "$($result.ControlId)|$($result.Status)|$($result.OfflineContractOnly)|$($result.LiveDeliveryVerified)" |
            Should -Be 'EXR-011-A04|Pass|True|False'
        @($result.Normalized.Domain) | Should -Be @('contoso.example', 'fabrikam.example')
        @($result.Normalized.AuthenticationResults.Dkim.Selector | Select-Object -Unique) | Should -Be @('selector1')
        @($result.Normalized.AuthenticationResults.Spf.Aligned | Select-Object -Unique) | Should -Be @($true)
        @($result.Normalized.AuthenticationResults.Dkim.Aligned | Select-Object -Unique) | Should -Be @($true)
        @($result.Normalized.AuthenticationResults.Dmarc.Aligned | Select-Object -Unique) | Should -Be @($true)
        @($result.Normalized | Where-Object { @($_.ReceivedHeaders).Count -eq 0 -or -not $_.Sender.Authorized }).Count | Should -Be 0
        @($result.Normalized | Where-Object { -not $_.IndependentSpf -or -not $_.IndependentDmarc -or -not $_.CutoverAttestation }).Count | Should -Be 0
        $result.LiveVerificationOwner | Should -Be 'EXR-016-A03/EXR-017-A01/A02'
    }
}