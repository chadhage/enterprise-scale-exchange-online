#requires -Version 7.0

$DmarcDnsDefect = @(
    @{ Name = 'missing'; Records = @(); Pattern = 'DmarcRecordMissing:*' }
    @{ Name = 'duplicate'; Records = @('v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@contoso.com; ruf=mailto:forensic@contoso.com', 'v=DMARC1; p=reject'); Pattern = 'DmarcRecordDuplicated:*' }
    @{ Name = 'malformed'; Records = @('v=DMARC1; p'); Pattern = 'DmarcRecordMalformed:*' }
    @{ Name = 'weak p'; Records = @('v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@contoso.com; ruf=mailto:forensic@contoso.com'); Pattern = 'DmarcPolicyDrift:*p*quarantine*reject*' }
    @{ Name = 'weak sp'; Records = @('v=DMARC1; p=reject; sp=none; pct=100; rua=mailto:dmarc@contoso.com; ruf=mailto:forensic@contoso.com'); Pattern = 'DmarcPolicyDrift:*sp*none*reject*' }
    @{ Name = 'partial pct'; Records = @('v=DMARC1; p=reject; sp=reject; pct=75; rua=mailto:dmarc@contoso.com; ruf=mailto:forensic@contoso.com'); Pattern = 'DmarcPolicyDrift:*pct*75*100*' }
    @{ Name = 'missing aggregate destination'; Records = @('v=DMARC1; p=reject; sp=reject; pct=100; ruf=mailto:forensic@contoso.com'); Pattern = 'DmarcDestinationMissing:*rua*mailto:dmarc@contoso.com*' }
    @{ Name = 'missing forensic destination'; Records = @('v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@contoso.com'); Pattern = 'DmarcDestinationMissing:*ruf*mailto:forensic@contoso.com*' }
)

$DmarcReportRefusal = @(
    @{ Name = 'stale'; Reason = 'ExternalEvidenceStale: report exceeds its maximum age.' }
    @{ Name = 'unsigned'; Reason = 'ExternalEvidenceUnsigned: detached CMS signature is required.' }
    @{ Name = 'mismatched'; Reason = 'ExternalEvidenceTenantMismatch: report belongs to another tenant.' }
)

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:Domain = @('contoso.com', 'fabrikam.com')
    $script:CompliantDmarcRecord = 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@contoso.com; ruf=mailto:forensic@contoso.com'

    function New-DmarcAnswer {
        param(
            [string]$Domain,
            [object]$Authoritative = $true,
            [object[]]$Records = @($script:CompliantDmarcRecord)
        )

        [pscustomobject]@{
            Name = "_dmarc.$Domain"
            Authoritative = $Authoritative
            Records = @($Records)
            Ttl = 3600
        }
    }

    function New-DmarcReportDecision {
        param(
            [string[]]$Domain = $script:Domain,
            [string[]]$Refusal = @(),
            [hashtable]$PolicyOverride = @{}
        )

        $admitted = foreach ($name in $Domain) {
            $policy = [ordered]@{
                Policy = 'reject'
                SubdomainPolicy = 'reject'
                Percentage = 100
                AggregateReportAddress = 'mailto:dmarc@contoso.com'
                ForensicReportAddress = 'mailto:forensic@contoso.com'
            }
            foreach ($key in $PolicyOverride.Keys) { $policy[$key] = $PolicyOverride[$key] }

            [pscustomobject]@{
                EvidenceId = [guid]::NewGuid().ToString()
                ControlId = 'AUTH-003'
                Evidence = [pscustomobject]@{
                    GeneratedAtUtc = '2026-09-19T11:55:00.0000000Z'
                    Payload = [pscustomobject]@{ Domain = $name; Policy = [pscustomobject]$policy }
                }
            }
        }

        [pscustomobject]@{
            Satisfied = ($Refusal.Count -eq 0)
            Admitted = @($admitted)
            Refused = @($Refusal | ForEach-Object { [pscustomobject]@{ ControlId = 'AUTH-003'; Reason = @($_) } })
        }
    }

    function New-DmarcDesiredState {
        [pscustomobject]@{
            policy = 'reject'
            subdomainPolicy = 'reject'
            percentage = 100
            aggregateReportAddress = 'mailto:dmarc@contoso.com'
            forensicReportAddress = 'mailto:forensic@contoso.com'
        }
    }

    function Get-DmarcResult {
        param(
            [scriptblock]$Dns,
            [object]$ReportDecision = (New-DmarcReportDecision)
        )

        if (-not $PSBoundParameters.ContainsKey('Dns')) {
            $record = $script:CompliantDmarcRecord
            $Dns = { param($Domain) [pscustomobject]@{ Name = "_dmarc.$Domain"; Authoritative = $true; Records = @($record); Ttl = 3600 } }.GetNewClosure()
        }

        $evidence = Get-DmarcEvidence -SendingDomain $script:Domain -DmarcRecordCollection $Dns -ReportImportDecision $ReportDecision
        Test-DmarcControl -Evidence $evidence -DesiredState (New-DmarcDesiredState) -SendingDomain $script:Domain
    }
}

AfterAll {
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}

Describe 'AUTH-003 authoritative DMARC and signed report evidence' {
    Context 'Negative: the registered API must be shipped and callable only through injected evidence' {
        It 'exports the DMARC collector and evaluator' {
            # Arrange
            $expected = @('Get-DmarcEvidence', 'Test-DmarcControl')

            # Act
            $actual = @(Get-Command -Module ExchangeOnlineBaseline.Common -Name $expected -ErrorAction SilentlyContinue).Name

            # Assert
            $actual | Should -Be $expected
        }

        It 'refuses collection without every sending domain' {
            # Arrange
            $domain = @()

            # Act
            $act = { Get-DmarcEvidence -SendingDomain $domain -DmarcRecordCollection { } -ReportImportDecision (New-DmarcReportDecision) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DmarcSendingDomainRequired*'
        }

        It 'refuses collection without an authoritative-DNS seam' {
            # Arrange
            $dns = $null

            # Act
            $act = { Get-DmarcEvidence -SendingDomain $script:Domain -DmarcRecordCollection $dns -ReportImportDecision (New-DmarcReportDecision) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DmarcRecordCollectionRequired*'
        }

        It 'refuses collection without an EVD-008 report decision' {
            # Arrange
            $report = $null

            # Act
            $act = { Get-DmarcEvidence -SendingDomain $script:Domain -DmarcRecordCollection { } -ReportImportDecision $report }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DmarcReportDecisionRequired*'
        }

        It 'records a DNS dependency failure as uncollected evidence' {
            # Arrange
            $record = $script:CompliantDmarcRecord
            $dns = { param($Domain) if ($Domain -eq 'fabrikam.com') { throw 'authoritative server timed out' }; [pscustomobject]@{ Name = "_dmarc.$Domain"; Authoritative = $true; Records = @($record); Ttl = 3600 } }.GetNewClosure()

            # Act
            $evidence = Get-DmarcEvidence -SendingDomain $script:Domain -DmarcRecordCollection $dns -ReportImportDecision (New-DmarcReportDecision)

            # Assert
            ('{0}|{1}' -f $evidence.Collected, $evidence.FailureReason) | Should -BeLike 'False|CollectionFailed:*authoritative server timed out*'
        }
    }

    Context 'Negative: every domain requires one authoritative, parseable, strict record' {
        It 'fails a <Name> DMARC answer for its named reason' -ForEach $DmarcDnsDefect {
            # Arrange
            $records = $_.Records
            $dns = { param($Domain) [pscustomobject]@{ Name = "_dmarc.$Domain"; Authoritative = $true; Records = @($records); Ttl = 3600 } }.GetNewClosure()

            # Act
            $result = Get-DmarcResult -Dns $dns

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike "Fail|$($_.Pattern)"
        }

        It 'errors on a non-authoritative DMARC answer' {
            # Arrange
            $record = $script:CompliantDmarcRecord
            $dns = { param($Domain) [pscustomobject]@{ Name = "_dmarc.$Domain"; Authoritative = ($Domain -ne 'fabrikam.com'); Records = @($record); Ttl = 3600 } }.GetNewClosure()

            # Act
            $result = Get-DmarcResult -Dns $dns

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike 'Error|DmarcEvidenceInconclusive:*fabrikam.com*not authoritative*'
        }
    }

    Context 'Negative: every domain requires one admitted report matching the published policy' {
        It 'carries a <Name> EVD-008 refusal into a fail-closed error' -ForEach $DmarcReportRefusal {
            # Arrange
            $decision = New-DmarcReportDecision -Refusal @($_.Reason)

            # Act
            $result = Get-DmarcResult -ReportDecision $decision

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike "Error|DmarcReportRefused:*$($_.Reason)*"
        }

        It 'fails when a sending domain has no admitted report' {
            # Arrange
            $decision = New-DmarcReportDecision -Domain @('contoso.com')

            # Act
            $result = Get-DmarcResult -ReportDecision $decision

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike 'Fail|DmarcReportMissing:*fabrikam.com*'
        }

        It 'errors when a sending domain has duplicate admitted reports' {
            # Arrange
            $decision = New-DmarcReportDecision -Domain @('contoso.com', 'fabrikam.com', 'fabrikam.com')

            # Act
            $result = Get-DmarcResult -ReportDecision $decision

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike 'Error|DmarcReportDuplicated:*fabrikam.com*'
        }

        It 'fails when an admitted report policy mismatches authoritative DNS' {
            # Arrange
            $decision = New-DmarcReportDecision -PolicyOverride @{ Percentage = 50 }

            # Act
            $result = Get-DmarcResult -ReportDecision $decision

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike 'Fail|DmarcReportMismatch:*Percentage*50*100*'
        }
    }

    Context 'Positive: one complete all-domain fixture' {
        It 'passes only when every authoritative record is strict and every signed report matches it' {
            # Arrange
            $queriedDomain = [System.Collections.Generic.List[string]]::new()
            $record = $script:CompliantDmarcRecord
            $dns = { param($Domain) $queriedDomain.Add($Domain); [pscustomobject]@{ Name = "_dmarc.$Domain"; Authoritative = $true; Records = @($record); Ttl = 3600 } }.GetNewClosure()
            $decision = New-DmarcReportDecision

            # Act
            $result = Get-DmarcResult -Dns $dns -ReportDecision $decision

            # Assert
            ('{0}|{1}|{2}' -f $result.ControlId, $result.Status, (@($queriedDomain) -join ',')) |
                Should -BeExactly 'AUTH-003|Pass|contoso.com,fabrikam.com'
        }
    }
}