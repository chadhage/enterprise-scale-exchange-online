BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force

    function New-OofDesired {
        param([string]$Type = 'None', [object]$Approval = $null)
        return @{
            autoForwardEnabled = $false; autoReplyEnabled = $false
            allowedOOFType = $Type; externalReplyApproval = $Approval
            deliveryReportEnabled = $false; nonDeliveryReportEnabled = $false
        }
    }

    function New-OofDomain {
        param([string]$Identity = 'Default', [string]$Domain = '*', [string]$Type = 'None')
        return @{
            Identity = $Identity; DomainName = $Domain; AllowedOOFType = $Type
            AutoForwardEnabled = $false; AutoReplyEnabled = $false
            DeliveryReportEnabled = $false; NDREnabled = $false
        }
    }
}

Describe 'EXR-002 OOF policy admission' {
    It 'rejects unsafe or unknown desired OOF type <Type>' -ForEach @(
        @{ Type = 'InternalLegacy' }, @{ Type = 'ExternalLegacy' }, @{ Type = 'All' }, @{ Type = '' }
    ) {
        # Arrange
        $desired = New-OofDesired -Type $Type
        $evidence = Get-RemoteDomainEvidence -Collection { New-OofDomain -Type $Type }
        # Act
        $act = { Test-RemoteDomainControl -Evidence $evidence -DesiredState $desired }
        # Assert
        $act | Should -Throw '*RemoteDomainOofPolicyInvalid*'
    }

    It 'rejects External without a nonblank approval reference: <Label>' -ForEach @(
        @{ Label = 'absent'; Approval = $null }, @{ Label = 'empty'; Approval = '' },
        @{ Label = 'whitespace'; Approval = '  ' }, @{ Label = 'boolean'; Approval = $true }
    ) {
        # Arrange
        $desired = New-OofDesired -Type External -Approval $Approval
        $evidence = Get-RemoteDomainEvidence -Collection { New-OofDomain -Type External }
        # Act
        $act = { Test-RemoteDomainControl -Evidence $evidence -DesiredState $desired }
        # Assert
        $act | Should -Throw '*RemoteDomainExternalApprovalRequired*'
    }
    It 'resolves the explicit external-reply policy with its approval reference' {
        # Arrange
        $desired = New-OofDesired -Type External -Approval 'CHG-2026-0042 / Exchange service owner'
        # Act
        $type = Resolve-BaselineRemoteDomainOofType -DesiredState $desired
        # Assert
        $type | Should -BeExactly External
    }
}

Describe 'EXR-002 effective domain evidence' {
    It 'identifies the effective specific-domain OOF conflict for <Type>' -ForEach @(
        @{ Type = 'InternalLegacy' }, @{ Type = 'External' }, @{ Type = 'ExternalLegacy' }
    ) {
        # Arrange
        $desired = New-OofDesired
        $evidence = Get-RemoteDomainEvidence -Collection {
            New-OofDomain
            New-OofDomain -Identity Partner -Domain '*.partner.example' -Type $Type
        }
        # Act
        $result = Test-RemoteDomainControl -Evidence $evidence -DesiredState $desired
        # Assert
        "$($result.Status)|$($result.Reason)" | Should -BeLike "Fail|RemoteDomainDrift:*Partner*[*].partner.example*AllowedOOFType*$Type*None*"
    }

    It 'rejects an observation missing the wildcard default' {
        # Arrange
        $desired = New-OofDesired
        $evidence = Get-RemoteDomainEvidence -Collection { New-OofDomain -Identity Partner -Domain partner.example }
        # Act
        $result = Test-RemoteDomainControl -Evidence $evidence -DesiredState $desired
        # Assert
        "$($result.Status)|$($result.Reason)" | Should -BeLike 'Error|RemoteDomainDefaultMissing:*'
    }

    It 'rejects a domain with no <Member>' -ForEach @(@{ Member = 'Identity' }, @{ Member = 'DomainName' }) {
        # Arrange
        $desired = New-OofDesired
        $domain = New-OofDomain
        $domain.Remove($Member)
        $evidence = Get-RemoteDomainEvidence -Collection { $domain }.GetNewClosure()
        # Act
        $result = Test-RemoteDomainControl -Evidence $evidence -DesiredState $desired
        # Assert
        "$($result.Status)|$($result.Reason)" | Should -BeLike "Error|RemoteDomainEvidenceIncomplete:*$Member*"
    }

    It 'passes the shipped block-external policy across default and specific domains' {
        # Arrange
        $desired = (Get-Content (Join-Path $script:SampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json).controls.'EXO-008'
        $evidence = Get-RemoteDomainEvidence -Collection {
            New-OofDomain
            New-OofDomain -Identity Partner -Domain '*.partner.example' -Type ' none '
        }
        # Act
        $result = Test-RemoteDomainControl -Evidence $evidence -DesiredState $desired
        # Assert
        $result.Status | Should -BeExactly Pass
        $result.GoLiveSuccess | Should -BeTrue
    }
}

Describe 'EXR-002 shipped OOF contract' {
    It 'does not ship a disclosure-enabling default in <File>' -ForEach @(
        @{ File = 'exchange-only.v1.json' },
        @{ File = 'exchange-online-secure-baseline.json' },
        @{ File = 'exchange-online-secure-baseline.microsoft-native.json' }
    ) {
        # Arrange
        $configuration = Get-Content (Join-Path $script:SampleRoot "config/$File") -Raw | ConvertFrom-Json
        # Act
        $remote = if ($File -eq 'exchange-only.v1.json') { $configuration.controls.'EXO-008' } else { $configuration.desiredState.exchangeOnline.remoteDomainDefault }
        # Assert
        $remote.allowedOOFType | Should -BeExactly None
    }

    It 'rejects unsafe or unapproved OOF in the Exchange schema: <Type>' -ForEach @(
        @{ Type = 'InternalLegacy' }, @{ Type = 'ExternalLegacy' }, @{ Type = 'External' }
    ) {
        # Arrange
        $configuration = Get-Content (Join-Path $script:SampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json
        $configuration.controls.'EXO-008'.allowedOOFType = $Type
        $json = $configuration | ConvertTo-Json -Depth 50
        # Act
        $valid = Test-Json -Json $json -SchemaFile (Join-Path $script:SampleRoot 'config/exchange-only.schema.v1.json') -ErrorAction SilentlyContinue
        # Assert
        $valid | Should -BeFalse
    }

    It 'does not execute an internal-disclosure setting from the shipped runbook' {
        # Arrange
        $text = Get-Content (Join-Path $script:SampleRoot 'docs/RUNBOOKS.md') -Raw
        $section = ($text -split '### R-EXO-008 Default remote domain')[1] -split '### R-EXO-009' | Select-Object -First 1
        $block = [regex]::Match($section, '(?s)```powershell\s*(.*?)```').Groups[1].Value
        $script:DocumentedCalls = @()
        function Set-RemoteDomain { param($Identity, $AutoForwardEnabled, $AutoReplyEnabled, $AllowedOOFType, $DeliveryReportEnabled, $NDREnabled) $script:DocumentedCalls += $PSBoundParameters }
        # Act
        & ([scriptblock]::Create($block))
        # Assert
        $script:DocumentedCalls.Count | Should -Be 1
        $script:DocumentedCalls[0].AllowedOOFType | Should -BeExactly None
    }

    It 'executes the documented set and all-domain readback as the selected local policy' {
        # Arrange
        $text = Get-Content (Join-Path $script:SampleRoot 'docs/RUNBOOKS.md') -Raw
        $section = ($text -split '### R-EXO-008 Default remote domain')[1] -split '### R-EXO-009' | Select-Object -First 1
        $blocks = [regex]::Matches($section, '(?s)```powershell\s*(.*?)```')
        $script:ReadbackScope = 'not collected'
        $script:DocumentedDefault = $null
        function Set-RemoteDomain {
            param($Identity, $AutoForwardEnabled, $AutoReplyEnabled, $AllowedOOFType, $DeliveryReportEnabled, $NDREnabled)
            $script:DocumentedDefault = New-OofDomain -Type $AllowedOOFType
            $script:DocumentedDefault.AutoForwardEnabled = $AutoForwardEnabled
            $script:DocumentedDefault.AutoReplyEnabled = $AutoReplyEnabled
            $script:DocumentedDefault.DeliveryReportEnabled = $DeliveryReportEnabled
            $script:DocumentedDefault.NDREnabled = $NDREnabled
        }
        function Get-RemoteDomain {
            param($Identity)
            $script:ReadbackScope = if ($Identity) { $Identity } else { 'all' }
            [pscustomobject]$script:DocumentedDefault
            [pscustomobject](New-OofDomain -Identity Partner -Domain partner.example)
        }
        # Act
        $readback = & {
            & ([scriptblock]::Create($blocks[0].Groups[1].Value))
            & ([scriptblock]::Create($blocks[1].Groups[1].Value)) | Out-String
        }
        # Assert
        $script:ReadbackScope | Should -BeExactly all
        $script:DocumentedDefault.AllowedOOFType | Should -BeExactly None
        $script:DocumentedDefault.AutoForwardEnabled | Should -BeFalse
        $script:DocumentedDefault.NDREnabled | Should -BeFalse
        $readback | Should -Match 'partner.example'
    }
}

Describe 'EXR-002 historical public-command OOF readback' {
    BeforeAll {
        $commandText = Get-Content (Join-Path $script:SampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1') -Raw
        $start = $commandText.IndexOf("Add-Result 'EXO-007 externalSenderTagging'")
        $start = $commandText.IndexOf("`n", $start) + 1
        $end = $commandText.IndexOf('$clientProtocolEvidence =', $start)
        $script:RemoteReadbackBlock = [scriptblock]::Create('param($configuration, $evidence)' + [Environment]::NewLine + $commandText.Substring($start, $end - $start))
        function Add-Result {
            param($Name, $Passed)
            [pscustomobject]@{ Status = $(if ($Passed) { 'Pass' } else { 'Fail' }); Reason = '' }
        }
        function Add-Check {
            param($Name, $Status, $Reason)
            [pscustomobject]@{ Status = $Status; Reason = $Reason }
        }
    }

    It 'reports named OOF drift through the public-command block: <Label>' -ForEach @(
        @{ Label = 'internal disclosure'; Desired = 'None'; Actual = 'InternalLegacy'; Identity = 'Default'; Domain = '*' },
        @{ Label = 'specific override'; Desired = 'None'; Actual = 'InternalLegacy'; Identity = 'Partner'; Domain = 'partner.example' },
        @{ Label = 'approved external mismatch'; Desired = 'External'; Actual = 'None'; Identity = 'Partner'; Domain = 'partner.example' }
    ) {
        # Arrange
        $configuration = @{ desiredState = @{ exchangeOnline = @{ remoteDomainDefault = (New-OofDesired -Type $Desired -Approval 'CHG-2026-0042') } } }
        $evidence = @{ remoteDomain = @(
            if ($Identity -ne 'Default') { New-OofDomain -Type $Desired }
            New-OofDomain -Identity $Identity -Domain $Domain -Type $Actual
        ) }
        # Act
        $result = & $script:RemoteReadbackBlock -configuration $configuration -evidence $evidence
        # Assert
        "$($result.Status)|$($result.Reason)" | Should -BeLike "Fail|RemoteDomainDrift:*$Identity*AllowedOOFType*$Actual*$Desired*"
    }

    It 'passes approved external replies on all domains with independently approved forwarding and NDR choices' {
        # Arrange
        $desired = New-OofDesired -Type External -Approval 'CHG-2026-0042'
        $desired.autoForwardEnabled = $true
        $desired.nonDeliveryReportEnabled = $true
        $configuration = @{ desiredState = @{ exchangeOnline = @{ remoteDomainDefault = $desired } } }
        $domains = @(New-OofDomain -Type External; New-OofDomain -Identity Partner -Domain partner.example -Type External)
        foreach ($domain in $domains) {
            $domain.AutoForwardEnabled = $true
            $domain.NDREnabled = $true
        }
        $evidence = @{ remoteDomain = $domains }
        # Act
        $result = & $script:RemoteReadbackBlock -configuration $configuration -evidence $evidence
        # Assert
        $result.Status | Should -BeExactly Pass
        $result.Reason | Should -BeNullOrEmpty
    }
}