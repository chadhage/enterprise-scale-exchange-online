#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:AsOf = [datetimeoffset]'2026-09-19T12:00:00Z'
    $script:DesiredTenantAllowBlockList = [pscustomobject][ordered]@{
        registerLocation                   = 'https://governance.contoso.example/tabl'
        permanentAllowEntries             = @()
        blockEntriesRequireExpiryAndTicket = $true
        allowEntryMaximumDurationDays      = 30
        blockEntryRetentionDays            = 90
        requiredEntryFields                = @(
            'entryType', 'entryValue', 'owner', 'ticket', 'createdDateTime',
            'expirationDateTime', 'justification'
        )
    }

    function New-TenantAllowBlockEntry {
        [CmdletBinding()]
        param(
            [object]$EntryType = 'Sender',
            [object]$EntryValue = 'newsletter@partner.example',
            [object]$Action = 'Allow',
            [object]$Owner = 'Messaging Security',
            [object]$Ticket = 'CHG0012345',
            [object]$CreatedDateTime = '2026-09-01T12:00:00Z',
            [object]$ExpirationDateTime = '2026-09-30T12:00:00Z',
            [object]$Justification = 'Temporary partner authentication repair.',
            [string[]]$Remove = @()
        )

        $entry = [ordered]@{
            entryType         = $EntryType
            entryValue        = $EntryValue
            action            = $Action
            owner             = $Owner
            ticket            = $Ticket
            createdDateTime   = $CreatedDateTime
            expirationDateTime = $ExpirationDateTime
            justification     = $Justification
        }
        foreach ($member in $Remove) { $entry.Remove($member) }
        return [pscustomobject]$entry
    }

    function New-TenantAllowBlockListEvidenceRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$Entry
        )

        return New-BaselineEvidence -ControlId 'MDO-007' -Source 'ExchangeOnline' `
            -Command 'Get-TenantAllowBlockListItems' -Value $Entry
    }

    function New-TenantAllowBlockDesiredState {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Remove = @()
        )

        $state = [ordered]@{
            registerLocation                   = 'https://governance.contoso.example/tabl'
            permanentAllowEntries             = @()
            blockEntriesRequireExpiryAndTicket = $true
            allowEntryMaximumDurationDays      = 30
            blockEntryRetentionDays            = 90
            requiredEntryFields                = @(
                'entryType', 'entryValue', 'owner', 'ticket', 'createdDateTime',
                'expirationDateTime', 'justification'
            )
        }
        foreach ($member in $Override.Keys) { $state[$member] = $Override[$member] }
        foreach ($member in $Remove) { $state.Remove($member) }
        return [pscustomobject]$state
    }

    function Get-TenantAllowBlockVerdictFold {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Result)

        return '{0}|golive={1}|reason={2}' -f $Result.Status, $Result.GoLiveSuccess, $Result.Reason
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-009 exact Tenant Allow/Block List evaluator' {
    Context 'Negative: the registry evaluator must be exported' {
        It 'exports Test-TenantAllowBlockListControl' {
            # Arrange
            $registered = 'Test-TenantAllowBlockListControl'

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count | Should -Be 1 -Because 'MDO-007 cannot leave a manual verdict when the registry names an evaluator'
        }
    }

    Context 'Negative: evidence and resolved desired state are mandatory' {
        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-TenantAllowBlockListControl -Evidence $noEvidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-006' -Source 'ExchangeOnline' `
                -Command 'Get-TenantAllowBlockListItems' -Value @(New-TenantAllowBlockEntry)

            # Act
            $act = { Test-TenantAllowBlockListControl -Evidence $foreign -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*'
        }

        It 'refuses a decision with no resolved TABL contract' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry)

            # Act
            $act = { Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $null -AsOf $script:AsOf }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredTenantAllowBlockListStateRequired*'
        }

        It 'refuses a resolved TABL contract missing <Member>' -ForEach @(
            @{ Member = 'registerLocation' }
            @{ Member = 'permanentAllowEntries' }
            @{ Member = 'blockEntriesRequireExpiryAndTicket' }
            @{ Member = 'allowEntryMaximumDurationDays' }
            @{ Member = 'blockEntryRetentionDays' }
            @{ Member = 'requiredEntryFields' }
        ) {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry)
            $partial = New-TenantAllowBlockDesiredState -Remove @($Member)

            # Act
            $act = { Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $partial -AsOf $script:AsOf }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredTenantAllowBlockListMemberRequired*'
        }

        It 'refuses a TABL contract that does not require every governed entry field' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry)
            $partial = New-TenantAllowBlockDesiredState -Override @{ requiredEntryFields = @('entryType', 'entryValue', 'owner') }

            # Act
            $act = { Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $partial -AsOf $script:AsOf }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredTenantAllowBlockListRequiredFieldMissing*'
        }

        It 'refuses a TABL contract that does not keep block retention separate from allow duration' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry)
            $sharedLimit = New-TenantAllowBlockDesiredState -Override @{ blockEntryRetentionDays = 30 }

            # Act
            $act = { Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $sharedLimit -AsOf $script:AsOf }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredTenantAllowBlockListRetentionNotSeparate*'
        }
    }

    Context 'Negative: malformed raw evidence is an Error' {
        It 'returns Error when collection was refused' {
            # Arrange
            $refused = Get-BaselineEvidence -ControlId 'MDO-007' -Source 'ExchangeOnline' `
                -Command 'Get-TenantAllowBlockListItems' -Collection { throw 'offline synthetic refusal' }

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $refused -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*'
        }

        It 'returns Error when the raw payload is not a collection of records' {
            # Arrange
            $malformed = New-TenantAllowBlockListEvidenceRecord -Entry 'not-a-record'

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $malformed -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly 'Error|golive=False|reason=TenantAllowBlockListEvidenceMalformed: entry 1 is not a record.'
        }

        It 'returns Error when <Member> is not a readable timestamp' -ForEach @(
            @{ Member = 'createdDateTime' }
            @{ Member = 'expirationDateTime' }
        ) {
            # Arrange
            $argument = @{ $Member = 'not-a-timestamp' }
            $malformed = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry @argument)

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $malformed -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Error|golive=False|reason=TenantAllowBlockListEvidenceMalformed: entry 1 has unreadable '$Member' value 'not-a-timestamp'."
        }
    }

    Context 'Negative: every entry needs exact type, action, value and governance' {
        It 'fails an entry with unknown type' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -EntryType 'IpAddress')

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Fail|golive=False|reason=TenantAllowBlockListDrift: entry 1 has unknown type 'IpAddress'."
        }

        It 'fails an entry with unknown action' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -Action 'Monitor')

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Fail|golive=False|reason=TenantAllowBlockListDrift: entry 1 has unknown action 'Monitor'."
        }

        It 'fails an entry with a blank value' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -EntryValue '   ')

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly 'Fail|golive=False|reason=TenantAllowBlockListDrift: entry 1 has blank entryValue.'
        }

        It 'fails overbroad or type-mismatched <Type> value <Value>' -ForEach @(
            @{ Type = 'Sender'; Value = '*@partner.example' }
            @{ Type = 'Sender'; Value = 'partner.example' }
            @{ Type = 'Domain'; Value = '*.partner.example' }
            @{ Type = 'Domain'; Value = 'user@partner.example' }
            @{ Type = 'Url'; Value = 'https://*' }
            @{ Type = 'Url'; Value = 'partner.example/path' }
            @{ Type = 'File'; Value = '*' }
            @{ Type = 'File'; Value = 'document.docx' }
        ) {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -EntryType $Type -EntryValue $Value)

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Fail|golive=False|reason=TenantAllowBlockListDrift: entry 1 type '$Type' does not exactly scope value '$Value'."
        }

        It 'fails an entry missing governance field <Member>' -ForEach @(
            @{ Member = 'owner' }
            @{ Member = 'ticket' }
            @{ Member = 'createdDateTime' }
            @{ Member = 'expirationDateTime' }
            @{ Member = 'justification' }
        ) {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -Remove @($Member))

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Fail|golive=False|reason=TenantAllowBlockListDrift: entry 1 is missing required governance field '$Member'."
        }

        It 'fails a blank governance field <Member>' -ForEach @(
            @{ Member = 'owner' }
            @{ Member = 'ticket' }
            @{ Member = 'justification' }
        ) {
            # Arrange
            $argument = @{ $Member = '   ' }
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry @argument)

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Fail|golive=False|reason=TenantAllowBlockListDrift: entry 1 has blank required governance field '$Member'."
        }
    }

    Context 'Negative: entry time windows are bounded by action-specific policy' {
        It 'fails an entry created in the future' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -CreatedDateTime '2026-09-20T12:00:00Z' -ExpirationDateTime '2026-09-25T12:00:00Z')

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Fail|golive=False|reason=TenantAllowBlockListDrift: entry 1 was created at '2026-09-20T12:00:00.0000000+00:00', after evaluation time '2026-09-19T12:00:00.0000000+00:00'."
        }

        It 'fails an expired allow' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -CreatedDateTime '2026-08-01T12:00:00Z' -ExpirationDateTime '2026-09-18T12:00:00Z')

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Fail|golive=False|reason=TenantAllowBlockListDrift: allow entry 1 expired at '2026-09-18T12:00:00.0000000+00:00'."
        }

        It 'fails an allow whose duration exceeds the allow maximum' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -CreatedDateTime '2026-09-01T12:00:00Z' -ExpirationDateTime '2026-10-02T12:00:00Z')

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly 'Fail|golive=False|reason=TenantAllowBlockListDrift: allow entry 1 lasts 31 days where at most 30 days is allowed.'
        }

        It 'fails a permanent allow' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(New-TenantAllowBlockEntry -ExpirationDateTime $null)

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly 'Fail|golive=False|reason=TenantAllowBlockListDrift: allow entry 1 is permanent; every allow must expire.'
        }

        It 'fails a block whose duration violates the separately declared retention' {
            # Arrange
            $block = New-TenantAllowBlockEntry -EntryType 'Domain' -EntryValue 'malicious.example' -Action 'Block' `
                -CreatedDateTime '2026-07-01T12:00:00Z' -ExpirationDateTime '2026-10-01T12:00:00Z'
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @($block)

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly 'Fail|golive=False|reason=TenantAllowBlockListDrift: block entry 1 lasts 92 days where separately declared retention is 90 days.'
        }
    }

    Context 'Negative: governance metadata cannot stand in for exact entry scope' {
        It 'does not infer compliance from a ticket and register location when the value is overbroad' {
            # Arrange
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry @(
                New-TenantAllowBlockEntry -EntryType 'Domain' -EntryValue '*' -Ticket 'CHG0012345'
            )

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            (Get-TenantAllowBlockVerdictFold -Result $result) | Should -BeExactly "Fail|golive=False|reason=TenantAllowBlockListDrift: entry 1 type 'Domain' does not exactly scope value '*'."
        }
    }

    Context 'Positive: one complete in-policy allow and block set' {
        It 'returns one normalized pass for exactly scoped, governed and bounded entries' {
            # Arrange
            $entries = @(
                New-TenantAllowBlockEntry -EntryType 'Sender' -EntryValue 'newsletter@partner.example' -Action 'Allow'
                New-TenantAllowBlockEntry -EntryType 'Url' -EntryValue 'https://partner.example/campaign' -Action 'Allow'
                New-TenantAllowBlockEntry -EntryType 'Domain' -EntryValue 'malicious.example' -Action 'Block' `
                    -CreatedDateTime '2026-07-01T12:00:00Z' -ExpirationDateTime '2026-09-29T12:00:00Z'
                New-TenantAllowBlockEntry -EntryType 'File' `
                    -EntryValue '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' -Action 'Block' `
                    -CreatedDateTime '2026-07-01T12:00:00Z' -ExpirationDateTime '2026-09-29T12:00:00Z'
            )
            $evidence = New-TenantAllowBlockListEvidenceRecord -Entry $entries

            # Act
            $result = Test-TenantAllowBlockListControl -Evidence $evidence -DesiredState $script:DesiredTenantAllowBlockList -AsOf $script:AsOf

            # Assert
            ('{0}|{1}|normalized={2}|golive={3}|reason={4}|evidence={5}:{6}' -f `
                    $result.ControlId, $result.Status, $result.Normalized, $result.GoLiveSuccess,
                    $result.Reason, $result.Evidence.Command, $result.Evidence.ControlId) |
                Should -BeExactly 'MDO-007|Pass|normalized=True|golive=True|reason=|evidence=Get-TenantAllowBlockListItems:MDO-007'
        }
    }
}