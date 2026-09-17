#requires -Version 7.0

# Discovery-scope copies so the per-section and per-permission negatives can be expanded by -ForEach.
$MandatedSections = @('Microsoft Graph Permissions', 'Consent')
$RequiredPermissions = @(
    'Organization.Read.All'
    'User.Read.All'
    'GroupMember.Read.All'
    'LicenseAssignment.Read.All'
)

BeforeAll {
    $script:MandatedSections = @('Microsoft Graph Permissions', 'Consent')
    $script:RequiredPermissions = @(
        'Organization.Read.All'
        'User.Read.All'
        'GroupMember.Read.All'
        'LicenseAssignment.Read.All'
    )
    $script:PermissionType = @('Application', 'Delegated')

    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:LicensingGatePath = Join-Path $script:SampleRoot 'docs' 'LICENSING-GATE.md'

    # The permission contract as a table under one heading, so an operator granting consent reads
    # the same list the collectors read, and a reviewer can see what each scope is for.
    $script:PermissionRow = [ordered]@{
        'Organization.Read.All'      = @('Application', '`Get-BaselineTenantServicePlan` reading `subscribedSkus`', 'The tenant subscription inventory is the only entitlement authority.')
        'User.Read.All'              = @('Application', '`Get-BaselineTargetPopulation` classifying recipients', 'Classification needs the account and licence state of every recipient.')
        'GroupMember.Read.All'       = @('Application', '`Get-BaselineTargetPopulation` resolving the Strict priority group', 'Strict scope is a group membership, not a domain.')
        'LicenseAssignment.Read.All' = @('Application', '`Get-BaselineTargetEntitlement` reading `assignedPlans`', 'A per-user gap is invisible in the tenant inventory.')
    }

    function Get-GraphPermissionVerdict {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$Path
        )

        $verdict = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $verdict.Reason = 'DocumentMissing'
            return [pscustomobject]$verdict
        }

        $content = Get-Content -LiteralPath $Path -Raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            $verdict.Reason = 'DocumentEmpty'
            return [pscustomobject]$verdict
        }

        $lines = $content -split "`r?`n"
        $headings = @($lines | Where-Object { $_ -match '^##\s+(.+?)\s*$' } | ForEach-Object { $Matches[1] })

        $missingSections = @($script:MandatedSections | Where-Object { $_ -notin $headings })
        if ($missingSections.Count -gt 0) {
            $verdict.Reason = 'SectionMissing'
            $verdict.Violations = $missingSections
            return [pscustomobject]$verdict
        }

        $permissionRow = [System.Collections.Generic.List[object]]::new()
        $consentLine = [System.Collections.Generic.List[string]]::new()
        $section = $null

        foreach ($line in $lines) {
            if ($line -match '^##\s+(.+?)\s*$') {
                $section = $Matches[1]
                continue
            }

            if ($section -eq 'Consent') { $consentLine.Add($line) }
            if ($section -ne 'Microsoft Graph Permissions' -or $line -notmatch '^\s*\|') { continue }

            $cells = @(($line.Trim() -split '\|') | ForEach-Object { $_.Trim().Trim('`') })
            if ($cells.Count -lt 6) { continue }
            if ($cells[1] -eq 'Permission' -or $cells[1] -match '^-+$') { continue }

            $permissionRow.Add([pscustomobject]@{
                    Permission    = $cells[1]
                    Type          = $cells[2]
                    ReadBy        = $cells[3]
                    Justification = $cells[4]
                })
        }

        $documented = @($permissionRow | ForEach-Object { $_.Permission })

        $undocumented = @($script:RequiredPermissions | Where-Object { $_ -notin $documented })
        if ($undocumented.Count -gt 0) {
            $verdict.Reason = 'PermissionNotDocumented'
            $verdict.Violations = $undocumented
            return [pscustomobject]$verdict
        }

        $writeScope = @($documented | Where-Object { $_ -match 'Write' })
        if ($writeScope.Count -gt 0) {
            $verdict.Reason = 'WriteScopeRequested'
            $verdict.Violations = $writeScope
            return [pscustomobject]$verdict
        }

        $surplus = @($documented | Where-Object { $_ -notin $script:RequiredPermissions })
        if ($surplus.Count -gt 0) {
            $verdict.Reason = 'PermissionNotRequired'
            $verdict.Violations = $surplus
            return [pscustomobject]$verdict
        }

        $untyped = @($permissionRow | Where-Object { [string]::IsNullOrWhiteSpace($_.Type) } | ForEach-Object { $_.Permission })
        if ($untyped.Count -gt 0) {
            $verdict.Reason = 'PermissionTypeMissing'
            $verdict.Violations = $untyped
            return [pscustomobject]$verdict
        }

        $unknownType = @($permissionRow | Where-Object { $_.Type -notin $script:PermissionType } | ForEach-Object { '{0}:{1}' -f $_.Permission, $_.Type })
        if ($unknownType.Count -gt 0) {
            $verdict.Reason = 'UnknownPermissionType'
            $verdict.Violations = $unknownType
            return [pscustomobject]$verdict
        }

        $unattributed = @($permissionRow | Where-Object { [string]::IsNullOrWhiteSpace($_.ReadBy) } | ForEach-Object { $_.Permission })
        if ($unattributed.Count -gt 0) {
            $verdict.Reason = 'PermissionPurposeMissing'
            $verdict.Violations = $unattributed
            return [pscustomobject]$verdict
        }

        $unjustified = @($permissionRow | Where-Object { [string]::IsNullOrWhiteSpace($_.Justification) } | ForEach-Object { $_.Permission })
        if ($unjustified.Count -gt 0) {
            $verdict.Reason = 'PermissionJustificationMissing'
            $verdict.Violations = $unjustified
            return [pscustomobject]$verdict
        }

        $consent = ($consentLine -join "`n")
        if ($consent -notmatch '(?i)admin(istrator)?\s+consent') {
            $verdict.Reason = 'AdminConsentNotDocumented'
            return [pscustomobject]$verdict
        }

        if ($consent -notmatch 'Connect-MgGraph') {
            $verdict.Reason = 'ConsentGrantNotDocumented'
            return [pscustomobject]$verdict
        }

        $verdict.Satisfied = $true
        $verdict.Reason = 'GraphPermissionContractSatisfied'
        return [pscustomobject]$verdict
    }

    function New-LicensingGateFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [switch]$Empty,
            [string]$OmitSection,
            [string]$OmitPermission,
            [string]$BlankCell,
            [string]$OverridePermissionType,
            [string]$ExtraPermission,
            [switch]$OmitAdminConsent,
            [switch]$OmitConsentGrant
        )

        if ($Empty) {
            Set-Content -LiteralPath $Path -Value '' -NoNewline
            return $Path
        }

        $line = [System.Collections.Generic.List[string]]::new()
        $line.Add('# Licensing and Capability Gate')
        $line.Add('')

        if ($OmitSection -ne 'Microsoft Graph Permissions') {
            $line.Add('## Microsoft Graph Permissions')
            $line.Add('')
            $line.Add('| Permission | Type | Read by | Least privilege |')
            $line.Add('| --- | --- | --- | --- |')

            foreach ($permission in $script:PermissionRow.Keys) {
                if ($permission -eq $OmitPermission) { continue }

                $cell = @($script:PermissionRow[$permission])
                $type = $cell[0]
                $readBy = $cell[1]
                $justification = $cell[2]

                if ($permission -eq 'Organization.Read.All') {
                    if ($OverridePermissionType) { $type = $OverridePermissionType }
                    switch ($BlankCell) {
                        'Type' { $type = '' }
                        'ReadBy' { $readBy = '' }
                        'Justification' { $justification = '' }
                    }
                }

                # Parenthesized: inside a method call an unparenthesized -f would split on the commas into further Add arguments.
                $line.Add(('| `{0}` | {1} | {2} | {3} |' -f $permission, $type, $readBy, $justification))
            }

            if ($ExtraPermission) {
                $line.Add(('| `{0}` | Application | An unreviewed reader | An unreviewed justification |' -f $ExtraPermission))
            }

            $line.Add('')
        }

        if ($OmitSection -ne 'Consent') {
            $line.Add('## Consent')
            $line.Add('')
            if (-not $OmitAdminConsent) {
                $line.Add('A Global Administrator or Privileged Role Administrator grants tenant-wide administrator consent once.')
            }
            else {
                $line.Add('Someone grants the scopes once.')
            }

            if (-not $OmitConsentGrant) {
                $line.Add('```powershell')
                $line.Add("Connect-MgGraph -Scopes 'Organization.Read.All','User.Read.All','GroupMember.Read.All','LicenseAssignment.Read.All'")
                $line.Add('```')
            }

            $line.Add('')
        }

        Set-Content -LiteralPath $Path -Value ($line -join [System.Environment]::NewLine)
        return $Path
    }
}

Describe 'LIC-007-A documented Graph permission contract' {

    Context 'Negative: the document must exist and carry content' {

        It 'refuses an absent document' {
            # Arrange
            $absent = Join-Path $TestDrive 'no-such-licensing-gate.md'

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $absent

            # Assert
            $verdict.Reason | Should -Be 'DocumentMissing' -Because 'a permission contract nobody can read is a permission contract nobody reviewed'
        }

        It 'refuses an empty document' {
            # Arrange
            $empty = New-LicensingGateFixture -Path (Join-Path $TestDrive 'empty.md') -Empty

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $empty

            # Assert
            $verdict.Reason | Should -Be 'DocumentEmpty' -Because 'an empty file satisfies a file-exists check while documenting nothing'
        }
    }

    Context 'Negative: the document must carry the mandated sections' {

        It 'refuses a document that omits a mandated section' -ForEach @(
            @{ Section = 'Microsoft Graph Permissions' }
            @{ Section = 'Consent' }
        ) {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive "omit-section-$($Section -replace '\W').md") -OmitSection $Section

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            @($verdict.Violations) | Should -Be @($Section) -Because "an operator cannot act on '$Section' that is not there"
        }
    }

    Context 'Negative: every permission the collectors read must be documented' {

        It 'refuses a document that omits a required permission' -ForEach @(
            @{ Permission = 'Organization.Read.All' }
            @{ Permission = 'User.Read.All' }
            @{ Permission = 'GroupMember.Read.All' }
            @{ Permission = 'LicenseAssignment.Read.All' }
        ) {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive "omit-$Permission.md") -OmitPermission $Permission

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            @($verdict.Violations) | Should -Be @($Permission) -Because "a collector that needs '$Permission' fails on a consent grant that omits it"
        }

        It 'refuses a permission row that does not declare its permission type' {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive 'untyped.md') -BlankCell 'Type'

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            $verdict.Reason | Should -Be 'PermissionTypeMissing' -Because 'a delegated scope and an application scope are consented and audited differently'
        }

        It 'refuses a permission type outside the declared vocabulary' {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive 'unknown-type.md') -OverridePermissionType 'Certificate'

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            $verdict.Reason | Should -Be 'UnknownPermissionType' -Because 'a permission type Entra does not offer cannot be granted'
        }

        It 'refuses a permission row that does not name what reads it' {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive 'unattributed.md') -BlankCell 'ReadBy'

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            $verdict.Reason | Should -Be 'PermissionPurposeMissing' -Because 'a scope nobody can attribute to a collector can never be safely removed'
        }

        It 'refuses a permission row that does not justify itself as least privilege' {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive 'unjustified.md') -BlankCell 'Justification'

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            $verdict.Reason | Should -Be 'PermissionJustificationMissing' -Because 'least privilege that is asserted rather than argued is not reviewable'
        }
    }

    Context 'Negative: the gate never asks for more than it reads' {

        It 'refuses a documented write scope' {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive 'write-scope.md') -ExtraPermission 'Directory.ReadWrite.All'

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            @($verdict.Violations) | Should -Be @('Directory.ReadWrite.All') -Because 'the licensing gate only reads, so a write scope is a standing privilege nothing in the solution uses'
        }

        It 'refuses a documented permission the solution does not read' {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive 'surplus.md') -ExtraPermission 'Mail.Read'

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            @($verdict.Violations) | Should -Be @('Mail.Read') -Because 'a scope the operator is told to consent to but nothing uses is privilege granted for nothing'
        }
    }

    Context 'Negative: consent must be documented' {

        It 'refuses a consent section that does not name administrator consent' {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive 'no-admin-consent.md') -OmitAdminConsent

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            $verdict.Reason | Should -Be 'AdminConsentNotDocumented' -Because 'every scope here is admin-consent only, so a run that assumes user consent fails at the first read'
        }

        It 'refuses a consent section that does not name how consent is granted' {
            # Arrange
            $mutated = New-LicensingGateFixture -Path (Join-Path $TestDrive 'no-consent-grant.md') -OmitConsentGrant

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $mutated

            # Assert
            $verdict.Reason | Should -Be 'ConsentGrantNotDocumented' -Because 'a consent requirement with no grant leaves the operator to invent the scope list'
        }
    }

    Context 'Positive: the shipped document satisfies the permission contract' {

        It 'accepts the shipped licensing gate document' {
            # Arrange
            $shipped = $script:LicensingGatePath

            # Act
            $verdict = Get-GraphPermissionVerdict -Path $shipped

            # Assert
            $verdict.Reason | Should -Be 'GraphPermissionContractSatisfied' -Because 'the document an operator consents from is the only place the scope list is reviewable'
        }
    }
}
