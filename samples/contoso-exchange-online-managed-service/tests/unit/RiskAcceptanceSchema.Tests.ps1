#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'risk-acceptance.schema.json'

    # The schema is proved by validating documents against it rather than by reading its text. A
    # schema that merely names a field in a `required` list has not been shown to refuse a document
    # that omits it, and it is the refusal the gate depends on.
    function Test-RiskAcceptanceAgainstSchema {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Document,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$SchemaPath
        )

        $result = [ordered]@{
            Admitted = $false
            Reason   = $null
        }

        if ([string]::IsNullOrWhiteSpace($SchemaPath) -or -not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) {
            $result.Reason = 'SchemaMissing'
            return [pscustomobject]$result
        }

        try {
            $null = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $result.Reason = 'SchemaJsonInvalid'
            return [pscustomobject]$result
        }

        try {
            $null = Test-Json -Json ($Document | ConvertTo-Json -Depth 20) -SchemaFile $SchemaPath -ErrorAction Stop
        }
        catch {
            $result.Reason = if ($_.Exception.Message -like '*parse the JSON schema*') { 'SchemaNotValid' } else { 'DocumentRejected' }
            return [pscustomobject]$result
        }

        $result.Admitted = $true
        $result.Reason = 'DocumentAdmitted'
        return [pscustomobject]$result
    }

    function New-RiskAcceptanceDocument {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            ControlId           = 'EXO-004'
            TenantId            = '00000000-1111-2222-3333-444444444444'
            ConfigurationHash   = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
            Owner               = 'messaging-lead@contoso.example'
            Justification       = 'The legacy archive connector cannot honour the forwarding block until it is retired.'
            CompensatingControl = @('Daily forwarding report reviewed by SecOps', 'Conditional Access blocks legacy clients')
            ExternalReference   = 'CHG0012345'
            ApprovalIdentity    = 'ciso@contoso.example'
            ApprovalAuthority   = 'ExchangeOnlineChangeApproval'
            ApprovalTimeUtc     = '2026-09-10T09:00:00Z'
            EffectiveTimeUtc    = '2026-09-11T00:00:00Z'
            ExpiryTimeUtc       = '2026-12-11T00:00:00Z'
            Signature           = [ordered]@{
                Model = 'DetachedCms'
                Value = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            }
        }

        foreach ($name in $Omit) { $member.Remove($name) }
        foreach ($name in $Override.Keys) { $member[$name] = $Override[$name] }

        return [pscustomobject]$member
    }
}

Describe 'GATE-002-A1 the published risk-acceptance schema' {
    BeforeAll {
        $script:FixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('risk-acceptance-schema-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:FixtureRoot -Force | Out-Null
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:FixtureRoot) {
            Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'the schema itself must exist and be usable' {
        It 'refuses a schema path that names no file' {
            # Arrange
            $absent = Join-Path $script:FixtureRoot 'no-such-schema.json'

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document (New-RiskAcceptanceDocument) -SchemaPath $absent

            # Assert
            $result.Reason | Should -BeExactly 'SchemaMissing' -Because 'an exception measured against nothing is an exception nobody reviewed'
        }

        It 'refuses a schema document that is not valid JSON' {
            # Arrange
            $broken = Join-Path $script:FixtureRoot 'broken-schema.json'
            Set-Content -LiteralPath $broken -Value '{ "type": "object", ' -Encoding utf8

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document (New-RiskAcceptanceDocument) -SchemaPath $broken

            # Assert
            $result.Reason | Should -BeExactly 'SchemaJsonInvalid' -Because 'a schema nobody can parse admits every document by accident'
        }

        It 'refuses a schema document that is not a usable JSON Schema' {
            # Arrange
            $notASchema = Join-Path $script:FixtureRoot 'not-a-schema.json'
            Set-Content -LiteralPath $notASchema -Value '{ "type": 42 }' -Encoding utf8

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document (New-RiskAcceptanceDocument) -SchemaPath $notASchema

            # Assert
            $result.Reason | Should -BeExactly 'SchemaNotValid' -Because 'valid JSON that is not a schema still demands nothing'
        }
    }

    Context 'a field the card names is missing' {
        It 'rejects a risk acceptance that omits <_>' -ForEach @(
            'ControlId'
            'TenantId'
            'Owner'
            'Justification'
            'CompensatingControl'
            'ExternalReference'
            'ApprovalIdentity'
            'ApprovalAuthority'
            'ApprovalTimeUtc'
            'EffectiveTimeUtc'
            'ExpiryTimeUtc'
            'Signature'
        ) {
            # Arrange
            $document = New-RiskAcceptanceDocument -Omit @($_)

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because "an exception that declares no $_ cannot be reviewed, renewed or revoked"
        }
    }

    Context 'the acceptance must be bound to something finite' {
        It 'rejects a risk acceptance carrying neither a configuration hash nor a bounded applicability' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Omit @('ConfigurationHash')

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'an exception bound to nothing at all never stops applying'
        }

        It 'rejects a bounded applicability that names no deployment profile' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Omit @('ConfigurationHash') -Override @{
                AppliesTo = [ordered]@{ BaselineVersion = '1.0.0'; BoundedBy = @('Legacy archive connector retirement') }
            }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'the native and gateway profiles are held to different controls, so an exception that names neither is not bounded'
        }

        It 'rejects a bounded applicability that names no baseline version' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Omit @('ConfigurationHash') -Override @{
                AppliesTo = [ordered]@{ DeploymentProfile = 'MicrosoftNative'; BoundedBy = @('Legacy archive connector retirement') }
            }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'an exception that survives every future baseline is an exception nobody re-reviews'
        }

        It 'rejects a bounded applicability whose boundary names nothing at all' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Omit @('ConfigurationHash') -Override @{
                AppliesTo = [ordered]@{ DeploymentProfile = 'MicrosoftNative'; BaselineVersion = '1.0.0'; BoundedBy = @() }
            }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'an empty boundary is the word "bounded" without the fact'
        }

        It 'rejects a deployment profile the baseline does not declare' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Omit @('ConfigurationHash') -Override @{
                AppliesTo = [ordered]@{ DeploymentProfile = 'EveryTenant'; BaselineVersion = '1.0.0'; BoundedBy = @('Legacy archive connector retirement') }
            }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'a profile nothing deploys under cannot bound anything'
        }
    }

    Context 'a field the card names is present but says nothing' {
        It 'rejects an empty compensating-control list' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ CompensatingControl = @() }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'accepting a risk with nothing compensating for it is not an exception, it is a gap'
        }

        It 'rejects a blank business justification' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ Justification = '   ' }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'a justification nobody wrote cannot be the justification anybody approved'
        }

        It 'rejects a blank owner' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ Owner = '' }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'an exception nobody owns is an exception nobody retires'
        }

        It 'rejects a blank external ticket reference' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ ExternalReference = '' }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'an exception with no ticket behind it has no record outside this repository'
        }
    }

    Context 'a field the card names is present but the wrong shape' {
        It 'rejects a control identifier that is not a control identifier' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ ControlId = 'the forwarding one' }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'an exception that names no catalog control can never be matched to the verdict it excuses'
        }

        It 'rejects a tenant identifier that is not a GUID' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ TenantId = 'contoso.example' }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'a tenant named by domain is a tenant that can be renamed out from under the exception'
        }

        It 'rejects an approval authority other than the declared change-approval role' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ ApprovalAuthority = 'ServiceDeskTeamLead' }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'DES-005 names one role that may accept this risk, and a schema that admits any other makes the role advisory'
        }

        It 'rejects a timestamp that is not a timestamp' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ ExpiryTimeUtc = 'when the connector is retired' }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'an expiry nobody can compare against a clock is an exception that never expires'
        }

        It 'rejects a configuration hash that is not a SHA-256 digest' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ ConfigurationHash = 'the september baseline' }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'a configuration named in prose binds the exception to whatever the reader thinks it means'
        }
    }

    Context 'the signature metadata' {
        It 'rejects a signature that names no model' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ Signature = [ordered]@{ Value = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA=' } }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'a signature nobody can say how to verify cannot be verified'
        }

        It 'rejects a signature that carries no value' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ Signature = [ordered]@{ Model = 'DetachedCms'; Value = '' } }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'an empty signature is an unsigned exception wearing the word signed'
        }

        It 'rejects a signature model other than the selected one' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ Signature = [ordered]@{ Model = 'ExternalTicketEvidence'; Value = 'CHG0012345' } }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'DES-005 selected detached CMS, and a schema admitting the models it considered and rejected undoes that decision'
        }
    }

    Context 'the document must carry nothing the schema never declared' {
        It 'rejects a member the schema never declared' {
            # Arrange
            $document = New-RiskAcceptanceDocument -Override @{ PermanentWaiver = $true }

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Reason | Should -BeExactly 'DocumentRejected' -Because 'a member the schema never declared is a term nobody agreed to and no reader is looking for'
        }
    }

    Context 'a complete risk acceptance' {
        It 'admits a complete, correctly shaped risk acceptance' {
            # Arrange
            $document = New-RiskAcceptanceDocument

            # Act
            $result = Test-RiskAcceptanceAgainstSchema -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Admitted | Should -BeTrue -Because "a schema that refuses every document demands nothing useful, but this one reported '$($result.Reason)'"
        }
    }
}
