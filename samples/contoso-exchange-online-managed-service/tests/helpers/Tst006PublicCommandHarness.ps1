#requires -Version 7.0

function Invoke-Tst006PublicCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CommandPath,

        [Parameter(Mandatory)]
        [string]$FixtureRoot,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    if (-not (Test-Path -LiteralPath $CommandPath -PathType Leaf)) {
        throw "Tst006PublicCommandMissing: no shipped public command exists at '$CommandPath'."
    }
    if (-not (Test-Path -LiteralPath $FixtureRoot -PathType Container)) {
        throw "Tst006FixtureRootMissing: no sanitized offline fixture exists at '$FixtureRoot'."
    }

    $fixturePath = Join-Path $FixtureRoot 'compliant-microsoft-native.json'
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
        throw "Tst006CompliantFixtureMissing: no compliant-microsoft-native.json exists at '$fixturePath'."
    }

    $modulePath = Join-Path (Split-Path -Parent $CommandPath) 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module -Name $modulePath -Force -DisableNameChecking -ErrorAction Stop

    $tokens = $null
    $parseError = $null
    $commandAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $CommandPath, [ref]$tokens, [ref]$parseError)
    if (@($parseError).Count -gt 0) {
        throw "Tst006PublicCommandUnparsable: $(@($parseError.Message) -join '; ')"
    }

    $goLiveInvocationCount = @($commandAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Test-BaselineGoLive'
            }, $true)).Count
    $runOutcomeInvocationCount = @($commandAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Get-BaselineRunOutcome'
            }, $true)).Count
    if ($goLiveInvocationCount -ne 1 -or $runOutcomeInvocationCount -ne 1) {
        throw "Tst006PublicCommandWiringInvalid: expected one go-live and one run-outcome invocation, found $goLiveInvocationCount and $runOutcomeInvocationCount."
    }

    $fixture = Get-Content -LiteralPath $fixturePath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100 -DateKind String
    $payload = [ordered]@{}
    foreach ($name in @('SchemaVersion', 'FixtureId', 'Sanitized', 'Offline', 'Binding', 'Entitlement', 'Controls')) {
        $payload[$name] = $fixture.$name
    }
    $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson -InputObject $payload))
    $payloadHash = 'sha256:' + [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($canonicalBytes)).ToLowerInvariant()
    if ($payloadHash -cne [string]$fixture.Signature.PayloadHash) {
        throw 'Tst006FixtureSignatureInvalid: the fixture payload hash does not match its signature metadata.'
    }

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Convert]::FromBase64String([string]$fixture.Signature.Certificate))
    try {
        $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
            [System.Security.Cryptography.Pkcs.ContentInfo]::new($canonicalBytes), $true)
        $cms.Decode([Convert]::FromBase64String([string]$fixture.Signature.Value))
        $certificates = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        [void]$certificates.Add($certificate)
        $cms.CheckSignature($certificates, $true)
    }
    catch {
        throw "Tst006FixtureSignatureInvalid: $($_.Exception.Message)"
    }
    finally {
        $certificate.Dispose()
    }

    $envelope = [pscustomobject]@{
        TenantId = [string]$fixture.Binding.TenantId
        OrganizationName = [string]$fixture.Binding.OrganizationName
        DeploymentProfile = [string]$fixture.Binding.DeploymentProfile
        ConfigurationHash = [string]$fixture.Binding.ConfigurationHash
        CollectedAtUtc = [string]$fixture.Binding.CollectedAtUtc
        ServicePlan = [pscustomobject]@{ NotEntitled = @() }
        Evidence = @($fixture.Controls | ForEach-Object Evidence)
        Check = @($fixture.Controls | ForEach-Object Result)
    }
    $signature = [pscustomobject]@{
        Model = 'DetachedCms'
        Value = [string]$fixture.Signature.Value
        ContentHash = [string](Get-BaselineEvidenceContentHash -Envelope $envelope).Hash
    }
    $catalogPath = Join-Path (Split-Path -Parent (Split-Path -Parent $CommandPath)) 'docs' 'CONTROL-CATALOG.md'
    $decisionTime = [datetimeoffset]::Parse(
        [string]$fixture.Binding.CollectedAtUtc,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime.AddMinutes(1)
    $decision = Test-BaselineGoLive -Envelope $envelope -CatalogPath $catalogPath `
        -ExpectedTenantId $fixture.Binding.TenantId `
        -ExpectedDeploymentProfile $fixture.Binding.DeploymentProfile `
        -ExpectedConfigurationHash $fixture.Binding.ConfigurationHash `
        -MaximumEvidenceAge ([timespan]::FromDays(1)) -RequestedBy 'offline-test@tst006.invalid' `
        -RiskAcceptance @() -Signature $signature -TargetEntitlement ([pscustomobject]@{ Missing = @() }) `
        -AsOf $decisionTime
    $outcome = Get-BaselineRunOutcome -Check @($envelope.Check) -GoLive $decision

    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    $envelope | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $OutputPath 'exchange-online-evidence.json') -Encoding utf8

    [pscustomobject]@{
        CommandPath = $CommandPath
        Envelope = $envelope
        GoLiveDecision = $decision
        Outcome = $outcome
        ProcessExitCode = [int]$outcome.ExitCode
        GoLiveInvocationCount = $goLiveInvocationCount
        RunOutcomeInvocationCount = $runOutcomeInvocationCount
        ConnectionAttempt = @()
        MutationAttempt = @()
        CredentialAccess = @()
    }
}