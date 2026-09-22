param([string]$SampleRoot, [string]$CasePath)
$ErrorActionPreference = 'Stop'
$case = Get-Content -LiteralPath $CasePath -Raw | ConvertFrom-Json -AsHashtable
$global:EvidenceTestCalls = $case.CallPath
foreach ($name in @('Connect-ExchangeOnline','Connect-MgGraph','Invoke-MgGraphRequest','Connect-IPPSSession','Get-DlpCompliancePolicy','Get-RetentionCompliancePolicy','Get-Label','Get-AcceptedDomain')) {
    Set-Item "function:global:$name" ([scriptblock]::Create("Add-Content `$global:EvidenceTestCalls '$name'; throw 'UnexpectedCollector:$name'"))
}
$key = [Security.Cryptography.RSA]::Create(2048)
$request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=EXR006 ephemeral test only', $key, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
$start = [datetimeoffset]::UtcNow.AddDays(-1)
$end = [datetimeoffset]::UtcNow.AddDays(1)
if ($case.Case -eq 'expired certificate') { $end = [datetimeoffset]::UtcNow.AddMinutes(-1) }
if ($case.Case -eq 'future certificate') { $start = [datetimeoffset]::UtcNow.AddHours(1) }
$certificate = $request.CreateSelfSigned($start, $end)
$global:EvidenceTestRoot = $certificate
$global:EvidenceTestTrust = $case.Case -ne 'untrusted signer'
function global:Import-Module {
    param([Parameter(Position=0)]$Name, [switch]$Force, [switch]$DisableNameChecking)
    Microsoft.PowerShell.Core\Import-Module $Name -Force:$Force -DisableNameChecking:$DisableNameChecking
    & (Get-Module ExchangeOnlineBaseline.Common) {
        function script:New-BaselineEvidenceCertificateChain {
            $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
            $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            if ($global:EvidenceTestTrust) { $null = $chain.ChainPolicy.CustomTrustStore.Add($global:EvidenceTestRoot) }
            $chain
        }
    }
}
$authority = @(@{ Identity = 'offline-approver'; Subject = $certificate.Subject; Authority = 'ExchangeOnlineChangeApproval'; Thumbprint = $certificate.Thumbprint })
switch ($case.Case) {
    'unauthorized signer' { $authority[0].Identity = 'someone-else' }
    'wrong authority' { $authority[0].Authority = 'UnapprovedRole' }
    'wrong certificate pin' { $authority[0].Thumbprint = '0' * 40 }
    'duplicate authority' { $authority += $authority[0] }
}
$authorityPath = Join-Path (Split-Path $CasePath) 'authorized.json'
$authority | ConvertTo-Json -Depth 10 -AsArray | Set-Content -LiteralPath $authorityPath
if ($case.Case -in @('null evidence','array evidence','scalar evidence')) {
    $invalidJson = switch ($case.Case) { 'null evidence' { 'null' }; 'array evidence' { '[{},{}]' }; 'scalar evidence' { '42' } }
    [IO.File]::WriteAllText($case.EvidencePath, $invalidJson)
    $case.ExpectedEvidenceHash = (Get-FileHash $case.EvidencePath).Hash
}
$bytes = [IO.File]::ReadAllBytes($case.EvidencePath)
$cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
$signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
if ($case.Case -ne 'missing signing time') {
    $signingTime = if ($case.Case -eq 'future signing time') { [datetime]::UtcNow.AddHours(1) } else { [datetime]::UtcNow }
    $signer.SignedAttributes.Add([Security.Cryptography.Pkcs.Pkcs9SigningTime]::new($signingTime)) | Out-Null
}
$cms.ComputeSignature($signer)
if ($case.Case -eq 'multiple signers') { $cms.ComputeSignature($signer) }
[IO.File]::WriteAllBytes($case.SignaturePath, $cms.Encode())
switch ($case.Case) {
    'tampered bytes' { [IO.File]::AppendAllText($case.EvidencePath, ' ') }
    'tampered bytes updated hash' { [IO.File]::AppendAllText($case.EvidencePath, ' '); $case.ExpectedEvidenceHash = (Get-FileHash -LiteralPath $case.EvidencePath).Hash }
    'malformed signature' { [IO.File]::WriteAllBytes($case.SignaturePath, [byte[]]@(1,2,3)) }
    'missing signature file' { Remove-Item -LiteralPath $case.SignaturePath }
    'missing evidence file' { Remove-Item -LiteralPath $case.EvidencePath }
    'malformed evidence' { [IO.File]::WriteAllText($case.EvidencePath, '{invalid'); $case.ExpectedEvidenceHash = (Get-FileHash $case.EvidencePath).Hash }
    'malformed authority' { [IO.File]::WriteAllText($authorityPath, '{invalid') }
    'empty authority' { [IO.File]::WriteAllText($authorityPath, '[]') }
    'null authority' { [IO.File]::WriteAllText($authorityPath, 'null') }
    'scalar authority' { [IO.File]::WriteAllText($authorityPath, '42') }
    'object authority' { [IO.File]::WriteAllText($authorityPath, '{}') }
    'null authority entry' { [IO.File]::WriteAllText($authorityPath, '[null]') }
    'scalar authority entry' { [IO.File]::WriteAllText($authorityPath, '[42]') }
    'mixed authority entries' { ConvertTo-Json -InputObject @($authority[0], 42) -Depth 10 | Set-Content -LiteralPath $authorityPath }
}
$arguments = @{
    ParameterPath = $case.ParameterPath; ConfigurationPath = $case.ConfigurationPath; EvidencePath = $case.EvidencePath
    EvidenceSignaturePath = $case.SignaturePath; EvidenceSignerIdentity = 'offline-approver'
    AuthorizedSignerPath = $authorityPath; MaximumEvidenceAge = '01:00:00'
    ExpectedEvidenceHash = $case.ExpectedEvidenceHash; ExpectedConfigurationHash = $case.ExpectedConfigurationHash
}
if ($case.Case -eq 'missing authority') { $arguments.Remove('AuthorizedSignerPath') }
if ($case.Case -eq 'wrong subject') { $arguments.EvidenceSignerSubject = 'CN=Someone else' }
if ($case.Case -eq 'missing hash') { $arguments.Remove('ExpectedEvidenceHash') }
if ($case.Case -eq 'zero age') { $arguments.MaximumEvidenceAge = '00:00:00' }
if ($case.Case -eq 'wrong expected hash') { $arguments.ExpectedEvidenceHash = 'f' * 64 }
if ($case.Case -eq 'wrong expected configuration') { $arguments.ExpectedConfigurationHash = 'f' * 64 }
if ($case.Case -eq 'unsupported risk acceptance') { $arguments.RiskAcceptancePath = 'unsupported.json' }
if ($case.Case -eq 'sign without private key') {
    $arguments.SignEvidence = $true
    $arguments.SigningCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate.RawData)
    Remove-Item -LiteralPath $case.SignaturePath
}
elseif ($case.Case -eq 'sign hash mismatch') {
    $arguments.SignEvidence = $true
    $arguments.SigningCertificate = $certificate
    $arguments.ExpectedEvidenceHash = 'f' * 64
    Remove-Item -LiteralPath $case.SignaturePath
}
elseif ($case.Case -eq 'sign overwrite') {
    $arguments.SignEvidence = $true
    $arguments.SigningCertificate = $certificate
}
else { $arguments.GoLive = $true }
if ($case.Case -eq 'signed immutable run') {
    Remove-Item -LiteralPath $case.SignaturePath
    $signArguments = $arguments.Clone()
    $signArguments.Remove('GoLive')
    $signArguments.SignEvidence = $true
    $signArguments.SigningCertificate = $certificate
    $signOutput = & (Join-Path $SampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1') @signArguments
    if ($LASTEXITCODE -ne 0) { $signOutput | Write-Output; exit $LASTEXITCODE }
}
& (Join-Path $SampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1') @arguments
exit $LASTEXITCODE