#Requires -Version 7.0
<#
.SYNOPSIS
    Serves the microsite on localhost with the rendered documentation bundled, matching GitHub Pages.

.DESCRIPTION
    Browsers block fetch() from file:// pages, and microsite/docs only exists in the Pages build.
    This copies the sample docs into microsite/docs (git-ignored) and serves the microsite folder
    on http://localhost only. Press Ctrl+C to stop.

.EXAMPLE
    ./microsite/Start-MicrositePreview.ps1 -Port 8080 -Open
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,

    [switch]$Open
)

$ErrorActionPreference = 'Stop'
$siteRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$sourceDocs = Join-Path (Split-Path -Parent $siteRoot) 'samples\contoso-exchange-online-managed-service\docs'
$targetDocs = Join-Path $siteRoot 'docs'

New-Item -ItemType Directory -Path $targetDocs -Force | Out-Null
Get-ChildItem -LiteralPath $targetDocs -Filter '*.md' -File | Remove-Item -Force
Copy-Item -Path (Join-Path $sourceDocs '*.md') -Destination $targetDocs

$contentTypes = @{
    '.html' = 'text/html; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.js'   = 'text/javascript; charset=utf-8'
    '.md'   = 'text/markdown; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.png'  = 'image/png'
    '.svg'  = 'image/svg+xml'
    '.ico'  = 'image/x-icon'
}

$prefix = "http://localhost:$($Port)/"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Information -MessageData "Serving $($siteRoot) at $($prefix) (Ctrl+C to stop)" -InformationAction Continue
if ($Open) {
    Start-Process $prefix
}

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $response = $context.Response
        try {
            $relative = [System.Uri]::UnescapeDataString($context.Request.Url.AbsolutePath.TrimStart('/'))
            if ([string]::IsNullOrEmpty($relative)) {
                $relative = 'index.html'
            }
            $fullPath = [System.IO.Path]::GetFullPath((Join-Path $siteRoot $relative))
            $insideRoot = $fullPath.StartsWith($siteRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
            if (-not $insideRoot -or -not (Test-Path -LiteralPath $fullPath -PathType Leaf) -or
                $fullPath.EndsWith('.ps1', [System.StringComparison]::OrdinalIgnoreCase)) {
                $response.StatusCode = 404
            }
            else {
                $extension = [System.IO.Path]::GetExtension($fullPath).ToLowerInvariant()
                $response.ContentType = $contentTypes[$extension] ?? 'application/octet-stream'
                $bytes = [System.IO.File]::ReadAllBytes($fullPath)
                $response.ContentLength64 = $bytes.Length
                $response.OutputStream.Write($bytes, 0, $bytes.Length)
            }
        }
        finally {
            $response.Close()
        }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
}
