#Requires -Version 5.1
<#
    Protect-HushManifest.ps1 — (re)build and sign the catalog after editing definitions.

    For every definition *.json in the definitions folder it:
      * validates required fields (name, displayName, definitionVersion, updateDate),
      * computes the SHA-256,
      * writes manifest.json (catalog),
      * signs it -> manifest.json.sig with the offline private key.

    Run after every edit, then commit + push the definitions folder. IMPORTANT: the repo
    must NOT alter the bytes of these files (set `*.json -text` in .gitattributes) or the
    signature will not match what GitHub serves.

    Example:
      .\Protect-HushManifest.ps1 -PrivateKeyPath .\hush-private.xml
#>

[CmdletBinding()]
param(
    [string]$DefinitionsDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'definitions'),
    [Parameter(Mandatory)][string]$PrivateKeyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Write-Utf8NoBom([string]$Path, [string]$Text) { [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom) }
function Get-Sha256Hex([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

$manifestPath = Join-Path $DefinitionsDir 'manifest.json'
$sigPath      = "$manifestPath.sig"

$defs = @()
foreach ($file in (Get-ChildItem -Path $DefinitionsDir -Filter *.json | Where-Object { $_.Name -ne 'manifest.json' })) {
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $def   = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
    foreach ($f in @('name','displayName','definitionVersion','updateDate','description')) {
        if ($null -eq $def.PSObject.Properties[$f]) { throw "$($file.Name): missing required field '$f'" }
    }
    $defs += [pscustomobject]@{
        name              = $def.name
        displayName       = $def.displayName
        definitionVersion = $def.definitionVersion
        updateDate        = $def.updateDate
        description       = $def.description
        file              = $file.Name
        sha256            = Get-Sha256Hex $bytes
    }
    Write-Host "  + $($def.name)  v$($def.definitionVersion)  ($($file.Name))"
}

$manifest = [pscustomobject]@{
    schemaVersion = 1
    updateDate    = [datetime]::UtcNow.ToString('o')
    definitions   = $defs
}

# Write manifest as UTF-8 (no BOM) so the signed bytes equal the served bytes.
Write-Utf8NoBom $manifestPath ($manifest | ConvertTo-Json -Depth 8)

# Sign the exact on-disk bytes.
$manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
try {
    $rsa.FromXmlString((Get-Content -Path $PrivateKeyPath -Raw))
    $sig = $rsa.SignData($manifestBytes, 'SHA256')
    [System.IO.File]::WriteAllBytes($sigPath, $sig)
} finally { $rsa.Dispose() }

Write-Host ''
Write-Host "Wrote $manifestPath" -ForegroundColor Green
Write-Host "Wrote $sigPath" -ForegroundColor Green
Write-Host 'Commit and push the definitions folder (manifest.json, manifest.json.sig, and the *.json defs).'
