#Requires -Version 5.1
<#
    Test-HushCatalog.ps1 — validate a published catalog without its private key.

    This is intended for the definitions repository's CI. It checks every authored JSON
    definition, the generated manifest metadata and hashes, and (when supplied) the detached
    signature against the public key. It never writes catalog files.
#>

[CmdletBinding()]
param(
    [string]$DefinitionsDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'definitions'),
    [string[]]$PublicKeyXml,
    [string[]]$PublicKeyPath,
    [switch]$AllowExpired
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Hush.Common.ps1')

$manifestPath = Join-Path $DefinitionsDir 'manifest.json'
$signaturePath = "$manifestPath.sig"
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "Manifest not found: $manifestPath" }
if (-not (Test-Path -LiteralPath $signaturePath)) { throw "Detached signature not found: $signaturePath" }

$manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
$manifest = [System.Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
$manifestResult = Test-HushManifest -Manifest $manifest -AllowExpired:$AllowExpired
if (-not $manifestResult.Ok) { throw "Manifest invalid — $($manifestResult.Errors -join '; ')" }

$keys = @()
if ($PublicKeyXml) { $keys += $PublicKeyXml }
if ($PublicKeyPath) { foreach ($path in $PublicKeyPath) { $keys += (Get-Content -LiteralPath $path -Raw) } }
if (@($keys).Count -gt 0) {
    $signature = [System.IO.File]::ReadAllBytes($signaturePath)
    if (-not (Test-HushSignature -Data $manifestBytes -Signature $signature -PublicKeyXml $keys)) {
        throw 'Manifest signature does not verify against the supplied public key(s).'
    }
}

foreach ($entry in @($manifest.definitions)) {
    $path = Join-Path $DefinitionsDir $entry.file
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing definition file: $($entry.file)" }
    if ((Get-HushFileSha256Hex -Path $path) -ne $entry.sha256.ToLowerInvariant()) {
        throw "Hash mismatch: $($entry.file)"
    }
    $definition = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $valid = Test-HushDefinition -Def $definition
    if (-not $valid.Ok) { throw "$($entry.file): schema/guardrail invalid — $($valid.Errors -join '; ')" }
    if (-not (Test-HushManifestDefinitionMatch -Entry $entry -Definition $definition)) {
        throw "$($entry.file): manifest metadata does not match definition."
    }
}

Write-Host ("Catalog v{0} is valid ({1} definition(s))." -f $manifestResult.CatalogVersion, @($manifest.definitions).Count) -ForegroundColor Green
