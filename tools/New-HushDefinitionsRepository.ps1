#Requires -Version 5.1
<#
    New-HushDefinitionsRepository.ps1 — bootstrap the independent catalog repository.

    This copies the checked-in validation fixtures into a new destination, writes the
    catalog repository README and CI workflow, copies the public key, and signs the
    initial catalog with the supplied offline private key. It never copies or stores the
    private key in the destination.

    The Hush commit is deliberately required as a full SHA so catalog CI cannot silently
    consume a moving application/tooling branch.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$PublicKeyPath,
    [Parameter(Mandatory)][string]$PrivateKeyPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$HushRef
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceDefinitions = Join-Path $repoRoot 'tests\fixtures\definitions'
$destinationRoot = [IO.Path]::GetFullPath($Destination).TrimEnd('\', '/')
$repoRootFull = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\', '/')

if ($destinationRoot.Equals($repoRootFull, [StringComparison]::OrdinalIgnoreCase) -or
    $destinationRoot.StartsWith("$repoRootFull\", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Destination must be outside the Hush repository: $destinationRoot"
}
if (-not (Test-Path -LiteralPath $sourceDefinitions -PathType Container)) {
    throw "Definition fixtures not found: $sourceDefinitions"
}
if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
    throw "Public key not found: $PublicKeyPath"
}
if (-not (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)) {
    throw "Private signing key not found: $PrivateKeyPath"
}
if (Test-Path -LiteralPath $destinationRoot) {
    $existing = @(Get-ChildItem -LiteralPath $destinationRoot -Force -ErrorAction Stop)
    if ($existing.Count -gt 0) { throw "Destination must be new or empty: $destinationRoot" }
} elseif ($PSCmdlet.ShouldProcess($destinationRoot, 'Create Hush definitions repository')) {
    New-Item -ItemType Directory -Path $destinationRoot -Force | Out-Null
} else {
    return
}

$catalogDir = Join-Path $destinationRoot 'definitions'
$workflowDir = Join-Path $destinationRoot '.github\workflows'
New-Item -ItemType Directory -Path $catalogDir -Force | Out-Null
New-Item -ItemType Directory -Path $workflowDir -Force | Out-Null

foreach ($file in @(Get-ChildItem -LiteralPath $sourceDefinitions -File -Force)) {
    if ($file.Name -eq 'README.md') { continue }
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $catalogDir $file.Name) -Force
}
Copy-Item -LiteralPath $PublicKeyPath -Destination (Join-Path $destinationRoot 'public-key.xml') -Force

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Write-HushUtf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}
$publicKeyBytes = [IO.File]::ReadAllBytes((Join-Path $destinationRoot 'public-key.xml'))
$sha = New-Object System.Security.Cryptography.SHA256Managed
try {
    $publicKeyFingerprint = ([BitConverter]::ToString($sha.ComputeHash($publicKeyBytes))).Replace('-', '').ToLowerInvariant()
} finally { $sha.Dispose() }
Write-HushUtf8NoBom (Join-Path $destinationRoot 'public-key.sha256') "$publicKeyFingerprint  public-key.xml`n"

$readme = @"
# Hush definitions

This repository contains the signed policy catalog consumed by Hush. It is intentionally
independent from the Hush application so policy edits can be reviewed and released without
shipping new binaries.

## Layout

* `definitions/*.json` are authored policies.
* `definitions/manifest.json` and `manifest.json.sig` are generated release metadata.
* `public-key.xml` is the verification key pinned by Hush installations.
* `public-key.sha256` records the public-key file fingerprint for release review.

The JSON and detached signature bytes are protected by `.gitattributes`; do not enable line
ending conversion for catalog files.

## Release

On the offline signing machine, run the pinned Hush tooling:

```powershell
..\Hush\tools\Protect-HushManifest.ps1 `
  -DefinitionsDir .\definitions `
  -PrivateKeyPath .\hush-private.xml.dpapi
```

Commit the generated manifest and detached signature only after
`tools/Test-HushCatalog.ps1` passes. Never commit the private key.

Catalog CI checks out Hush at the exact SHA recorded in its workflow and validates schema,
guardrails, hashes, metadata, and the detached signature against `public-key.xml`.
"@
Write-HushUtf8NoBom (Join-Path $destinationRoot 'README.md') $readme

$workflow = @'
name: Validate Hush catalog

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

env:
  HUSH_REF: '__HUSH_REF__'

jobs:
  validate:
    runs-on: windows-latest
    timeout-minutes: 10
    steps:
      - name: Check out catalog
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Check out pinned Hush tooling
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: bardagi/Hush
          ref: ${{ env.HUSH_REF }}
          path: hush
      - name: Install pinned Pester
        shell: pwsh
        run: Install-Module Pester -RequiredVersion 5.8.0 -Scope CurrentUser -Force
      - name: Verify public-key fingerprint
        shell: pwsh
        run: |
          $expected = (Get-Content .\public-key.sha256 -Raw).Trim().Split()[0].ToLowerInvariant()
          $actual = (Get-FileHash .\public-key.xml -Algorithm SHA256).Hash.ToLowerInvariant()
          if ($expected -ne $actual) { throw 'public-key.xml fingerprint mismatch' }
      - name: Validate signed catalog
        shell: pwsh
        run: .\hush\tools\Test-HushCatalog.ps1 -DefinitionsDir .\definitions -PublicKeyPath .\public-key.xml
'@
$workflow = $workflow.Replace('__HUSH_REF__', $HushRef)
Write-HushUtf8NoBom (Join-Path $workflowDir 'catalog.yml') $workflow

& (Join-Path $repoRoot 'tools\Protect-HushManifest.ps1') `
    -DefinitionsDir $catalogDir `
    -PrivateKeyPath $PrivateKeyPath

Write-Host "Created Hush definitions repository skeleton at $destinationRoot" -ForegroundColor Green
Write-Host "Pinned Hush tooling SHA: $HushRef"
Write-Host 'The private key was used for signing but was not copied.' -ForegroundColor Yellow
