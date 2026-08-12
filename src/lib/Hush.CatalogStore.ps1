#Requires -Version 5.1
<#
    Hush.CatalogStore.ps1
    Verified catalog snapshot and lock management.

    This file is dot-sourced by the Hush compatibility loaders.
#>

function Test-HushCatalogSnapshotComplete {
    param([Parameter(Mandatory)][string]$Root)
    try {
        $manifestPath = Join-Path $Root 'manifest.json'
        $signaturePath = Join-Path $Root 'manifest.json.sig'
        if (-not (Test-Path -LiteralPath $manifestPath) -or -not (Test-Path -LiteralPath $signaturePath)) { return $false }
        $manifest = Read-HushJson -Path $manifestPath
        $valid = Test-HushManifest -Manifest $manifest -AllowExpired
        if (-not $valid.Ok) { return $false }
        foreach ($entry in @($manifest.definitions)) {
            $entryValid = Test-HushManifestEntry -Entry $entry
            if (-not $entryValid.Ok) { return $false }
            $definitionPath = Join-Path $Root $entry.file
            if (-not (Test-Path -LiteralPath $definitionPath)) { return $false }
            if ((Get-HushFileSha256Hex -Path $definitionPath) -ne ([string]$entry.sha256).ToLowerInvariant()) { return $false }
        }
        return $true
    } catch { return $false }
}

function Get-HushCatalogFiles {
    <#
        Resolve the currently active catalog snapshot. The fetcher switches snapshots by
        atomically replacing active-catalog.json; the legacy cache paths remain a read-only
        compatibility fallback for older installs and tests.
    #>
    $paths = Get-HushPaths
    $root = $paths.Cache
    if (Test-Path $paths.ActiveCatalog) {
        try {
            $pointer = Read-HushJson -Path $paths.ActiveCatalog
            $directory = [string]$pointer.directory
            if ($directory -match '^[0-9]+-[0-9a-f]{16}(?:-[0-9a-f]{8})?$') {
                $snapshot = Join-Path $paths.Catalogs $directory
                $manifest = Join-Path $snapshot 'manifest.json'
                $signature = Join-Path $snapshot 'manifest.json.sig'
                if ((Test-HushCatalogSnapshotComplete -Root $snapshot) -and
                    ((Read-HushJson -Path $manifest).catalogVersion -eq [int64]$pointer.catalogVersion)) {
                    return [pscustomobject]@{
                        Root           = $snapshot
                        Manifest       = $manifest
                        ManifestSig    = $signature
                        CatalogVersion = [int64]$pointer.catalogVersion
                    }
                }
            }
        } catch { }
    }
    # If a pointer write was interrupted, select the newest complete snapshot. The caller
    # still verifies the signature and hashes before applying it.
    foreach ($candidate in @(Get-ChildItem -LiteralPath $paths.Catalogs -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^[0-9]+-[0-9a-f]{16}(?:-[0-9a-f]{8})?$' } |
                Sort-Object LastWriteTimeUtc -Descending)) {
        $candidateManifest = Join-Path $candidate.FullName 'manifest.json'
        $candidateSignature = Join-Path $candidate.FullName 'manifest.json.sig'
        if (Test-HushCatalogSnapshotComplete -Root $candidate.FullName) {
            $candidateManifestDoc = Read-HushJson -Path $candidateManifest
            return [pscustomobject]@{
                Root           = $candidate.FullName
                Manifest       = $candidateManifest
                ManifestSig    = $candidateSignature
                CatalogVersion = [int64]$candidateManifestDoc.catalogVersion
            }
        }
    }
    if ((Test-Path $paths.ManifestCache) -and (Test-Path $paths.ManifestSigCache)) {
        return [pscustomobject]@{
            Root           = $root
            Manifest       = $paths.ManifestCache
            ManifestSig    = $paths.ManifestSigCache
            CatalogVersion = 0
        }
    }
    return $null
}

function Enter-HushCatalogLock {
    $paths = Get-HushPaths
    if (-not (Test-Path -LiteralPath $paths.Cache)) { New-Item -ItemType Directory -Path $paths.Cache -Force | Out-Null }
    $lockPath = Join-Path $paths.Cache 'catalog.lock'
    $deadline = [datetime]::UtcNow.AddSeconds(30)
    while ($true) {
        try {
            return [System.IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        } catch [System.IO.IOException] {
            if ([datetime]::UtcNow -ge $deadline) { throw 'Timed out waiting for the Hush catalog lock.' }
            Start-Sleep -Milliseconds 100
        }
    }
}

function Exit-HushCatalogLock {
    param($Lock)
    if ($null -ne $Lock) {
        try { $Lock.Dispose() } catch { }
    }
}

