#Requires -Version 5.1
<#
    Update-HushDefinitions.ps1   (FETCHER)

    Runs as NT AUTHORITY\LOCAL SERVICE on a schedule. The ONLY component with network
    access. Downloads the signed catalog + definitions from the public GitHub repo,
    verifies the manifest signature against the pinned public key, hash-checks every
    definition, enforces anti-rollback, schema-validates, and writes verified files
    ATOMICALLY into the cache. It has no rights to stop processes/services — minimal
    blast radius. The SYSTEM enforcer re-verifies the cache before trusting it.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Hush.Common.ps1')

function Get-HushUrlBytes {
    param([Parameter(Mandatory)][string]$Url)
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $handler = New-Object System.Net.Http.HttpClientHandler
    $client = New-Object System.Net.Http.HttpClient($handler)
    try {
        $client.Timeout = [timespan]::FromSeconds(30)
        # Cap the in-memory response so a hostile/MITM endpoint can't exhaust memory before
        # the signature is even checked. Catalogs and definitions are tiny (a few KB).
        $client.MaxResponseContentBufferSize = 5MB
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('Hush/1.0')
        $resp = $client.GetAsync($Url).GetAwaiter().GetResult()
        if (-not $resp.IsSuccessStatusCode) { throw "HTTP $([int]$resp.StatusCode) fetching $Url" }
        return $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
    } finally { $client.Dispose(); $handler.Dispose() }
}

try {
    # Enforce modern TLS.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 } catch { }

    $paths = Get-HushPaths
    $config = Get-HushConfig
    if (-not $config) { throw "Config not found at $($paths.Config)" }
    if (-not (Test-Path $paths.Cache)) { New-Item -ItemType Directory -Path $paths.Cache -Force | Out-Null }
    if (-not (Test-Path $paths.Catalogs)) { New-Item -ItemType Directory -Path $paths.Catalogs -Force | Out-Null }

    $base = $config.repoRawBaseUrl.TrimEnd('/')
    $baseUri = [uri]$base
    if ($baseUri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($baseUri.Host)) {
        throw "Catalog URL must use HTTPS (got '$base')."
    }
    $manifestUrl = "$base/$($config.manifestFile)"
    $sigUrl = "$manifestUrl.sig"

    Write-HushLog -Component 'fetch' -Message "Fetching catalog from $manifestUrl"

    $manifestBytes = Get-HushUrlBytes -Url $manifestUrl
    $sigBytes = Get-HushUrlBytes -Url $sigUrl

    # 1) Verify the catalog signature against the pinned public key. Hard stop on failure.
    if (-not (Test-HushSignature -Data $manifestBytes -Signature $sigBytes -PublicKeyXml $config.publicKeyXml)) {
        throw 'Manifest signature verification FAILED — refusing to update cache (keeping last-known-good).'
    }

    $manifest = [System.Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
    $manifestValid = Test-HushManifest -Manifest $manifest
    if (-not $manifestValid.Ok) {
        throw "Manifest validation failed — $($manifestValid.Errors -join '; ') — refusing to update cache."
    }

    # Reject replayed catalog metadata before downloading any definitions. A same-version
    # catalog is accepted only when its exact signed bytes are unchanged.
    $active = Get-HushCatalogFiles
    if ($active) {
        try {
            $cachedManifest = Read-HushJson -Path $active.Manifest
            $cachedVersion = if ((Test-HushProp $cachedManifest 'catalogVersion') -and
                ($cachedManifest.catalogVersion -is [int] -or $cachedManifest.catalogVersion -is [long])) {
                [int64]$cachedManifest.catalogVersion
            } else { 0 }
            if ($manifestValid.CatalogVersion -lt $cachedVersion) {
                throw "Catalog rollback blocked (incoming v$($manifestValid.CatalogVersion) < cached v$cachedVersion)."
            }
            if ($manifestValid.CatalogVersion -eq $cachedVersion -and $cachedVersion -gt 0) {
                $cachedBytes = [System.IO.File]::ReadAllBytes($active.Manifest)
                if ((Get-HushSha256Hex -Bytes $cachedBytes) -ne (Get-HushSha256Hex -Bytes $manifestBytes)) {
                    throw "Catalog version $cachedVersion was republished with different bytes."
                }
            }
        } catch {
            if ($_.Exception.Message -like 'Catalog *') { throw }
        }
    }
    Write-HushLog -Component 'fetch' -Message "Catalog signature and metadata OK (v$($manifestValid.CatalogVersion)); $(@($manifest.definitions).Count) definition(s) listed."

    # 2) Stage each definition: download, hash-check, anti-rollback, schema-validate.
    # Any failure aborts the whole fetch so the signed manifest cache never points at
    # missing, stale, or hash-mismatched definition files.
    $staged = @{}   # cacheFileName -> bytes
    $stageFailures = New-Object System.Collections.Generic.List[string]
    $activeRoot = if ($active) { $active.Root } else { $paths.Cache }
    foreach ($entry in @($manifest.definitions)) {
        # Validate the (signed) entry's own fields before they touch URLs, hashing or the
        # filesystem — a bad 'file' must never reach Join-Path (path traversal).
        $entryValid = Test-HushManifestEntry -Entry $entry
        if (-not $entryValid.Ok) {
            Write-HushLog -Level Warning -Component 'fetch' -Message "Manifest entry rejected — $($entryValid.Errors -join '; ') — skipped."
            $stageFailures.Add("manifest entry rejected: $($entryValid.Errors -join '; ')")
            continue
        }
        $defUrl = "$base/$($entry.file)"
        try {
            $defBytes = Get-HushUrlBytes -Url $defUrl
            $hash = Get-HushSha256Hex -Bytes $defBytes
            if ($hash -ne $entry.sha256.ToLowerInvariant()) {
                Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): SHA-256 mismatch (manifest=$($entry.sha256), got=$hash) — skipped."
                $stageFailures.Add("$($entry.name): SHA-256 mismatch")
                continue
            }
            $def = [System.Text.Encoding]::UTF8.GetString($defBytes) | ConvertFrom-Json

            $valid = Test-HushDefinition -Def $def
            if (-not $valid.Ok) {
                Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): schema invalid — $($valid.Errors -join '; ') — skipped."
                $stageFailures.Add("$($entry.name): schema invalid")
                continue
            }

            if (-not (Test-HushManifestDefinitionMatch -Entry $entry -Definition $def)) {
                Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): manifest metadata does not match definition — skipped."
                $stageFailures.Add("$($entry.name): manifest metadata mismatch")
                continue
            }

            # Anti-rollback vs cached copy.
            $cachedPath = Join-Path $activeRoot $entry.file
            if (Test-Path $cachedPath) {
                try {
                    $cached = Read-HushJson -Path $cachedPath
                    if ($cached -and ($def.definitionVersion -lt $cached.definitionVersion)) {
                        Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): rollback blocked (incoming v$($def.definitionVersion) < cached v$($cached.definitionVersion)) — skipped."
                        $stageFailures.Add("$($entry.name): rollback blocked")
                        continue
                    }
                    if ($cached -and ($def.definitionVersion -eq $cached.definitionVersion) -and
                        ((Get-HushFileSha256Hex -Path $cachedPath) -ne $entry.sha256.ToLowerInvariant())) {
                        Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): same definitionVersion with different bytes — skipped. Bump definitionVersion for content changes."
                        $stageFailures.Add("$($entry.name): same-version content change")
                        continue
                    }
                } catch { }
            }
            $staged[$entry.file] = $defBytes
        } catch {
            Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): fetch error — $($_.Exception.Message) — skipped."
            $stageFailures.Add("$($entry.name): fetch error")
        }
    }

    if ($stageFailures.Count -gt 0) {
        throw "Fetch incomplete; keeping last-known-good cache. $($stageFailures.Count) definition(s) failed staging."
    }

    # 3) Commit a complete immutable snapshot, then atomically switch the active pointer.
    # SYSTEM can never observe a manifest whose definition files are only partly written.
    $manifestHash = Get-HushSha256Hex -Bytes $manifestBytes
    $snapshotName = '{0}-{1}' -f $manifestValid.CatalogVersion, $manifestHash.Substring(0, 16)
    $snapshot = Join-Path $paths.Catalogs $snapshotName
    if (Test-Path $snapshot) { Remove-Item -LiteralPath $snapshot -Recurse -Force }
    New-Item -ItemType Directory -Path $snapshot -Force | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $snapshot 'manifest.json'), $manifestBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $snapshot 'manifest.json.sig'), $sigBytes)
    foreach ($file in $staged.Keys) {
        [System.IO.File]::WriteAllBytes((Join-Path $snapshot $file), $staged[$file])
    }
    Write-HushJsonAtomic -Path $paths.ActiveCatalog -Object ([pscustomobject]@{
            catalogVersion = $manifestValid.CatalogVersion
            directory      = $snapshotName
            manifestSha256 = $manifestHash
        })
    # Keep a small rollback window without allowing unbounded catalog growth. The active
    # snapshot is never selected for deletion, even if timestamps are unexpectedly equal.
    $oldSnapshots = @(Get-ChildItem -LiteralPath $paths.Catalogs -Directory -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -Skip 3)
    foreach ($old in $oldSnapshots) {
        if ($old.Name -ne $snapshotName -and $old.Name -match '^[0-9]+-[0-9a-f]{16}$') {
            Remove-Item -LiteralPath $old.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # 4) Record the successful fetch time. The fetcher (LOCAL SERVICE) writes ONLY into the
    #    cache directory it owns — it has no rights to create files in the install root, and
    #    sharing state.json with the SYSTEM enforcer would race (lost updates). The enforcer
    #    reads this for its staleness check and remains the sole writer of state.json.
    Write-HushJsonAtomic -Path $paths.FetchStatus -Object ([pscustomobject]@{
            lastFetchUtc = [datetime]::UtcNow.ToString('o')
        })

    Write-HushLog -Component 'fetch' -Message "Fetch complete. Catalog v$($manifestValid.CatalogVersion) with $($staged.Count) definition(s) verified and activated."
    exit 0
} catch {
    Write-HushLog -Level Error -Component 'fetch' -Message "Fetch aborted: $($_.Exception.Message)"
    exit 1
}
