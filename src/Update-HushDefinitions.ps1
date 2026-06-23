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

    $base = $config.repoRawBaseUrl.TrimEnd('/')
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
    if (-not (Test-HushProp $manifest 'schemaVersion') -or $manifest.schemaVersion -ne 1) {
        throw "Manifest schemaVersion unsupported ('$(if (Test-HushProp $manifest 'schemaVersion') { $manifest.schemaVersion } else { 'missing' })') — refusing to update cache."
    }
    Write-HushLog -Component 'fetch' -Message "Catalog signature OK; $(@($manifest.definitions).Count) definition(s) listed."

    # 2) Stage each definition: download, hash-check, anti-rollback, schema-validate.
    $staged = @{}   # cacheFileName -> bytes
    foreach ($entry in @($manifest.definitions)) {
        # Validate the (signed) entry's own fields before they touch URLs, hashing or the
        # filesystem — a bad 'file' must never reach Join-Path (path traversal).
        $entryValid = Test-HushManifestEntry -Entry $entry
        if (-not $entryValid.Ok) {
            Write-HushLog -Level Warning -Component 'fetch' -Message "Manifest entry rejected — $($entryValid.Errors -join '; ') — skipped."
            continue
        }
        $defUrl = "$base/$($entry.file)"
        try {
            $defBytes = Get-HushUrlBytes -Url $defUrl
            $hash = Get-HushSha256Hex -Bytes $defBytes
            if ($hash -ne $entry.sha256.ToLowerInvariant()) {
                Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): SHA-256 mismatch (manifest=$($entry.sha256), got=$hash) — skipped."
                continue
            }
            $def = [System.Text.Encoding]::UTF8.GetString($defBytes) | ConvertFrom-Json

            $valid = Test-HushDefinition -Def $def
            if (-not $valid.Ok) {
                Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): schema invalid — $($valid.Errors -join '; ') — skipped."
                continue
            }

            # Anti-rollback vs cached copy.
            $cachedPath = Join-Path $paths.Cache $entry.file
            if (Test-Path $cachedPath) {
                try {
                    $cached = Read-HushJson -Path $cachedPath
                    if ($cached -and ($def.definitionVersion -lt $cached.definitionVersion)) {
                        Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): rollback blocked (incoming v$($def.definitionVersion) < cached v$($cached.definitionVersion)) — skipped."
                        continue
                    }
                } catch { }
            }
            $staged[$entry.file] = $defBytes
        } catch {
            Write-HushLog -Level Warning -Component 'fetch' -Message "$($entry.name): fetch error — $($_.Exception.Message) — skipped."
        }
    }

    # 3) Commit atomically: manifest + signature first, then each staged definition.
    [System.IO.File]::WriteAllBytes("$($paths.ManifestCache).new", $manifestBytes)
    Move-Item -Path "$($paths.ManifestCache).new" -Destination $paths.ManifestCache -Force
    [System.IO.File]::WriteAllBytes("$($paths.ManifestSigCache).new", $sigBytes)
    Move-Item -Path "$($paths.ManifestSigCache).new" -Destination $paths.ManifestSigCache -Force

    foreach ($file in $staged.Keys) {
        $dest = Join-Path $paths.Cache $file
        [System.IO.File]::WriteAllBytes("$dest.new", $staged[$file])
        Move-Item -Path "$dest.new" -Destination $dest -Force
    }

    # 4) Record the successful fetch time. The fetcher (LOCAL SERVICE) writes ONLY into the
    #    cache directory it owns — it has no rights to create files in the install root, and
    #    sharing state.json with the SYSTEM enforcer would race (lost updates). The enforcer
    #    reads this for its staleness check and remains the sole writer of state.json.
    Write-HushJsonAtomic -Path $paths.FetchStatus -Object ([pscustomobject]@{
            lastFetchUtc = [datetime]::UtcNow.ToString('o')
        })

    Write-HushLog -Component 'fetch' -Message "Fetch complete. $($staged.Count) definition(s) verified and cached."
    exit 0
} catch {
    Write-HushLog -Level Error -Component 'fetch' -Message "Fetch aborted: $($_.Exception.Message)"
    exit 1
}
