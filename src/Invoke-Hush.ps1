#Requires -Version 5.1
<#
    Invoke-Hush.ps1   (ENFORCER)

    Runs as NT AUTHORITY\SYSTEM on a schedule. NEVER touches the network. Reads the
    locally cached, signed catalog, RE-VERIFIES it against the pinned public key (the
    trust boundary versus the lower-privileged fetcher), then applies the actions for
    each admin-enabled definition — honouring hard guardrails, local exclusions, the
    snooze / quiet-hours gate, and -Preview (dry-run).

    -Preview : compute and emit what WOULD happen without changing anything (used by GUI).
#>

[CmdletBinding()]
param([switch]$Preview)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Hush.Common.ps1')

$allResults = New-Object System.Collections.Generic.List[object]

try {
    $paths = Get-HushPaths
    $config = Get-HushConfig
    if (-not $config) { throw "Config not found at $($paths.Config)" }
    $enabledDoc = Read-HushJson -Path $paths.Enabled
    $enabled = @(); if ($enabledDoc -and $enabledDoc.enabled) { $enabled = @($enabledDoc.enabled) }
    $exclusions = Read-HushJson -Path $paths.Exclusions
    $state = Read-HushJson -Path $paths.State
    if (-not $state) { $state = [pscustomobject]@{} }

    # --- Snooze / quiet-hours gate (preview bypasses so you can always see the plan) ---
    if (-not $Preview) {
        $snooze = Test-HushSnoozed -State $state
        if ($snooze.Snoozed) {
            Write-HushLog -Component 'enforce' -Message "Enforcement skipped ($($snooze.Reason))."
            $state | Add-Member lastEnforceUtc ([datetime]::UtcNow.ToString('o')) -Force
            $state | Add-Member lastEnforceResult "skipped: $($snooze.Reason)" -Force
            Write-HushJsonAtomic -Path $paths.State -Object $state
            exit 0
        }
    }

    if ($enabled.Count -eq 0) {
        Write-HushLog -Component 'enforce' -Message 'No definitions enabled — nothing to do.'
    }

    # --- Re-verify the cached catalog against the pinned public key ---
    if (-not (Test-Path $paths.ManifestCache) -or -not (Test-Path $paths.ManifestSigCache)) {
        throw 'No cached catalog yet (fetcher has not produced a verified manifest). Skipping.'
    }
    $manifestBytes = [System.IO.File]::ReadAllBytes($paths.ManifestCache)
    $sigBytes = [System.IO.File]::ReadAllBytes($paths.ManifestSigCache)
    if (-not (Test-HushSignature -Data $manifestBytes -Signature $sigBytes -PublicKeyXml $config.publicKeyXml)) {
        throw 'Cached manifest signature INVALID — refusing to apply anything.'
    }
    $manifest = [System.Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
    if (-not (Test-HushProp $manifest 'schemaVersion') -or $manifest.schemaVersion -ne 1) {
        throw "Cached manifest schemaVersion unsupported — refusing to apply anything."
    }

    # --- Manifest-level anti-rollback ---
    # Per-definition versions block downgrading a single definition; this blocks replaying a
    # whole older (but still validly-signed) catalog, which could otherwise drop/withhold
    # definitions. We record the highest manifest updateDate we've applied and refuse anything
    # older. Missing/unparseable dates skip the check (the manifest is still signature-gated).
    $manifestDate = $null
    if ((Test-HushProp $manifest 'updateDate') -and $manifest.updateDate) {
        try { $manifestDate = ConvertTo-HushUtc $manifest.updateDate } catch { }
    }
    $priorManifestDate = $null
    if ((Test-HushProp $state 'manifestUpdateDate') -and $state.manifestUpdateDate) {
        try { $priorManifestDate = ConvertTo-HushUtc $state.manifestUpdateDate } catch { }
    }
    if ($manifestDate -and $priorManifestDate -and ($manifestDate -lt $priorManifestDate)) {
        throw "Cached manifest rollback blocked (updateDate $($manifestDate.ToString('o')) < last-applied $($priorManifestDate.ToString('o'))) — refusing to apply anything."
    }

    $byName = @{}
    foreach ($e in @($manifest.definitions)) {
        # Re-validate each entry's own fields (name/file/sha256) before they index the cache
        # or feed Join-Path — the trust boundary versus the lower-privileged fetcher.
        $entryValid = Test-HushManifestEntry -Entry $e
        if (-not $entryValid.Ok) {
            Write-HushLog -Level Warning -Component 'enforce' -Message "Manifest entry rejected — $($entryValid.Errors -join '; ') — ignored."
            continue
        }
        $byName[$e.name] = $e
    }

    # --- Stale-definition alert ---
    # The fetcher records its last success in fetch-status.json (the cache dir it owns);
    # fall back to the manifest cache mtime if that file is missing.
    $lastFetch = $null
    $fetchStatus = Read-HushJson -Path $paths.FetchStatus
    if ((Test-HushProp $fetchStatus 'lastFetchUtc') -and $fetchStatus.lastFetchUtc) {
        try { $lastFetch = ConvertTo-HushUtc $fetchStatus.lastFetchUtc } catch { }
    }
    if (-not $lastFetch) { $lastFetch = (Get-Item $paths.ManifestCache).LastWriteTimeUtc }
    $ageHours = ([datetime]::UtcNow - $lastFetch).TotalHours
    $maxAge = if (Test-HushProp $config 'maxDefinitionAgeHours') { [double]$config.maxDefinitionAgeHours } else { 72 }
    $stale = $ageHours -gt $maxAge
    if ($stale) {
        Write-HushLog -Level Warning -Component 'enforce' -Message ("Definitions are STALE: last verified fetch {0:N1}h ago (> {1}h)." -f $ageHours, $maxAge)
    }

    # --- Applied-version tracking for anti-rollback ---
    $applied = @{}
    if ((Test-HushProp $state 'appliedVersions') -and $state.appliedVersions) {
        foreach ($p in $state.appliedVersions.PSObject.Properties) { $applied[$p.Name] = $p.Value }
    }

    $context = [pscustomobject]@{ Preview = [bool]$Preview; Exclusions = $exclusions; Config = $config }

    foreach ($name in $enabled) {
        if (-not $byName.ContainsKey($name)) {
            Write-HushLog -Level Warning -Component 'enforce' -Message "Enabled '$name' is not in the signed catalog — ignored."
            continue
        }
        $entry = $byName[$name]
        $defPath = Join-Path $paths.Cache $entry.file
        if (-not (Test-Path $defPath)) {
            Write-HushLog -Level Warning -Component 'enforce' -Message "'$name' not cached yet — will apply after next fetch."
            continue
        }
        # Re-hash the cached file against the (signed) manifest entry.
        $hash = Get-HushFileSha256Hex -Path $defPath
        if ($hash -ne $entry.sha256.ToLowerInvariant()) {
            Write-HushLog -Level Warning -Component 'enforce' -Message "'$name' cache hash mismatch vs signed manifest — skipped."
            continue
        }
        $def = Read-HushJson -Path $defPath
        $valid = Test-HushDefinition -Def $def
        if (-not $valid.Ok) {
            Write-HushLog -Level Warning -Component 'enforce' -Message "'$name' failed schema re-check — $($valid.Errors -join '; ') — skipped."
            continue
        }
        if ($applied.ContainsKey($name) -and ($def.definitionVersion -lt $applied[$name])) {
            Write-HushLog -Level Warning -Component 'enforce' -Message "'$name' rollback blocked (v$($def.definitionVersion) < applied v$($applied[$name])) — skipped."
            continue
        }

        $verb = if ($Preview) { 'Preview' } else { 'Applying' }
        Write-HushLog -Component 'enforce' -Message "$verb '$name' (v$($def.definitionVersion))."
        foreach ($action in @($def.actions)) {
            foreach ($r in @(Invoke-HushAction -Action $action -Context $context)) {
                $allResults.Add($r)
                $msg = "[$name] $($r.Type) $($r.Target): $($r.Status) — $($r.Detail)"
                if ($r.Status -eq 'Error') { Write-HushLog -Level Error -Component 'enforce' -Message $msg }
                elseif ($r.Status -in @('Blocked', 'Excluded')) { Write-HushLog -Level Warning -Component 'enforce' -Message $msg }
                else { Write-HushLog -Component 'enforce' -Message $msg }
            }
        }
        if (-not $Preview) { $applied[$name] = $def.definitionVersion }
    }

    # --- Persist state (skip in preview so dry-runs are side-effect free) ---
    if (-not $Preview) {
        $appl = @($allResults | Where-Object { $_.Status -eq 'Applied' }).Count
        $errs = @($allResults | Where-Object { $_.Status -eq 'Error' }).Count
        $blocked = @($allResults | Where-Object { $_.Status -in @('Blocked', 'Excluded') }).Count
        $state | Add-Member appliedVersions ([pscustomobject]$applied) -Force
        if ($manifestDate) { $state | Add-Member manifestUpdateDate ($manifestDate.ToString('o')) -Force }
        $state | Add-Member staleDefinitions ([bool]$stale) -Force
        $state | Add-Member lastEnforceUtc ([datetime]::UtcNow.ToString('o')) -Force
        $state | Add-Member lastEnforceResult "applied=$appl errors=$errs blocked/excluded=$blocked" -Force
        Write-HushJsonAtomic -Path $paths.State -Object $state
        Write-HushLog -Component 'enforce' -Message "Done. applied=$appl errors=$errs blocked/excluded=$blocked"
    }

    # Emit results so callers (the GUI Preview button) can display them.
    $allResults
    exit 0
} catch {
    Write-HushLog -Level Error -Component 'enforce' -Message "Enforce aborted: $($_.Exception.Message)"
    $allResults
    exit 1
}
