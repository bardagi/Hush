#Requires -Version 5.1
<#
    Hush.Core.ps1
    Core paths, persistence, logging, and cryptographic helpers.

    This file is dot-sourced by the Hush compatibility loaders.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------- paths

function Get-HushRoot {
    # Override with $env:HUSH_ROOT for testing without touching ProgramData.
    if ($env:HUSH_ROOT) { return $env:HUSH_ROOT }
    return (Join-Path $env:ProgramData 'Hush')
}

function Get-HushPaths {
    $root = Get-HushRoot
    [pscustomobject]@{
        Root             = $root
        Bin              = Join-Path $root 'bin'
        Cache            = Join-Path $root 'cache'
        Logs             = Join-Path $root 'logs'
        Backups          = Join-Path $root 'backups'
        Catalogs         = Join-Path (Join-Path $root 'cache') 'catalogs'
        ActiveCatalog    = Join-Path (Join-Path $root 'cache') 'active-catalog.json'
        Config           = Join-Path $root 'config.json'
        Enabled          = Join-Path $root 'enabled.json'
        Exclusions       = Join-Path $root 'exclusions.json'
        Preferences      = Join-Path $root 'preferences.json'
        Changes          = Join-Path $root 'changes.json'
        State            = Join-Path $root 'state.json'
        FetchStatus      = Join-Path (Join-Path $root 'cache') 'fetch-status.json'
        LogFile          = Join-Path (Join-Path $root 'logs') 'hush.log'
        ManifestCache    = Join-Path (Join-Path $root 'cache') 'manifest.json'
        ManifestSigCache = Join-Path (Join-Path $root 'cache') 'manifest.json.sig'
    }
}

$script:HushEventSource = 'Hush'

# ----------------------------------------------------------------------------- logging

function Write-HushLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')][string]$Level = 'Info',
        [string]$Component = 'Hush'
    )
    $paths = Get-HushPaths
    $line = '{0} [{1}] [{2}] {3}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Component, $Message

    try {
        if (-not (Test-Path $paths.Logs)) { New-Item -ItemType Directory -Path $paths.Logs -Force | Out-Null }
        # Rotate at ~1 MB (keep one previous file).
        if ((Test-Path $paths.LogFile) -and ((Get-Item $paths.LogFile).Length -gt 1MB)) {
            Move-Item -Path $paths.LogFile -Destination "$($paths.LogFile).1" -Force
        }
        Add-Content -Path $paths.LogFile -Value $line -Encoding UTF8
    } catch { }

    try {
        if ([System.Diagnostics.EventLog]::SourceExists($script:HushEventSource)) {
            $entry = switch ($Level) { 'Error' { 'Error' } 'Warning' { 'Warning' } default { 'Information' } }
            $eventId = switch ($Level) { 'Error' { 1003 } 'Warning' { 1002 } default { 1001 } }
            Write-EventLog -LogName 'Application' -Source $script:HushEventSource -EntryType $entry -EventId $eventId -Message $Message
        }
    } catch { }

    switch ($Level) {
        'Error' { Write-Host $line -ForegroundColor Red }
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

# ----------------------------------------------------------------------------- JSON I/O

function Read-HushJson {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Write-HushJsonAtomic {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Object)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = $Object | ConvertTo-Json -Depth 16
    $tmp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    Set-Content -Path $tmp -Value $json -Encoding UTF8
    Move-Item -Path $tmp -Destination $Path -Force   # rename = atomic on same volume
}

function Get-HushConfig { Read-HushJson -Path (Get-HushPaths).Config }

function Get-HushPreferences {
    $paths = Get-HushPaths
    $preferences = Read-HushJson -Path $paths.Preferences
    if ($preferences) { return $preferences }

    # One-time migration from the pre-preferences state document. Only the two user-owned
    # fields are copied; runtime telemetry and anti-rollback state stay enforcer-owned.
    $legacy = Read-HushJson -Path $paths.State
    $preferences = [pscustomobject]@{
        snoozeUntil = if ($legacy -and (Test-HushProp $legacy 'snoozeUntil')) { $legacy.snoozeUntil } else { $null }
        quietHours  = if ($legacy -and (Test-HushProp $legacy 'quietHours')) { @($legacy.quietHours) } else { @() }
    }
    try { Write-HushJsonAtomic -Path $paths.Preferences -Object $preferences } catch { }
    return $preferences
}

function Test-HushProp {
    # Safe "does this object have this property?" — works on empty PSCustomObjects under
    # StrictMode (where `$o.PSObject.Properties.Name -contains 'x'` throws if $o has none).
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $false }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function ConvertTo-HushUtc {
    # Normalize a timestamp to UTC DateTime, whether it arrives as a string or as a
    # [datetime] (ConvertFrom-Json auto-converts ISO strings to DateTime).
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    return [datetimeoffset]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind).UtcDateTime
}

# ----------------------------------------------------------------------------- crypto

function Get-HushSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-HushFileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    Get-HushSha256Hex -Bytes ([System.IO.File]::ReadAllBytes($Path))
}

function Test-HushSignature {
    <#
        Verify an RSA PKCS#1 v1.5 / SHA-256 signature against one or more pinned public keys
        (XML). Returns true if ANY pinned key verifies. Accepting several keys enables
        overlap-based key rotation — pin the new key alongside the old, re-sign with the new
        private key, then later drop the old key — with no flag-day reinstall.
    #>
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][byte[]]$Signature,
        [Parameter(Mandatory)]$PublicKeyXml
    )
    foreach ($keyXml in @($PublicKeyXml)) {
        if ([string]::IsNullOrWhiteSpace([string]$keyXml)) { continue }
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        try {
            $rsa.FromXmlString([string]$keyXml)
            if ($rsa.VerifyData($Data, 'SHA256', $Signature)) { return $true }
        } catch {
            Write-HushLog -Level Error -Component 'Verify' -Message "Signature verification threw: $($_.Exception.Message)"
        } finally { $rsa.Dispose() }
    }
    return $false
}
