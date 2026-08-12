#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
    Install-Hush.ps1   — run once per machine, elevated.

    Deploys Hush to C:\ProgramData\Hush, hardens ACLs (anti-privilege-escalation),
    registers the Windows Event Log source, and creates two scheduled tasks:
      * Hush-Fetch   as LOCAL SERVICE  (network: download + verify + cache)
      * Hush-Enforce as SYSTEM         (apply cached, re-verified policy)
    plus a "Hush Settings" Start-Menu shortcut to the self-elevating GUI.

    Example:
      .\Install-Hush.ps1 `
          -RepoRawBaseUrl 'https://raw.githubusercontent.com/bardagi/hush-definitions/main/definitions' `
          -PublicKeyPath  '.\hush-public.xml' `
          -EnabledDefinitions chrome-background
#>

[CmdletBinding()]
param(
    [string]$RepoRawBaseUrl = 'https://raw.githubusercontent.com/bardagi/hush-definitions/main/definitions',
    [string[]]$PublicKeyXml,
    [string[]]$PublicKeyPath,
    [string]$ManifestFile = 'manifest.json',
    [int]$IntervalMinutes = 15,
    [int]$MaxDefinitionAgeHours = 72,
    [string[]]$EnabledDefinitions = @(),
    [string[]]$ProtectedServices = @('WinDefend', 'Sense', 'wuauserv')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# One or more pinned public keys may be supplied (pass several to enable overlap-based key
# rotation: pin the new key alongside the old, re-sign with the new private key, then later
# re-run the installer dropping the old key).
$pinnedKeys = @()
if ($PublicKeyXml) { $pinnedKeys += $PublicKeyXml }
if ($PublicKeyPath) { foreach ($p in $PublicKeyPath) { $pinnedKeys += (Get-Content -Path $p -Raw) } }
$pinnedKeys = @($pinnedKeys | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($pinnedKeys.Count -eq 0) { throw 'Provide -PublicKeyXml or -PublicKeyPath (the pinned RSA public key).' }
try {
    $repoUri = [uri]$RepoRawBaseUrl
    if ($repoUri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($repoUri.Host)) { throw 'not https' }
} catch { throw "RepoRawBaseUrl must be an HTTPS URL (got '$RepoRawBaseUrl')." }

$repoRoot = Split-Path -Parent $PSScriptRoot
$srcDir = Join-Path $repoRoot 'src'
$guiDir = Join-Path $repoRoot 'gui'

$root = Join-Path $env:ProgramData 'Hush'
$bin = Join-Path $root 'bin'
$cache = Join-Path $root 'cache'
$catalogs = Join-Path $cache 'catalogs'
$logs = Join-Path $root 'logs'
$backups = Join-Path $root 'backups'

. (Join-Path $srcDir 'Hush.InstallSecurity.ps1')

Write-Host "Installing Hush to $root ..." -ForegroundColor Cyan

# 1) Validate the pre-existing root before creating or traversing any child path.
Assert-HushInstallTreeSafe -Root $root
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
}
Assert-HushInstallTreeSafe -Root $root

# 2) Folders. Directories are checked as a group before the nested catalog path is touched.
foreach ($d in @($bin, $cache, $logs, $backups)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
Assert-HushInstallTreeSafe -Root $root
if (-not (Test-Path -LiteralPath $catalogs -PathType Container)) {
    New-Item -ItemType Directory -Path $catalogs -Force | Out-Null
}

# 3) Secure the tree BEFORE copying any SYSTEM-executed script. This also repairs a
#    pre-existing ProgramData\Hush tree, but refuses reparse points rather than traversing
#    attacker-controlled locations.
Protect-HushInstallTree -Root $root -Bin $bin -Cache $cache -Logs $logs -Backups $backups

# 4) Copy scripts + GUI into the already-hardened executable directory.
Copy-Item -Path (Join-Path $srcDir '*.ps1') -Destination $bin -Force
Copy-Item -Path (Join-Path $guiDir 'Hush-Settings.ps1') -Destination $bin -Force

# 5) config.json
$config = [pscustomobject]@{
    repoRawBaseUrl        = $RepoRawBaseUrl
    manifestFile          = $ManifestFile
    # A single key is stored as a string (back-compat); multiple keys as an array. Test-HushSignature
    # accepts either and verifies if ANY key matches.
    publicKeyXml          = if ($pinnedKeys.Count -eq 1) { $pinnedKeys[0] } else { $pinnedKeys }
    intervalMinutes       = $IntervalMinutes
    maxDefinitionAgeHours = $MaxDefinitionAgeHours
    protectedServices     = $ProtectedServices
}
$configPath = Join-Path $root 'config.json'
$config | ConvertTo-Json -Depth 8 | Set-Content -Path $configPath -Encoding UTF8
Protect-HushConfigFile -Root $root -ConfigPath $configPath

# 6) Seed state files if absent (don't clobber on re-install)
$enabledPath = Join-Path $root 'enabled.json'
$exclPath = Join-Path $root 'exclusions.json'
$preferencesPath = Join-Path $root 'preferences.json'
$statePath = Join-Path $root 'state.json'
if (-not (Test-Path $enabledPath)) {
    [pscustomobject]@{ enabled = $EnabledDefinitions; optionalActions = [pscustomobject]@{} } |
        ConvertTo-Json -Depth 8 | Set-Content $enabledPath -Encoding UTF8
}
if (-not (Test-Path $exclPath)) {
    [pscustomobject]@{ processes = @(); services = @(); autostarts = @() } | ConvertTo-Json | Set-Content $exclPath -Encoding UTF8
}
if (-not (Test-Path $preferencesPath)) {
    [pscustomobject]@{ snoozeUntil = $null; quietHours = @() } |
        ConvertTo-Json -Depth 8 | Set-Content $preferencesPath -Encoding UTF8
}
if (-not (Test-Path $statePath)) {
    [pscustomobject]@{ appliedVersions = @{}; catalogVersion = 0; lastEnforceUtc = $null } |
        ConvertTo-Json | Set-Content $statePath -Encoding UTF8
}

# 7) Event Log source
if (-not [System.Diagnostics.EventLog]::SourceExists('Hush')) {
    New-EventLog -LogName 'Application' -Source 'Hush'
}

# 8) Scheduled tasks
function Resolve-HushWindowsPowerShell {
    $candidates = @()
    if ($env:windir) {
        $candidates += (Join-Path $env:windir 'Sysnative\WindowsPowerShell\v1.0\powershell.exe')
        $candidates += (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe')
    }
    $cmd = Get-Command 'powershell.exe' -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    throw 'Could not find Windows PowerShell (powershell.exe) for scheduled tasks.'
}
$ps = Resolve-HushWindowsPowerShell
function New-HushRepeatingTriggers {
    param([int]$OffsetMinutes)
    $rep = New-ScheduledTaskTrigger -Once -At ((Get-Date).Date.AddMinutes($OffsetMinutes)) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
    @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn), $rep)
}
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 1)

$fetchAction = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$bin\Update-HushDefinitions.ps1`""
$fetchPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount
Register-ScheduledTask -TaskName 'Hush-Fetch' -Force -Description 'Hush: download + verify definition catalog (low privilege).' `
    -Action $fetchAction -Trigger (New-HushRepeatingTriggers -OffsetMinutes 1) -Principal $fetchPrincipal -Settings $settings | Out-Null

$enforceAction = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$bin\Invoke-Hush.ps1`""
$enforcePrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Hush-Enforce' -Force -Description 'Hush: apply cached, re-verified background policy (SYSTEM).' `
    -Action $enforceAction -Trigger (New-HushRepeatingTriggers -OffsetMinutes 2) -Principal $enforcePrincipal -Settings $settings | Out-Null

# 9) Start-Menu shortcut to the GUI
$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Hush Settings.lnk'
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut($shortcut)
$lnk.TargetPath = $ps
$lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$bin\Hush-Settings.ps1`""
$lnk.IconLocation = "$ps,0"
$lnk.Description = 'Choose what Hush closes in the background'
$lnk.Save()

# 10) Prime the cache (best-effort — needs a real repo URL + key configured)
Write-Host 'Priming definition cache ...' -ForegroundColor Cyan
try { Start-ScheduledTask -TaskName 'Hush-Fetch' } catch { }

Write-Host ''
Write-Host 'Hush installed.' -ForegroundColor Green
Write-Host "  Tasks   : Hush-Fetch (LOCAL SERVICE), Hush-Enforce (SYSTEM), every $IntervalMinutes min + startup/logon"
Write-Host "  Settings: Start Menu > 'Hush Settings'  (or $bin\Hush-Settings.ps1)"
Write-Host "  Logs    : $logs\hush.log   |   Event Log: Application/Hush"
Write-Host '  Next    : open Hush Settings to choose which definitions to enforce.'
