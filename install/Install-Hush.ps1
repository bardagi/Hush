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
          -RepoRawBaseUrl 'https://raw.githubusercontent.com/your-org/hush-definitions/main/definitions' `
          -PublicKeyPath  '.\hush-public.xml' `
          -EnabledDefinitions chrome-background
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoRawBaseUrl,
    [string]$PublicKeyXml,
    [string]$PublicKeyPath,
    [string]$ManifestFile = 'manifest.json',
    [int]$IntervalMinutes = 15,
    [int]$MaxDefinitionAgeHours = 72,
    [string[]]$EnabledDefinitions = @(),
    [string[]]$ProtectedServices = @('WinDefend', 'Sense', 'wuauserv')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $PublicKeyXml -and -not $PublicKeyPath) { throw 'Provide -PublicKeyXml or -PublicKeyPath (the pinned RSA public key).' }
if ($PublicKeyPath) { $PublicKeyXml = Get-Content -Path $PublicKeyPath -Raw }

$repoRoot = Split-Path -Parent $PSScriptRoot
$srcDir = Join-Path $repoRoot 'src'
$guiDir = Join-Path $repoRoot 'gui'

$root = Join-Path $env:ProgramData 'Hush'
$bin = Join-Path $root 'bin'
$cache = Join-Path $root 'cache'
$logs = Join-Path $root 'logs'
$backups = Join-Path $root 'backups'

Write-Host "Installing Hush to $root ..." -ForegroundColor Cyan

# 1) Folders
foreach ($d in @($root, $bin, $cache, $logs, $backups)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# 2) Copy scripts + GUI
Copy-Item -Path (Join-Path $srcDir '*.ps1') -Destination $bin -Force
Copy-Item -Path (Join-Path $guiDir 'Hush-Settings.ps1') -Destination $bin -Force

# 3) config.json
$config = [pscustomobject]@{
    repoRawBaseUrl        = $RepoRawBaseUrl
    manifestFile          = $ManifestFile
    publicKeyXml          = $PublicKeyXml.Trim()
    intervalMinutes       = $IntervalMinutes
    maxDefinitionAgeHours = $MaxDefinitionAgeHours
    protectedServices     = $ProtectedServices
}
$config | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $root 'config.json') -Encoding UTF8

# 4) Seed state files if absent (don't clobber on re-install)
$enabledPath = Join-Path $root 'enabled.json'
$exclPath = Join-Path $root 'exclusions.json'
$statePath = Join-Path $root 'state.json'
if (-not (Test-Path $enabledPath)) {
    [pscustomobject]@{ enabled = $EnabledDefinitions } | ConvertTo-Json | Set-Content $enabledPath -Encoding UTF8
}
if (-not (Test-Path $exclPath)) {
    [pscustomobject]@{ processes = @(); services = @(); autostarts = @() } | ConvertTo-Json | Set-Content $exclPath -Encoding UTF8
}
if (-not (Test-Path $statePath)) {
    [pscustomobject]@{ snoozeUntil = $null; quietHours = @(); appliedVersions = @{}; lastFetchUtc = $null; lastEnforceUtc = $null } |
        ConvertTo-Json | Set-Content $statePath -Encoding UTF8
}

# 5) Harden ACLs (SIDs: SYSTEM=S-1-5-18, LOCAL SERVICE=S-1-5-19, Admins=S-1-5-32-544, Users=S-1-5-32-545)
Write-Host 'Hardening permissions ...' -ForegroundColor Cyan
& icacls $root /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' '*S-1-5-19:(OI)(CI)RX' | Out-Null
# Fetcher (LOCAL SERVICE) needs to write the cache and update lastFetch in state.json.
& icacls $cache /grant:r '*S-1-5-19:(OI)(CI)M' | Out-Null
& icacls $statePath /grant:r '*S-1-5-19:M' | Out-Null

# 6) Event Log source
if (-not [System.Diagnostics.EventLog]::SourceExists('Hush')) {
    New-EventLog -LogName 'Application' -Source 'Hush'
}

# 7) Scheduled tasks
$ps = Join-Path $PSHOME 'powershell.exe'
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

# 8) Start-Menu shortcut to the GUI
$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Hush Settings.lnk'
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut($shortcut)
$lnk.TargetPath = $ps
$lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$bin\Hush-Settings.ps1`""
$lnk.IconLocation = "$ps,0"
$lnk.Description = 'Choose what Hush closes in the background'
$lnk.Save()

# 9) Prime the cache (best-effort — needs a real repo URL + key configured)
Write-Host 'Priming definition cache ...' -ForegroundColor Cyan
try { Start-ScheduledTask -TaskName 'Hush-Fetch' } catch { }

Write-Host ''
Write-Host 'Hush installed.' -ForegroundColor Green
Write-Host "  Tasks   : Hush-Fetch (LOCAL SERVICE), Hush-Enforce (SYSTEM), every $IntervalMinutes min + startup/logon"
Write-Host "  Settings: Start Menu > 'Hush Settings'  (or $bin\Hush-Settings.ps1)"
Write-Host "  Logs    : $logs\hush.log   |   Event Log: Application/Hush"
Write-Host '  Next    : open Hush Settings to choose which definitions to enforce.'
