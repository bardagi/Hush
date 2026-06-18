#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
    Uninstall-Hush.ps1 — removes the scheduled tasks, Event Log source, Start-Menu
    shortcut, and (optionally) the install directory.

    By default the install directory C:\ProgramData\Hush is left in place so logs and
    autostart backups survive. Pass -RemoveData to delete everything.
#>

[CmdletBinding()]
param([switch]$RemoveData)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Write-Host 'Removing Hush ...' -ForegroundColor Cyan

foreach ($task in @('Hush-Fetch','Hush-Enforce')) {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
        Write-Host "  removed scheduled task $task"
    }
}

$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Hush Settings.lnk'
if (Test-Path $shortcut) { Remove-Item $shortcut -Force; Write-Host '  removed Start-Menu shortcut' }

try {
    if ([System.Diagnostics.EventLog]::SourceExists('Hush')) {
        Remove-EventLog -Source 'Hush'
        Write-Host '  removed Event Log source'
    }
} catch { }

$root = Join-Path $env:ProgramData 'Hush'
if ($RemoveData) {
    if (Test-Path $root) {
        # Restore inheritance so removal isn't blocked by the hardened ACL.
        & icacls $root /reset /T /C | Out-Null
        Remove-Item -Path $root -Recurse -Force
        Write-Host "  deleted $root"
    }
} else {
    Write-Host "  kept data at $root (use -RemoveData to delete logs, backups, config)"
}

Write-Host 'Hush uninstalled.' -ForegroundColor Green
