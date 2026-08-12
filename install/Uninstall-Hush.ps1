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
$root = Join-Path $env:ProgramData 'Hush'

# Restore all tracked reversible changes before removing the scheduled tasks or journal.
# A failed restore aborts uninstall so the operator can recover with Hush still present.
$rollbackScript = Join-Path $root 'bin\Invoke-Hush.ps1'
$changesPath = Join-Path $root 'changes.json'
if ((Test-Path -LiteralPath $rollbackScript) -and (Test-Path -LiteralPath $changesPath)) {
    & $rollbackScript -RollbackAll | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Hush rollback failed; uninstall aborted and data was preserved.' }
    Write-Host '  restored Hush-managed reversible changes'
}

foreach ($task in @('Hush-Fetch', 'Hush-Enforce')) {
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
