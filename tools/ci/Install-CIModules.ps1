#Requires -Version 5.1
<#
    Install-CIModules.ps1 — installs pinned PowerShell modules for CI (and local dev).

    Skips a module that is already present at the pinned version (so warm CI module
    caches make repeated runs a no-op) and retries transient PowerShell Gallery
    failures with a short backoff, since a flaky Gallery response should not fail
    the whole workflow.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [hashtable[]]$Module,

    [int]$MaxAttempts = 3,

    [int]$RetryDelaySeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

foreach ($entry in $Module) {
    $name = $entry.Name
    $version = $entry.RequiredVersion
    $installed = Get-Module -ListAvailable -Name $name | Where-Object { $_.Version -eq $version }
    if ($installed) {
        Write-Host "$name $version already installed, skipping."
        continue
    }

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            Write-Host "Installing $name $version (attempt $attempt/$MaxAttempts)..."
            Install-Module -Name $name -RequiredVersion $version -Scope CurrentUser -Force -SkipPublisherCheck -Repository PSGallery
            break
        } catch {
            if ($attempt -ge $MaxAttempts) {
                throw "Failed to install $name $version after $MaxAttempts attempts: $($_.Exception.Message)"
            }
            Write-Warning "Install of $name $version failed: $($_.Exception.Message). Retrying in $RetryDelaySeconds s..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}
