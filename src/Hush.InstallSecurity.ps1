#Requires -Version 5.1
<#
    Installation-tree security helpers.

    These functions are deliberately separate from Hush.Common.ps1: they are used only by
    the elevated installer and must run before any SYSTEM-executed script is copied into
    ProgramData.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-HushIcacls {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Description
    )
    & icacls.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "ACL operation failed ($Description), exit code $LASTEXITCODE."
    }
}

function Get-HushReparsePoints {
    param([Parameter(Mandatory)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    $items = @()
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $items += $rootItem.FullName }
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $items += $item.FullName }
    }
    return @($items)
}

function ConvertTo-HushSecurityIdentifier {
    param([Parameter(Mandatory)]$Identity)
    try {
        if ($Identity -is [Security.Principal.SecurityIdentifier]) { return $Identity.Value }
        if ($Identity -is [Security.Principal.NTAccount]) {
            return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value
        }
        return (New-Object System.Security.Principal.NTAccount([string]$Identity)).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch { return ([string]$Identity).ToUpperInvariant() }
}

function Assert-HushInstallTreeSafe {
    param([Parameter(Mandatory)][string]$Root)
    if ([string]::IsNullOrWhiteSpace($Root)) { throw 'Install root is empty.' }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if (-not $rootFull.Equals(([IO.Path]::GetFullPath((Join-Path $env:ProgramData 'Hush')).TrimEnd('\', '/')), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to secure unexpected install root '$Root'."
    }
    $reparse = @(Get-HushReparsePoints -Root $Root)
    if ($reparse.Count -gt 0) {
        throw "Install tree contains reparse point(s): $($reparse -join ', '). Remove them and retry."
    }
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        if (Test-Path -LiteralPath $Root) { throw "Install root '$Root' is not a directory." }
        return
    }

    # A standard user can pre-create ProgramData\Hush. Do not silently bless an
    # explicit ACE from an unknown principal (for example Everyone:F) before the
    # tree is repaired. Inherited ProgramData entries are intentionally ignored:
    # Protect-HushInstallTree replaces them immediately with the Hush allowlist.
    $allowedPrincipals = @(
        'S-1-5-18',       # SYSTEM
        'S-1-5-32-544',   # BUILTIN\Administrators
        'S-1-5-19',       # LOCAL SERVICE
        'S-1-5-32-545',   # BUILTIN\Users
        ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    ) | ForEach-Object { $_.ToUpperInvariant() }
    $trustedInstaller = $null
    try {
        $trustedInstaller = (New-Object System.Security.Principal.NTAccount('NT SERVICE\TrustedInstaller')).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch { }
    $allowedOwners = @('S-1-5-18', 'S-1-5-32-544', ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value), $trustedInstaller) |
        Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() }
    foreach ($itemPath in @($Root) + @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop | ForEach-Object FullName)) {
        $acl = Get-Acl -LiteralPath $itemPath -ErrorAction Stop
        $owner = ConvertTo-HushSecurityIdentifier -Identity $acl.Owner
        if ($allowedOwners -notcontains $owner) {
            throw "Install tree item '$itemPath' has unsafe owner '$($acl.Owner)'. Remove it and retry."
        }
        foreach ($ace in @($acl.Access | Where-Object { -not $_.IsInherited })) {
            $principal = ConvertTo-HushSecurityIdentifier -Identity $ace.IdentityReference
            if ($allowedPrincipals -notcontains $principal) {
                throw "Install tree has an explicit ACE for unknown principal '$($ace.IdentityReference.Value)' on '$itemPath'. Remove it and retry."
            }
        }
    }
}

function Protect-HushInstallTree {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Bin,
        [Parameter(Mandatory)][string]$Cache,
        [Parameter(Mandatory)][string]$Logs,
        [Parameter(Mandatory)][string]$Backups
    )

    Assert-HushInstallTreeSafe -Root $Root

    # Take ownership and remove inherited/unknown ACEs before applying the exact policy.
    # A pre-created tree is accepted only when its owner/explicit principals pass the
    # preflight above; otherwise the installer aborts before it touches executable files.
    Invoke-HushIcacls @($Root, '/setowner', '*S-1-5-18', '/T', '/C') 'set SYSTEM owner'
    Invoke-HushIcacls @($Root, '/reset', '/T', '/C') 'reset inherited ACLs'

    # The root is traversable by users so the Start Menu shortcut can launch the GUI, but
    # users do not inherit read access to configuration, logs, backups, or runtime state.
    Invoke-HushIcacls @($Root, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-19:RX',
        '*S-1-5-32-545:X') 'secure install root'

    Invoke-HushIcacls @($Bin, '/reset', '/T', '/C') 'reset executable directory ACLs'
    Invoke-HushIcacls @($Bin, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-19:(OI)(CI)RX',
        '*S-1-5-32-545:(OI)(CI)RX', '/T', '/C') 'secure executable directory'

    Invoke-HushIcacls @($Cache, '/reset', '/T', '/C') 'reset cache directory ACLs'
    Invoke-HushIcacls @($Cache, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-19:(OI)(CI)M', '/T', '/C') 'secure cache directory'

    # LOCAL SERVICE needs to append/rotate fetch telemetry, but must not read the
    # recovery backups. Keep the two directories separate so this grant cannot
    # reach autostart payloads or journaled state.
    Invoke-HushIcacls @($Logs, '/reset', '/T', '/C') 'reset log directory ACLs'
    Invoke-HushIcacls @($Logs, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-19:(OI)(CI)M', '/T', '/C') 'secure log directory'
    foreach ($privateDir in @($Backups)) {
        Invoke-HushIcacls @($privateDir, '/reset', '/T', '/C') "reset private directory '$privateDir' ACLs"
        Invoke-HushIcacls @($privateDir, '/inheritance:r', '/grant:r',
            '*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-544:(OI)(CI)F', '/T', '/C') "secure private directory '$privateDir'"
    }

    # Files directly under the root (config, selections, preferences, runtime state, and
    # journal) must not retain a permissive inherited ACL from the old installer.
    foreach ($file in @(Get-ChildItem -LiteralPath $Root -File -Force -ErrorAction SilentlyContinue)) {
        Invoke-HushIcacls @($file.FullName, '/inheritance:r', '/grant:r',
            '*S-1-5-18:F', '*S-1-5-32-544:F') "secure root file '$($file.Name)'"
    }
}

function Protect-HushConfigFile {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$ConfigPath
    )
    $expected = [IO.Path]::GetFullPath((Join-Path $Root 'config.json'))
    if (-not ([IO.Path]::GetFullPath($ConfigPath)).Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to secure unexpected config path '$ConfigPath'."
    }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Config file not found: $ConfigPath" }
    Invoke-HushIcacls @($ConfigPath, '/inheritance:r', '/grant:r',
        '*S-1-5-18:F',
        '*S-1-5-32-544:F',
        '*S-1-5-19:R') 'secure configuration file'
}
