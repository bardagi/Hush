#Requires -Version 5.1
<#
    Hush.TargetPolicy.ps1
    Input validation and non-overridable target guardrails.

    This file is dot-sourced by the Hush compatibility loaders.
#>

# ----------------------------------------------------------------------------- input validation
#
#  Every value that crosses from a (signed) JSON definition into a privileged operation is
#  treated as hostile and canonicalised + allowlisted here BEFORE it is used. The goal: no
#  mistyped / case-variant / whitespace / Unicode look-alike / wildcard / escape / path-
#  traversal value can slip past a guardrail. Validation is the single chokepoint used by
#  both the fetcher and the enforcer (Test-HushDefinition), and the action helpers re-check
#  the resolved targets again at run time (defence in depth).

function Test-HushHasWildcard {
    # PowerShell -like / provider glob metacharacters. Reject wherever a match must be exact.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return ($Value -match '[*?\[\]]')
}

function Test-HushHasUnsafeChar {
    # Control chars AND invisible/ambiguous Unicode (zero-width, format, surrogate, private
    # use, line/paragraph separators) — anything that lets a name hide or masquerade.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $bad = @(
        [System.Globalization.UnicodeCategory]::Format,
        [System.Globalization.UnicodeCategory]::Surrogate,
        [System.Globalization.UnicodeCategory]::OtherNotAssigned,
        [System.Globalization.UnicodeCategory]::LineSeparator,
        [System.Globalization.UnicodeCategory]::ParagraphSeparator,
        [System.Globalization.UnicodeCategory]::PrivateUse
    )
    foreach ($ch in $Value.ToCharArray()) {
        if ([char]::IsControl($ch)) { return $true }
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -in $bad) { return $true }
    }
    return $false
}

function Test-HushSafeString {
    <#
        A value safe to use as an exact identifier (process / service / registry value name).
        Rejects: non-strings, empty, leading/trailing whitespace (dodges trimless compares),
        control / non-printable chars (zero-width, NUL, newlines) and — unless -AllowWildcards
        — glob metacharacters. -Pattern is an extra whitelist the value must fully match.
    #>
    param($Value, [switch]$AllowWildcards, [string]$Pattern)
    if ($Value -isnot [string]) { return $false }
    if ($Value.Length -eq 0) { return $false }
    if ($Value -ne $Value.Trim()) { return $false }
    if (Test-HushHasUnsafeChar $Value) { return $false }
    if (-not $AllowWildcards -and (Test-HushHasWildcard $Value)) { return $false }
    if ($Pattern -and ($Value -notmatch $Pattern)) { return $false }
    return $true
}

# Exact-match identifiers (no wildcards). Spaces allowed internally ("Adobe Desktop Service.exe").
function Test-HushSafeProcessName { param($Value) Test-HushSafeString -Value $Value -Pattern '^[A-Za-z0-9 ._+()\-]+$' }
function Test-HushSafeServiceName { param($Value) Test-HushSafeString -Value $Value -Pattern '^[A-Za-z0-9 ._\-]+$' }
function Test-HushSafeDefinitionName { param($Value) Test-HushSafeString -Value $Value -Pattern '^[A-Za-z0-9._\-]+$' }
function Test-HushSafeActionId { param($Value) Test-HushSafeString -Value $Value -Pattern '^[A-Za-z0-9._\-]+$' }
function Test-HushSafeCacheFileName {
    # Manifest 'file' — a bare *.json filename, never a path (blocks ..\ traversal in Join-Path).
    param($Value)
    return (Test-HushSafeString -Value $Value -Pattern '^[A-Za-z0-9._\-]+\.json$') -and ($Value -notmatch '\.\.')
}
function Test-HushSha256Hex { param($Value) ($Value -is [string]) -and ($Value -match '^[0-9a-fA-F]{64}$') }

function Test-HushSafeAutostartPattern {
    # removeAutostart 'name' is intentionally a wildcard pattern, but never a path and never
    # so broad it would sweep everything.
    param($Value)
    if ($Value -isnot [string] -or $Value.Length -eq 0) { return $false }
    if ($Value -ne $Value.Trim()) { return $false }
    if (Test-HushHasUnsafeChar $Value) { return $false }
    if ($Value -match '[\\/:]' -or $Value -match '\.\.') { return $false }   # no separators / traversal
    if ($Value.Trim('*', '?', ' ') -eq '') { return $false }                  # reject bare '*' / '?' (too broad)
    if (($Value -replace '[*?]', '').Length -lt 3) { return $false }
    return ($Value -match '^[A-Za-z0-9 ._+()\-*?]+$')
}

function Test-HushSafeBackupFileName {
    # A restored Startup item filename: exact filename only, never a path or wildcard.
    param($Value)
    return (Test-HushSafeString -Value $Value -Pattern '^[A-Za-z0-9 ._+()\-]+$') -and ($Value -notmatch '[\\/:]') -and ($Value -notmatch '\.\.')
}

function Test-HushQuietHourValue {
    # GUI/enforcer quiet-hours format: strict 24h HH:mm.
    param($Value)
    return ($Value -is [string]) -and ($Value -match '^([01][0-9]|2[0-3]):[0-5][0-9]$')
}

function Test-HushSafeRegistryPath {
    # Sub-key path under a hive: backslash-separated, no wildcards, no drive/hive injection,
    # no '.'/'..' segments, safe charset per segment.
    param($Value)
    if ($Value -isnot [string] -or $Value.Length -eq 0) { return $false }
    if ($Value -ne $Value.Trim()) { return $false }
    if (Test-HushHasUnsafeChar $Value) { return $false }
    if ((Test-HushHasWildcard $Value) -or ($Value -match '[:/]')) { return $false }
    foreach ($seg in ($Value.Trim('\') -split '\\')) {
        if ($seg.Length -eq 0 -or $seg -eq '.' -or $seg -eq '..') { return $false }
        if ($seg -ne $seg.Trim()) { return $false }
        if ($seg -notmatch '^[A-Za-z0-9 ._+()\-]+$') { return $false }
    }
    return $true
}

function Test-HushBackupPathUnderRoot {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) { return $false }
    if ((Test-HushHasUnsafeChar $Path) -or (Test-HushHasUnsafeChar $Root)) { return $false }
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
        return $full.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith("$rootFull\", [System.StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Test-HushRunKeyBackupPath {
    param($Value)
    if ($Value -isnot [string] -or $Value.Length -eq 0) { return $false }
    if (Test-HushHasUnsafeChar $Value) { return $false }
    $machine = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    if ($machine -contains $Value) { return $true }
    return ($Value -match '^Registry::HKEY_USERS\\S-1-5-21-[0-9-]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?$')
}

function Test-HushStartupBackupPath {
    param($Value)
    if ($Value -isnot [string] -or $Value.Length -eq 0) { return $false }
    if ((Test-HushHasUnsafeChar $Value) -or (Test-HushHasWildcard $Value)) { return $false }
    $leaf = Split-Path -Leaf $Value
    if (-not (Test-HushSafeBackupFileName $leaf)) { return $false }
    $parent = Split-Path -Parent $Value
    foreach ($folder in (Get-HushStartupFolders -Scope 'allUsers')) {
        try {
            if ([System.IO.Path]::GetFullPath($parent).TrimEnd('\', '/').Equals(
                    [System.IO.Path]::GetFullPath($folder).TrimEnd('\', '/'),
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        } catch { }
    }
    return $false
}

function Test-HushScheduledTaskPath {
    param($Value)
    if ($Value -isnot [string] -or $Value.Length -eq 0) { return $false }
    if ($Value -ne $Value.Trim()) { return $false }
    if ((Test-HushHasUnsafeChar $Value) -or (Test-HushHasWildcard $Value)) { return $false }
    if ($Value -match '[:/]' -or ($Value -ne '\' -and $Value -notmatch '^\\(?:[^\\]+\\)+$')) { return $false }
    foreach ($seg in ($Value.Trim('\') -split '\\')) {
        if ($seg.Length -eq 0) { continue }
        if ($seg -eq '.' -or $seg -eq '..') { return $false }
        if ($seg -notmatch '^[A-Za-z0-9 ._+()\-]+$') { return $false }
    }
    return $true
}

function Test-HushBackup {
    <# Validate a backup document before restore. Returns @{ Ok = [bool]; Errors = @() } #>
    param([Parameter(Mandatory)]$Backup, [string]$BackupFile)
    $errors = New-Object System.Collections.Generic.List[string]

    function Has($obj, $name) { Test-HushProp $obj $name }

    if ($BackupFile -and -not (Test-HushBackupPathUnderRoot -Path $BackupFile -Root (Get-HushPaths).Backups)) {
        $errors.Add('backup file is outside the Hush backup root')
    }
    if (-not (Has $Backup 'kind')) {
        $errors.Add('missing kind')
    } else {
        switch ($Backup.kind) {
            'registryRun' {
                foreach ($f in @('keyPath', 'valueName', 'valueKind', 'valueData')) {
                    if (-not (Has $Backup $f)) { $errors.Add("missing $f") }
                }
                if ((Has $Backup 'keyPath') -and -not (Test-HushRunKeyBackupPath $Backup.keyPath)) { $errors.Add('registry Run key path invalid') }
                if ((Has $Backup 'valueName') -and -not (Test-HushSafeString $Backup.valueName)) { $errors.Add('registry value name invalid') }
                if ((Has $Backup 'valueKind') -and $script:HushRegValueTypes -notcontains $Backup.valueKind) { $errors.Add('registry value kind invalid') }
                if ((Has $Backup 'valueKind') -and (Has $Backup 'valueData') -and
                    ($script:HushRegValueTypes -contains $Backup.valueKind) -and
                    -not (Test-HushRegistryData -ValueType $Backup.valueKind -Data $Backup.valueData)) {
                    $errors.Add('registry value data does not match value kind')
                }
            }
            'startupFolder' {
                foreach ($f in @('originalPath', 'fileName')) {
                    if (-not (Has $Backup $f)) { $errors.Add("missing $f") }
                }
                if ((Has $Backup 'fileName') -and -not (Test-HushSafeBackupFileName $Backup.fileName)) { $errors.Add('startup filename invalid') }
                if ((Has $Backup 'originalPath') -and -not (Test-HushStartupBackupPath $Backup.originalPath)) { $errors.Add('startup original path invalid') }
                if ((Has $Backup 'originalPath') -and (Has $Backup 'fileName') -and
                    ((Split-Path -Leaf $Backup.originalPath) -ne $Backup.fileName)) {
                    $errors.Add('startup filename does not match original path')
                }
            }
            'scheduledTask' {
                foreach ($f in @('taskName', 'taskPath', 'xml')) {
                    if (-not (Has $Backup $f)) { $errors.Add("missing $f") }
                }
                if ((Has $Backup 'taskName') -and -not (Test-HushSafeString -Value $Backup.taskName -Pattern '^[A-Za-z0-9 ._+()\-]+$')) { $errors.Add('task name invalid') }
                if ((Has $Backup 'taskPath') -and -not (Test-HushScheduledTaskPath $Backup.taskPath)) { $errors.Add('task path invalid') }
                if (Has $Backup 'xml') {
                    if ($Backup.xml -isnot [string] -or [string]::IsNullOrWhiteSpace($Backup.xml)) {
                        $errors.Add('task xml invalid')
                    } else {
                        try {
                            [xml]$taskXml = $Backup.xml
                            if ($taskXml.DocumentElement.LocalName -ne 'Task') { $errors.Add('task xml root invalid') }
                        } catch { $errors.Add('task xml invalid') }
                    }
                }
            }
            default { $errors.Add("unknown backup kind '$($Backup.kind)'") }
        }
    }

    [pscustomobject]@{ Ok = ($errors.Count -eq 0); Errors = @($errors) }
}

function Test-HushRegistryData {
    # The 'data' payload's type must match the declared valueType (no type confusion).
    param([Parameter(Mandatory)][string]$ValueType, $Data)
    switch ($ValueType) {
        { $_ -in 'DWord', 'QWord' } { return ($Data -is [int] -or $Data -is [long]) }
        { $_ -in 'String', 'ExpandString' } { return ($Data -is [string]) }
        'MultiString' { return (($Data -is [System.Array]) -and @($Data | Where-Object { $_ -isnot [string] }).Count -eq 0) }
        'Binary' {
            if ($Data -is [string]) { return (($Data.Length % 2 -eq 0) -and ($Data -match '^[0-9a-fA-F]*$')) }
            if ($Data -is [System.Array]) { return (@($Data | Where-Object { ($_ -isnot [int]) -or ($_ -lt 0) -or ($_ -gt 255) }).Count -eq 0) }
            return $false
        }
        default { return $false }
    }
}

function ConvertTo-HushRegistryData {
    # Coerce validated 'data' into the concrete CLR type the registry provider expects.
    param([Parameter(Mandatory)][string]$ValueType, $Data)
    switch ($ValueType) {
        'Binary' {
            if ($Data -is [string]) {
                $bytes = New-Object byte[] ($Data.Length / 2)
                for ($k = 0; $k -lt $bytes.Length; $k++) { $bytes[$k] = [Convert]::ToByte($Data.Substring($k * 2, 2), 16) }
                return , $bytes
            }
            return , ([byte[]]@($Data))
        }
        'MultiString' { return , ([string[]]@($Data)) }
        default { return $Data }
    }
}

# ----------------------------------------------------------------------------- guardrails

# Non-overridable. Even a signed definition cannot touch these.
$script:HushProtectedProcesses = @(
    'system', 'registry', 'idle', 'smss', 'csrss', 'wininit', 'winlogon', 'services',
    'lsass', 'lsaiso', 'fontdrvhost', 'dwm', 'svchost', 'spoolsv', 'memcompression'
)
$script:HushProtectedServicesFloor = @('WinDefend', 'Sense', 'SecurityHealthService', 'WdNisSvc')
$script:HushProtectedScheduledTasks = @('Hush-Fetch', 'Hush-Enforce')

function Test-HushProtectedProcess {
    param([Parameter(Mandatory)][string]$Name)
    $base = ($Name -replace '\.exe$', '').Trim().ToLowerInvariant()
    return ($script:HushProtectedProcesses -contains $base)
}

function Test-HushProtectedService {
    param([Parameter(Mandatory)][string]$Name, $Config)
    $floor = @($script:HushProtectedServicesFloor)
    if ($Config -and (Test-HushProp $Config 'protectedServices') -and $Config.protectedServices) {
        $floor += @($Config.protectedServices)
    }
    $match = $floor | Where-Object { $_ -and ($_.ToLowerInvariant() -eq $Name.ToLowerInvariant()) }
    return [bool]$match
}

function Test-HushProtectedScheduledTask {
    param([Parameter(Mandatory)][string]$Name)
    return @($script:HushProtectedScheduledTasks | Where-Object { $_.Equals($Name, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
}

# --- registry write guardrail (setRegistryValue only) -------------------------
#
# Posture: a hard DENYLIST of code-execution / security-disabling keys that ALWAYS wins,
# plus an explicit path/value ALLOWLIST. Anything not on that exact allowlist (and everything
# on the denylist) is refused — even from a signed definition. Disabling autoruns is a
# separate, inherently-safe action (removeAutostart), so locking setRegistryValue down here
# does not reduce that capability.
$script:HushDeniedRegistryFragments = @(
    'image file execution options',          # IFEO Debugger / GlobalFlag -> code execution
    '\\currentversion\\run',                 # Run / RunOnce / RunServices / RunOnceEx
    '\\policies\\explorer\\run',             # policy-based autorun
    '\\winlogon',                            # Shell / Userinit / Notify -> code execution
    'userinit',
    'appinit_dlls',
    '\\active setup\\installed components',
    '\\system\\scripts',                     # logon/logoff/startup/shutdown policy scripts
    '\\safeboot',
    'windows defender',                      # disabling AV
    'smartscreen',
    '\\policies\\system',                    # EnableLUA / DisableTaskMgr / etc.
    '\\services\\',                           # service ImagePath / Start tampering
    'appcompatflags'
)
$script:HushAllowedRegistryPrefixes = @('software\policies\google\chrome')
$script:HushAllowedRegistryValues = @{
    'hklm\software\policies\google\chrome' = @('backgroundmodeenabled')
}

function Get-HushNormalizedRegPath {
    param([Parameter(Mandatory)][string]$Hive, [Parameter(Mandatory)][string]$Path)
    $p = (($Path -replace '/', '\').Trim('\') -replace '\\{2,}', '\').ToLowerInvariant()
    return [pscustomobject]@{ Path = $p; Full = ('{0}\{1}' -f $Hive.ToLowerInvariant(), $p) }
}

function Test-HushProtectedRegistryPath {
    <# Hard denylist — non-overridable, wins even over an allowlisted prefix. #>
    param([Parameter(Mandatory)][string]$Hive, [Parameter(Mandatory)][string]$Path)
    $full = (Get-HushNormalizedRegPath -Hive $Hive -Path $Path).Full
    foreach ($frag in $script:HushDeniedRegistryFragments) {
        if ($full -match $frag) { return $true }
    }
    return $false
}

function Test-HushAllowedRegistryPath {
    <# A write is permitted only if NOT denied AND under an explicitly allowlisted product path. #>
    param([Parameter(Mandatory)][string]$Hive, [Parameter(Mandatory)][string]$Path)
    if ($script:HushRegHives -notcontains $Hive) { return $false }
    if (Test-HushProtectedRegistryPath -Hive $Hive -Path $Path) { return $false }
    $norm = (Get-HushNormalizedRegPath -Hive $Hive -Path $Path).Path
    foreach ($prefix in $script:HushAllowedRegistryPrefixes) {
        if ($norm -eq $prefix -or $norm.StartsWith("$prefix\")) { return $true }
    }
    return $false
}

function Test-HushAllowedRegistryValue {
    param([Parameter(Mandatory)][string]$Hive, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-HushAllowedRegistryPath -Hive $Hive -Path $Path)) { return $false }
    $key = (Get-HushNormalizedRegPath -Hive $Hive -Path $Path).Full
    return $script:HushAllowedRegistryValues.ContainsKey($key) -and
    (@($script:HushAllowedRegistryValues[$key]) -contains $Name.ToLowerInvariant())
}

