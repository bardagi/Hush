#Requires -Version 5.1
<#
    Hush.Common.ps1
    Shared library for Hush: paths, logging, JSON I/O, signature/hash verification,
    schema validation, hard-coded guardrails, action helpers, autostart backup/restore,
    and the snooze / quiet-hours gate.

    Dot-source this file; it defines functions only and performs no actions on load.
    Works under LOCAL SERVICE (fetcher), SYSTEM (enforcer) and elevated admin (GUI).
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
        Root        = $root
        Bin         = Join-Path $root 'bin'
        Cache       = Join-Path $root 'cache'
        Logs        = Join-Path $root 'logs'
        Backups     = Join-Path $root 'backups'
        Config      = Join-Path $root 'config.json'
        Enabled     = Join-Path $root 'enabled.json'
        Exclusions  = Join-Path $root 'exclusions.json'
        State       = Join-Path $root 'state.json'
        LogFile     = Join-Path (Join-Path $root 'logs') 'hush.log'
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
        [ValidateSet('Info','Warning','Error')][string]$Level = 'Info',
        [string]$Component = 'Hush'
    )
    $paths = Get-HushPaths
    $line  = '{0} [{1}] [{2}] {3}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Component, $Message

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
        'Error'   { Write-Host $line -ForegroundColor Red }
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        default   { Write-Host $line }
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
    $tmp  = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    Set-Content -Path $tmp -Value $json -Encoding UTF8
    Move-Item -Path $tmp -Destination $Path -Force   # rename = atomic on same volume
}

function Get-HushConfig { Read-HushJson -Path (Get-HushPaths).Config }

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
    if ($Value -is [datetime])       { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    return [datetimeoffset]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind).UtcDateTime
}

# ----------------------------------------------------------------------------- crypto

function Get-HushSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-HushFileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    Get-HushSha256Hex -Bytes ([System.IO.File]::ReadAllBytes($Path))
}

function Test-HushSignature {
    <# Verify an RSA PKCS#1 v1.5 / SHA-256 signature against a pinned public key (XML). #>
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][byte[]]$Signature,
        [Parameter(Mandatory)][string]$PublicKeyXml
    )
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    try {
        $rsa.FromXmlString($PublicKeyXml)
        return $rsa.VerifyData($Data, 'SHA256', $Signature)
    } catch {
        Write-HushLog -Level Error -Component 'Verify' -Message "Signature verification threw: $($_.Exception.Message)"
        return $false
    } finally { $rsa.Dispose() }
}

# ----------------------------------------------------------------------------- schema

$script:HushAllowedActions = @{
    killProcess     = @('match')
    stopService     = @('name')
    removeAutostart = @('kind','name')
    setRegistryValue= @('hive','path','name','valueType','data')
}
$script:HushAutostartKinds = @('registryRun','startupFolder','scheduledTask')
$script:HushRegHives       = @('HKLM','HKCU')
$script:HushRegValueTypes  = @('String','ExpandString','DWord','QWord','MultiString','Binary')

function Test-HushDefinition {
    <# Validate a parsed definition object. Returns @{ Ok = [bool]; Errors = @() } #>
    param([Parameter(Mandatory)]$Def)
    $errors = New-Object System.Collections.Generic.List[string]

    function Has($obj, $name) { Test-HushProp $obj $name }

    if (-not (Has $Def 'schemaVersion'))     { $errors.Add('missing schemaVersion') }
    elseif ($Def.schemaVersion -ne 1)        { $errors.Add("unsupported schemaVersion '$($Def.schemaVersion)'") }
    foreach ($f in @('name','definitionVersion','updateDate','actions')) {
        if (-not (Has $Def $f)) { $errors.Add("missing $f") }
    }
    if ((Has $Def 'definitionVersion') -and -not ($Def.definitionVersion -is [int] -or $Def.definitionVersion -is [long])) {
        $errors.Add('definitionVersion must be an integer')
    }
    if (Has $Def 'actions') {
        if ($Def.actions -isnot [System.Array]) { $errors.Add('actions must be an array') }
        else {
            $i = -1
            foreach ($a in $Def.actions) {
                $i++
                if (-not (Has $a 'type')) { $errors.Add("action[$i] missing type"); continue }
                if (-not $script:HushAllowedActions.ContainsKey($a.type)) {
                    $errors.Add("action[$i] type '$($a.type)' not allowed"); continue
                }
                foreach ($req in $script:HushAllowedActions[$a.type]) {
                    if (-not (Has $a $req)) { $errors.Add("action[$i] ($($a.type)) missing $req") }
                }
                switch ($a.type) {
                    'killProcess' {
                        if ((Has $a 'match') -and -not (Has $a.match 'name')) { $errors.Add("action[$i] match.name required") }
                    }
                    'removeAutostart' {
                        if ((Has $a 'kind') -and $script:HushAutostartKinds -notcontains $a.kind) {
                            $errors.Add("action[$i] kind '$($a.kind)' invalid")
                        }
                    }
                    'setRegistryValue' {
                        if ((Has $a 'hive') -and $script:HushRegHives -notcontains $a.hive) { $errors.Add("action[$i] hive invalid") }
                        if ((Has $a 'valueType') -and $script:HushRegValueTypes -notcontains $a.valueType) { $errors.Add("action[$i] valueType invalid") }
                    }
                }
            }
        }
    }
    [pscustomobject]@{ Ok = ($errors.Count -eq 0); Errors = @($errors) }
}

# ----------------------------------------------------------------------------- guardrails

# Non-overridable. Even a signed definition cannot touch these.
$script:HushProtectedProcesses = @(
    'system','registry','idle','smss','csrss','wininit','winlogon','services',
    'lsass','lsaiso','fontdrvhost','dwm','svchost','spoolsv','memcompression'
)
$script:HushProtectedServicesFloor = @('WinDefend','Sense','SecurityHealthService','WdNisSvc')

function Test-HushProtectedProcess {
    param([Parameter(Mandatory)][string]$Name)
    $base = ($Name -replace '\.exe$','').Trim().ToLowerInvariant()
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

# ----------------------------------------------------------------------------- exclusions

function Test-HushExcluded {
    param(
        [Parameter(Mandatory)][ValidateSet('process','service','autostart')][string]$Type,
        [Parameter(Mandatory)][string]$Name,
        $Exclusions
    )
    if (-not $Exclusions) { return $false }
    $prop = @{ process = 'processes'; service = 'services'; autostart = 'autostarts' }[$Type]
    if (-not (Test-HushProp $Exclusions $prop)) { return $false }
    foreach ($pat in @($Exclusions.$prop)) {
        if ($pat -and ($Name -like $pat)) { return $true }
    }
    return $false
}

# ----------------------------------------------------------------------------- snooze / quiet hours

function Test-HushSnoozed {
    <# Returns @{ Snoozed = [bool]; Reason = [string] } based on state.json. #>
    param($State)
    if (-not $State) { return [pscustomobject]@{ Snoozed = $false; Reason = $null } }

    if ((Test-HushProp $State 'snoozeUntil') -and $State.snoozeUntil) {
        try {
            $until = ConvertTo-HushUtc $State.snoozeUntil
            if ([datetime]::UtcNow -lt $until) {
                return [pscustomobject]@{ Snoozed = $true; Reason = "snoozed until $($until.ToLocalTime())" }
            }
        } catch { }
    }

    if ((Test-HushProp $State 'quietHours') -and $State.quietHours) {
        $now = (Get-Date).TimeOfDay
        foreach ($w in @($State.quietHours)) {
            if (-not ((Test-HushProp $w 'start') -and (Test-HushProp $w 'end'))) { continue }
            try {
                $s = [timespan]::Parse($w.start); $e = [timespan]::Parse($w.end)
                $inWindow = if ($s -le $e) { ($now -ge $s -and $now -lt $e) } else { ($now -ge $s -or $now -lt $e) } # wrap past midnight
                if ($inWindow) { return [pscustomobject]@{ Snoozed = $true; Reason = "quiet hours $($w.start)-$($w.end)" } }
            } catch { }
        }
    }
    return [pscustomobject]@{ Snoozed = $false; Reason = $null }
}

# ----------------------------------------------------------------------------- result helper

function New-HushResult {
    param([string]$Type, [string]$Target, [string]$Status, [string]$Detail)
    [pscustomobject]@{ Type = $Type; Target = $Target; Status = $Status; Detail = $Detail }
}

# ----------------------------------------------------------------------------- autostart backup

function Backup-HushAutostart {
    <# Persist enough info to recreate a removed autostart entry. #>
    param([Parameter(Mandatory)][hashtable]$Entry)
    $paths = Get-HushPaths
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dir   = Join-Path $paths.Backups $stamp
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $file  = Join-Path $dir ("{0}.json" -f [guid]::NewGuid().ToString('N'))
    $Entry['backedUpUtc'] = [datetime]::UtcNow.ToString('o')
    Write-HushJsonAtomic -Path $file -Object ([pscustomobject]$Entry)
    return $file
}

# =============================================================================
#  ACTION HELPERS  — each returns one or more New-HushResult objects.
#  $Context = @{ Preview = [bool]; Exclusions = <obj>; Config = <obj> }
# =============================================================================

function Get-HushDescendantPids {
    param([Parameter(Mandatory)][int]$ParentId, [Parameter(Mandatory)]$AllProcs)
    $kids = $AllProcs | Where-Object { $_.ParentProcessId -eq $ParentId }
    foreach ($k in $kids) {
        $k.ProcessId
        Get-HushDescendantPids -ParentId $k.ProcessId -AllProcs $AllProcs
    }
}

function Invoke-HushKillProcess {
    param([Parameter(Mandatory)]$Action, [Parameter(Mandatory)]$Context)
    $name = [string]$Action.match.name
    $results = @()

    if (Test-HushProtectedProcess -Name $name) {
        Write-HushLog -Level Warning -Component 'kill' -Message "BLOCKED protected process '$name' (guardrail)"
        return ,(New-HushResult 'killProcess' $name 'Blocked' 'protected by guardrail')
    }
    if (Test-HushExcluded -Type process -Name $name -Exclusions $Context.Exclusions) {
        Write-HushLog -Level Info -Component 'kill' -Message "Excluded '$name' by local policy"
        return ,(New-HushResult 'killProcess' $name 'Excluded' 'local exclusion')
    }

    $safeName = $name.Replace("'","''")
    $procs = @(Get-CimInstance Win32_Process -Filter "Name = '$safeName'" -ErrorAction SilentlyContinue)

    # Optional narrowing by publisher company or executable path (@() keeps it an array).
    if ((Test-HushProp $Action.match 'company') -and $Action.match.company) {
        $procs = @($procs | Where-Object {
            $p = $_.ExecutablePath
            $p -and (Test-Path $p) -and ((Get-Item $p).VersionInfo.CompanyName -like $Action.match.company)
        })
    }
    if ((Test-HushProp $Action.match 'path') -and $Action.match.path) {
        $procs = @($procs | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -like $Action.match.path) })
    }

    if ($procs.Count -eq 0) {
        return ,(New-HushResult 'killProcess' $name 'Skipped' 'no matching process running')
    }

    $killTree = ((Test-HushProp $Action 'killTree') -and $Action.killTree)
    $allProcs = if ($killTree) { @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) } else { @() }

    foreach ($proc in $procs) {
        $pids = @($proc.ProcessId)
        if ($killTree) { $pids += @(Get-HushDescendantPids -ParentId $proc.ProcessId -AllProcs $allProcs) }
        $pids = @($pids | Select-Object -Unique)
        foreach ($procId in $pids) {
            $liveProc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($liveProc -and (Test-HushProtectedProcess -Name $liveProc.ProcessName)) { continue }
            if ($Context.Preview) {
                $results += New-HushResult 'killProcess' "$name (pid $procId)" 'Preview' 'would stop'
            } else {
                try {
                    Stop-Process -Id $procId -Force -ErrorAction Stop
                    $results += New-HushResult 'killProcess' "$name (pid $procId)" 'Applied' 'stopped'
                } catch {
                    $results += New-HushResult 'killProcess' "$name (pid $procId)" 'Error' $_.Exception.Message
                }
            }
        }
    }
    return $results
}

function Invoke-HushStopService {
    param([Parameter(Mandatory)]$Action, [Parameter(Mandatory)]$Context)
    $name = [string]$Action.name

    if (Test-HushProtectedService -Name $name -Config $Context.Config) {
        Write-HushLog -Level Warning -Component 'service' -Message "BLOCKED protected service '$name' (guardrail)"
        return ,(New-HushResult 'stopService' $name 'Blocked' 'protected by guardrail')
    }
    if (Test-HushExcluded -Type service -Name $name -Exclusions $Context.Exclusions) {
        return ,(New-HushResult 'stopService' $name 'Excluded' 'local exclusion')
    }

    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { return ,(New-HushResult 'stopService' $name 'Skipped' 'service not present') }

    $disable = ((Test-HushProp $Action 'disable') -and $Action.disable)
    if ($Context.Preview) {
        $what = if ($disable) { 'would stop and disable' } else { 'would stop' }
        return ,(New-HushResult 'stopService' $name 'Preview' $what)
    }
    try {
        if ($svc.Status -ne 'Stopped') { Stop-Service -Name $name -Force -ErrorAction Stop }
        if ($disable) { Set-Service -Name $name -StartupType Disabled -ErrorAction Stop }
        $detail = if ($disable) { 'stopped and disabled' } else { 'stopped' }
        return ,(New-HushResult 'stopService' $name 'Applied' $detail)
    } catch {
        return ,(New-HushResult 'stopService' $name 'Error' $_.Exception.Message)
    }
}

function Get-HushRunKeyPaths {
    param([string]$Scope = 'allUsers')
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    if ($Scope -ne 'machine') {
        try {
            foreach ($sid in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue).PSChildName) {
                if ($sid -match '^S-1-5-21' -and $sid -notlike '*_Classes') {
                    $paths += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
                    $paths += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                }
            }
        } catch { }
    }
    return $paths
}

function Get-HushStartupFolders {
    param([string]$Scope = 'allUsers')
    $folders = @((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'))
    if ($Scope -ne 'machine') {
        try {
            Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
                if (Test-Path $p) { $folders += $p }
            }
        } catch { }
    }
    return $folders
}

function Invoke-HushRemoveAutostart {
    param([Parameter(Mandatory)]$Action, [Parameter(Mandatory)]$Context)
    $pattern = [string]$Action.name
    $scope   = if (Test-HushProp $Action 'scope') { [string]$Action.scope } else { 'allUsers' }
    $results = @()

    if (Test-HushExcluded -Type autostart -Name $pattern -Exclusions $Context.Exclusions) {
        return ,(New-HushResult 'removeAutostart' $pattern 'Excluded' 'local exclusion')
    }

    switch ($Action.kind) {
        'registryRun' {
            foreach ($keyPath in (Get-HushRunKeyPaths -Scope $scope)) {
                $key = Get-Item -LiteralPath $keyPath -ErrorAction SilentlyContinue
                if (-not $key) { continue }
                foreach ($valName in @($key.GetValueNames() | Where-Object { $_ -like $pattern })) {
                    if ($Context.Preview) {
                        $results += New-HushResult 'removeAutostart' "$keyPath\$valName" 'Preview' 'would remove Run value'
                        continue
                    }
                    try {
                        Backup-HushAutostart @{ kind='registryRun'; keyPath=$keyPath; valueName=$valName;
                            valueKind=$key.GetValueKind($valName).ToString();
                            valueData=$key.GetValue($valName, $null, 'DoNotExpandEnvironmentNames') } | Out-Null
                        Remove-ItemProperty -LiteralPath $keyPath -Name $valName -Force -ErrorAction Stop
                        $results += New-HushResult 'removeAutostart' "$keyPath\$valName" 'Applied' 'Run value removed (backed up)'
                    } catch {
                        $results += New-HushResult 'removeAutostart' "$keyPath\$valName" 'Error' $_.Exception.Message
                    }
                }
            }
        }
        'startupFolder' {
            foreach ($folder in (Get-HushStartupFolders -Scope $scope)) {
                foreach ($item in @(Get-ChildItem -LiteralPath $folder -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $pattern })) {
                    if ($Context.Preview) {
                        $results += New-HushResult 'removeAutostart' $item.FullName 'Preview' 'would remove Startup item'
                        continue
                    }
                    try {
                        $backupDir = Split-Path -Parent (Backup-HushAutostart @{ kind='startupFolder'; originalPath=$item.FullName; fileName=$item.Name })
                        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $backupDir $item.Name) -Force
                        Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                        $results += New-HushResult 'removeAutostart' $item.FullName 'Applied' 'Startup item removed (backed up)'
                    } catch {
                        $results += New-HushResult 'removeAutostart' $item.FullName 'Error' $_.Exception.Message
                    }
                }
            }
        }
        'scheduledTask' {
            $disableOnly = ((Test-HushProp $Action 'disableOnly') -and $Action.disableOnly)
            foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like $pattern })) {
                $full = "$($task.TaskPath)$($task.TaskName)"
                if ($Context.Preview) {
                    $verb = if ($disableOnly) { 'would disable' } else { 'would unregister' }
                    $results += New-HushResult 'removeAutostart' $full 'Preview' "$verb scheduled task"
                    continue
                }
                try {
                    $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                    Backup-HushAutostart @{ kind='scheduledTask'; taskName=$task.TaskName; taskPath=$task.TaskPath;
                        disableOnly=$disableOnly; xml="$xml" } | Out-Null
                    if ($disableOnly) {
                        Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                        $results += New-HushResult 'removeAutostart' $full 'Applied' 'scheduled task disabled (backed up)'
                    } else {
                        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                        $results += New-HushResult 'removeAutostart' $full 'Applied' 'scheduled task removed (backed up)'
                    }
                } catch {
                    $results += New-HushResult 'removeAutostart' $full 'Error' $_.Exception.Message
                }
            }
        }
    }
    if ($results.Count -eq 0) { $results += New-HushResult 'removeAutostart' $pattern 'Skipped' 'no matching autostart entry' }
    return $results
}

function Invoke-HushSetRegistryValue {
    param([Parameter(Mandatory)]$Action, [Parameter(Mandatory)]$Context)
    $root = if ($Action.hive -eq 'HKLM') { 'HKLM:' } else { 'HKCU:' }
    $full = Join-Path $root $Action.path
    $target = "$full\$($Action.name)"

    if ($Context.Preview) {
        return ,(New-HushResult 'setRegistryValue' $target 'Preview' "would set = $($Action.data)")
    }
    try {
        if (-not (Test-Path $full)) { New-Item -Path $full -Force | Out-Null }
        New-ItemProperty -Path $full -Name $Action.name -PropertyType $Action.valueType -Value $Action.data -Force | Out-Null
        return ,(New-HushResult 'setRegistryValue' $target 'Applied' "set = $($Action.data)")
    } catch {
        return ,(New-HushResult 'setRegistryValue' $target 'Error' $_.Exception.Message)
    }
}

function Invoke-HushAction {
    param([Parameter(Mandatory)]$Action, [Parameter(Mandatory)]$Context)
    switch ($Action.type) {
        'killProcess'      { Invoke-HushKillProcess     -Action $Action -Context $Context }
        'stopService'      { Invoke-HushStopService     -Action $Action -Context $Context }
        'removeAutostart'  { Invoke-HushRemoveAutostart -Action $Action -Context $Context }
        'setRegistryValue' { Invoke-HushSetRegistryValue -Action $Action -Context $Context }
        default            { New-HushResult $Action.type '' 'Error' 'unknown action type' }
    }
}

# ----------------------------------------------------------------------------- restore

function Restore-HushBackup {
    <# Recreate an autostart entry from a backup JSON file produced by Backup-HushAutostart. #>
    param([Parameter(Mandatory)][string]$BackupFile)
    $b = Read-HushJson -Path $BackupFile
    if (-not $b) { throw "Backup not found: $BackupFile" }
    switch ($b.kind) {
        'registryRun' {
            if (-not (Test-Path $b.keyPath)) { New-Item -Path $b.keyPath -Force | Out-Null }
            Set-ItemProperty -LiteralPath $b.keyPath -Name $b.valueName -Value $b.valueData -Type $b.valueKind -Force
        }
        'startupFolder' {
            $src = Join-Path (Split-Path -Parent $BackupFile) $b.fileName
            Copy-Item -LiteralPath $src -Destination $b.originalPath -Force
        }
        'scheduledTask' {
            Register-ScheduledTask -Xml $b.xml -TaskName $b.taskName -TaskPath $b.taskPath -Force | Out-Null
        }
        default { throw "Unknown backup kind: $($b.kind)" }
    }
    Write-HushLog -Component 'restore' -Message "Restored $($b.kind) from $BackupFile"
}
