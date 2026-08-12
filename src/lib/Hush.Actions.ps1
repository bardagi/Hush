#Requires -Version 5.1
<#
    Hush.Actions.ps1
    Privileged action implementations and dispatch.

    This file is dot-sourced by the Hush compatibility loaders.
#>

function Invoke-HushKillProcess {
    param([Parameter(Mandatory)]$Action, [Parameter(Mandatory)]$Context)
    $name = [string]$Action.match.name
    $results = @()

    if (Test-HushProtectedProcess -Name $name) {
        Write-HushLog -Level Warning -Component 'kill' -Message "BLOCKED protected process '$name' (guardrail)"
        return , (New-HushResult 'killProcess' $name 'Blocked' 'protected by guardrail')
    }
    if (Test-HushExcluded -Type process -Name $name -Exclusions $Context.Exclusions) {
        Write-HushLog -Level Info -Component 'kill' -Message "Excluded '$name' by local policy"
        return , (New-HushResult 'killProcess' $name 'Excluded' 'local exclusion')
    }

    $safeName = $name.Replace("'", "''")
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
        return , (New-HushResult 'killProcess' $name 'Skipped' 'no matching process running')
    }

    $killTree = ((Test-HushProp $Action 'killTree') -and $Action.killTree)
    $allProcs = if ($killTree) { @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) } else { @() }

    $backgroundOnly = ((Test-HushProp $Action 'backgroundOnly') -and $Action.backgroundOnly)
    $visibleTreePids = New-Object 'System.Collections.Generic.HashSet[int]'
    $targetTreePids = @{}
    if ($backgroundOnly) {
        if (-not $killTree) { $allProcs = @($procs) }
        $sessionIds = @($procs | ForEach-Object { $_.SessionId } | Select-Object -Unique)
        if (@($sessionIds | Where-Object { $_ -ge 0 }).Count -eq 0) {
            return , (New-HushResult 'killProcess' $name 'Skipped' 'background-only check unavailable; fail-closed')
        }
        $windowProbe = Get-HushVisibleWindowPids -SessionIds $sessionIds
        if (-not $windowProbe.Available) {
            return , (New-HushResult 'killProcess' $name 'Skipped' 'background-only check unavailable; fail-closed')
        }

        foreach ($proc in $procs) {
            $treePids = @($proc.ProcessId)
            if ($killTree) { $treePids += @(Get-HushDescendantPids -ParentId $proc.ProcessId -AllProcs $allProcs) }
            $targetTreePids[[int]$proc.ProcessId] = @($treePids | Select-Object -Unique)
        }

        foreach ($visiblePid in @($windowProbe.VisiblePids)) {
            foreach ($tree in @($targetTreePids.GetEnumerator())) {
                $treePids = @($tree.Value)
                if (@($treePids | Where-Object { [int]$_ -eq [int]$visiblePid }).Count -eq 0) { continue }
                foreach ($treePid in $treePids) { [void]$visibleTreePids.Add([int]$treePid) }
            }
        }
    }

    foreach ($proc in $procs) {
        $pids = if ($backgroundOnly) {
            @($targetTreePids[[int]$proc.ProcessId])
        } else {
            $candidatePids = @($proc.ProcessId)
            if ($killTree) { $candidatePids += @(Get-HushDescendantPids -ParentId $proc.ProcessId -AllProcs $allProcs) }
            @($candidatePids | Select-Object -Unique)
        }

        if ($backgroundOnly -and @($pids | Where-Object { $visibleTreePids.Contains([int]$_) }).Count -gt 0) {
            $results += New-HushResult 'killProcess' "$name (pid $($proc.ProcessId))" 'Skipped' 'visible window in process tree'
            continue
        }

        foreach ($procId in $pids) {
            $liveProc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($liveProc -and (Test-HushProtectedProcess -Name $liveProc.ProcessName)) { continue }
            if ($Context.Preview) {
                $results += New-HushResult 'killProcess' "$name (pid $procId)" 'Preview' 'would stop (non-reversible)'
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
    $disable = ((Test-HushProp $Action 'disable') -and $Action.disable)

    # Resolve to concrete services and act on each by OBJECT — never re-pass a string that a
    # cmdlet could glob (Get/Stop/Set-Service all accept wildcards). The validator already
    # forbids wildcards in the name; re-checking each resolved service is defence in depth so
    # a pattern can never reach WinDefend et al.
    $svcs = @(Get-Service -Name $name -ErrorAction SilentlyContinue)
    if ($svcs.Count -eq 0) { return , (New-HushResult 'stopService' $name 'Skipped' 'service not present') }

    $results = @()
    foreach ($svc in $svcs) {
        $svcName = $svc.Name
        if (Test-HushProtectedService -Name $svcName -Config $Context.Config) {
            Write-HushLog -Level Warning -Component 'service' -Message "BLOCKED protected service '$svcName' (guardrail)"
            $results += New-HushResult 'stopService' $svcName 'Blocked' 'protected by guardrail'
            continue
        }
        if (Test-HushExcluded -Type service -Name $svcName -Exclusions $Context.Exclusions) {
            $results += New-HushResult 'stopService' $svcName 'Excluded' 'local exclusion'
            continue
        }
        if ($Context.Preview) {
            $what = if ($disable) { 'would stop and disable' } else { 'would stop' }
            $results += New-HushResult 'stopService' $svcName 'Preview' $what
            continue
        }
        try {
            if (Test-HushProp $Context 'DefinitionName') {
                Initialize-HushChange -DefinitionName $Context.DefinitionName -ActionId $Action.id -Type service -Action $Action | Out-Null
            }
            if ($svc.Status -ne 'Stopped') { Stop-Service -InputObject $svc -Force -ErrorAction Stop }
            if ($disable) { Set-Service -InputObject $svc -StartupType Disabled -ErrorAction Stop }
            if (Test-HushProp $Context 'DefinitionName') {
                Complete-HushChange -DefinitionName $Context.DefinitionName -ActionId $Action.id
            }
            $detail = if ($disable) { 'stopped and disabled' } else { 'stopped' }
            $results += New-HushResult 'stopService' $svcName 'Applied' $detail
        } catch {
            $results += New-HushResult 'stopService' $svcName 'Error' $_.Exception.Message
        }
    }
    return $results
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
    $scope = if (Test-HushProp $Action 'scope') { [string]$Action.scope } else { 'allUsers' }
    $results = @()

    # Exclusions are tested against each RESOLVED entry name below (not the definition's
    # pattern), so a local "never touch" list can spare an individual Run value / Startup
    # file / scheduled task that the pattern would otherwise sweep.

    switch ($Action.kind) {
        'registryRun' {
            foreach ($keyPath in (Get-HushRunKeyPaths -Scope $scope)) {
                $key = Get-Item -LiteralPath $keyPath -ErrorAction SilentlyContinue
                if (-not $key) { continue }
                foreach ($valName in @($key.GetValueNames() | Where-Object { $_ -like $pattern })) {
                    if (Test-HushExcluded -Type autostart -Name $valName -Exclusions $Context.Exclusions) {
                        $results += New-HushResult 'removeAutostart' "$keyPath\$valName" 'Excluded' 'local exclusion'
                        continue
                    }
                    if ($Context.Preview) {
                        $results += New-HushResult 'removeAutostart' "$keyPath\$valName" 'Preview' 'would remove Run value'
                        continue
                    }
                    try {
                        $backupFile = Backup-HushAutostart @{ kind='registryRun'; keyPath=$keyPath; valueName=$valName;
                            valueKind =$key.GetValueKind($valName).ToString();
                            valueData =$key.GetValue($valName, $null, 'DoNotExpandEnvironmentNames')
                        }
                        Remove-ItemProperty -LiteralPath $keyPath -Name $valName -Force -ErrorAction Stop
                        if (Test-HushProp $Context 'DefinitionName') {
                            Add-HushAutostartChange -DefinitionName $Context.DefinitionName -ActionId $Action.id -Target "$keyPath\$valName" -BackupFile $backupFile
                        }
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
                    if (Test-HushExcluded -Type autostart -Name $item.Name -Exclusions $Context.Exclusions) {
                        $results += New-HushResult 'removeAutostart' $item.FullName 'Excluded' 'local exclusion'
                        continue
                    }
                    if ($Context.Preview) {
                        $results += New-HushResult 'removeAutostart' $item.FullName 'Preview' 'would remove Startup item'
                        continue
                    }
                    try {
                        $backupFile = Backup-HushAutostart @{ kind = 'startupFolder'; originalPath = $item.FullName; fileName = $item.Name }
                        $backupDir = Split-Path -Parent $backupFile
                        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $backupDir $item.Name) -Force
                        Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                        if (Test-HushProp $Context 'DefinitionName') {
                            Add-HushAutostartChange -DefinitionName $Context.DefinitionName -ActionId $Action.id -Target $item.FullName -BackupFile $backupFile
                        }
                        $results += New-HushResult 'removeAutostart' $item.FullName 'Applied' 'Startup item removed (backed up)'
                    } catch {
                        $results += New-HushResult 'removeAutostart' $item.FullName 'Error' $_.Exception.Message
                    }
                }
            }
        }
        'scheduledTask' {
            $disableOnly = ((Test-HushProp $Action 'disableOnly') -and $Action.disableOnly)
            $taskPath = [string]$Action.taskPath
            foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                        $_.TaskName -like $pattern -and $_.TaskPath -eq $taskPath
                    })) {
                $full = "$($task.TaskPath)$($task.TaskName)"
                if (Test-HushProtectedScheduledTask -Name $task.TaskName) {
                    $results += New-HushResult 'removeAutostart' $full 'Blocked' 'protected Hush task'
                    continue
                }
                if (Test-HushExcluded -Type autostart -Name $task.TaskName -Exclusions $Context.Exclusions) {
                    $results += New-HushResult 'removeAutostart' $full 'Excluded' 'local exclusion'
                    continue
                }
                if ($Context.Preview) {
                    $verb = if ($disableOnly) { 'would disable' } else { 'would unregister' }
                    $results += New-HushResult 'removeAutostart' $full 'Preview' "$verb scheduled task"
                    continue
                }
                try {
                    $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                    $backupFile = Backup-HushAutostart @{ kind='scheduledTask'; taskName=$task.TaskName; taskPath=$task.TaskPath;
                        disableOnly=$disableOnly; xml="$xml"
                    }
                    if ($disableOnly) {
                        Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                        $results += New-HushResult 'removeAutostart' $full 'Applied' 'scheduled task disabled (backed up)'
                    } else {
                        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                        $results += New-HushResult 'removeAutostart' $full 'Applied' 'scheduled task removed (backed up)'
                    }
                    if (Test-HushProp $Context 'DefinitionName') {
                        Add-HushAutostartChange -DefinitionName $Context.DefinitionName -ActionId $Action.id -Target $full -BackupFile $backupFile
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

    # Re-check the registry write guardrail at action time (defence in depth vs validation):
    # deny dangerous keys, permit only the Policies allowlist — even for a signed definition.
    if (($script:HushRegHives -notcontains $Action.hive) -or
        -not (Test-HushSafeRegistryPath $Action.path) -or
        -not (Test-HushAllowedRegistryValue -Hive $Action.hive -Path $Action.path -Name $Action.name)) {
        Write-HushLog -Level Warning -Component 'registry' -Message "BLOCKED registry write '$target' (guardrail)"
        return , (New-HushResult 'setRegistryValue' $target 'Blocked' 'protected by guardrail')
    }

    if ($Context.Preview) {
        return , (New-HushResult 'setRegistryValue' $target 'Preview' "would set = $($Action.data)")
    }
    try {
        if (Test-HushProp $Context 'DefinitionName') {
            Initialize-HushChange -DefinitionName $Context.DefinitionName -ActionId $Action.id -Type registry -Action $Action | Out-Null
        }
        $data = ConvertTo-HushRegistryData -ValueType $Action.valueType -Data $Action.data
        if (-not (Test-Path -LiteralPath $full)) { New-Item -Path $full -Force | Out-Null }
        New-ItemProperty -LiteralPath $full -Name $Action.name -PropertyType $Action.valueType -Value $data -Force | Out-Null
        if (Test-HushProp $Context 'DefinitionName') {
            Complete-HushChange -DefinitionName $Context.DefinitionName -ActionId $Action.id
        }
        return , (New-HushResult 'setRegistryValue' $target 'Applied' "set = $($Action.data)")
    } catch {
        return , (New-HushResult 'setRegistryValue' $target 'Error' $_.Exception.Message)
    }
}

function Invoke-HushAction {
    param([Parameter(Mandatory)]$Action, [Parameter(Mandatory)]$Context)
    if ((Test-HushProp $Action 'optional') -and $Action.optional) {
        $selected = @()
        if (Test-HushProp $Context 'OptionalActionIds') { $selected = @($Context.OptionalActionIds) }
        if ($selected -notcontains [string]$Action.id) {
            return , (New-HushResult $Action.type ([string]$Action.id) 'NotSelected' 'optional action is not enabled locally')
        }
    }
    switch ($Action.type) {
        'killProcess' { Invoke-HushKillProcess     -Action $Action -Context $Context }
        'stopService' { Invoke-HushStopService     -Action $Action -Context $Context }
        'removeAutostart' { Invoke-HushRemoveAutostart -Action $Action -Context $Context }
        'setRegistryValue' { Invoke-HushSetRegistryValue -Action $Action -Context $Context }
        default { New-HushResult $Action.type '' 'Error' 'unknown action type' }
    }
}

