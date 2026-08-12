#Requires -Version 5.1
<#
    Hush.Journal.ps1
    Reversible change journal, backup validation, and restoration.

    This file is dot-sourced by the Hush compatibility loaders.
#>

# ----------------------------------------------------------------------------- result helper

function New-HushResult {
    param([string]$Type, [string]$Target, [string]$Status, [string]$Detail)
    [pscustomobject]@{ Type = $Type; Target = $Target; Status = $Status; Detail = $Detail }
}

# ----------------------------------------------------------------------------- reversible change journal

function Get-HushChangeJournal {
    $doc = Read-HushJson -Path (Get-HushPaths).Changes
    if (-not $doc -or -not (Test-HushProp $doc 'changes')) {
        return [pscustomobject]@{ schemaVersion = 1; changes = @() }
    }
    return $doc
}

function Get-HushChangeKey {
    param([Parameter(Mandatory)][string]$DefinitionName, [Parameter(Mandatory)][string]$ActionId)
    return "$DefinitionName/$ActionId"
}

function Get-HushChangeEntry {
    param([Parameter(Mandatory)][string]$DefinitionName, [Parameter(Mandatory)][string]$ActionId)
    $key = Get-HushChangeKey -DefinitionName $DefinitionName -ActionId $ActionId
    $journal = Get-HushChangeJournal
    return @($journal.changes | Where-Object { $_.key -eq $key -and -not $_.restored }) | Select-Object -First 1
}

function Set-HushChangeEntry {
    param([Parameter(Mandatory)]$Entry)
    $journal = Get-HushChangeJournal
    $remaining = @($journal.changes | Where-Object { $_.key -ne $Entry.key })
    Write-HushJsonAtomic -Path (Get-HushPaths).Changes -Object ([pscustomobject]@{
            schemaVersion = 1
            changes       = @($remaining + $Entry)
        })
}

function Initialize-HushChange {
    param(
        [Parameter(Mandatory)][string]$DefinitionName,
        [Parameter(Mandatory)][string]$ActionId,
        [Parameter(Mandatory)][ValidateSet('service', 'registry')][string]$Type,
        [Parameter(Mandatory)]$Action
    )
    $existing = Get-HushChangeEntry -DefinitionName $DefinitionName -ActionId $ActionId
    if ($existing) { return $existing }

    $entry = [ordered]@{
        key            = Get-HushChangeKey -DefinitionName $DefinitionName -ActionId $ActionId
        definitionName = $DefinitionName
        actionId       = $ActionId
        type           = $Type
        applied        = $false
        restored       = $false
        capturedUtc    = [datetime]::UtcNow.ToString('o')
    }
    if ($Type -eq 'service') {
        $serviceName = [string]$Action.name
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $service) { return $null }
        $cim = Get-CimInstance Win32_Service -Filter "Name = '$($serviceName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
        $entry.serviceName = $serviceName
        $entry.priorStatus = [string]$service.Status
        $entry.priorStartMode = if ($cim) { [string]$cim.StartMode } else { $null }
    } else {
        $path = "HKLM:\$($Action.path)"
        $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        $entry.hive = [string]$Action.hive
        $entry.path = [string]$Action.path
        $entry.valueName = [string]$Action.name
        $entry.priorKeyExists = [bool]$key
        $entry.priorValueExists = $false
        if ($key) {
            try {
                $entry.priorValueExists = @($key.GetValueNames()) -contains [string]$Action.name
                if ($entry.priorValueExists) {
                    $entry.priorValueKind = $key.GetValueKind([string]$Action.name).ToString()
                    $entry.priorValueData = $key.GetValue([string]$Action.name, $null, 'DoNotExpandEnvironmentNames')
                }
            } catch { }
        }
    }
    $entryObject = [pscustomobject]$entry
    Set-HushChangeEntry -Entry $entryObject
    return $entryObject
}

function Complete-HushChange {
    param([Parameter(Mandatory)][string]$DefinitionName, [Parameter(Mandatory)][string]$ActionId)
    $entry = Get-HushChangeEntry -DefinitionName $DefinitionName -ActionId $ActionId
    if (-not $entry) { return }
    $entry | Add-Member applied $true -Force
    $entry | Add-Member appliedUtc ([datetime]::UtcNow.ToString('o')) -Force
    Set-HushChangeEntry -Entry $entry
}

function Add-HushAutostartChange {
    param(
        [Parameter(Mandatory)][string]$DefinitionName,
        [Parameter(Mandatory)][string]$ActionId,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$BackupFile
    )
    $targetHash = (Get-HushSha256Hex -Bytes ([Text.Encoding]::UTF8.GetBytes($Target))).Substring(0, 16)
    $entry = [pscustomobject]@{
        key            = "$(Get-HushChangeKey -DefinitionName $DefinitionName -ActionId $ActionId)/$targetHash"
        definitionName = $DefinitionName
        actionId       = $ActionId
        type           = 'autostart'
        target         = $Target
        backupFile     = $BackupFile
        applied        = $true
        restored       = $false
        capturedUtc    = [datetime]::UtcNow.ToString('o')
        appliedUtc     = [datetime]::UtcNow.ToString('o')
    }
    Set-HushChangeEntry -Entry $entry
}

function Restore-HushChangeEntry {
    param([Parameter(Mandatory)]$Entry)
    if ($Entry.restored) { return (New-HushResult 'rollback' $Entry.key 'Skipped' 'already restored') }
    switch ($Entry.type) {
        'service' {
            $service = Get-Service -Name $Entry.serviceName -ErrorAction Stop
            if ($Entry.priorStartMode) {
                $startup = switch ([string]$Entry.priorStartMode) {
                    'Auto' { 'Automatic' }
                    'Automatic' { 'Automatic' }
                    'Manual' { 'Manual' }
                    'Disabled' { 'Disabled' }
                    default { $null }
                }
                if ($startup) { Set-Service -Name $Entry.serviceName -StartupType $startup -ErrorAction Stop }
            }
            if ([string]$Entry.priorStatus -eq 'Running') {
                if ($service.Status -ne 'Running') { Start-Service -InputObject $service -ErrorAction Stop }
            } elseif ([string]$Entry.priorStatus -eq 'Stopped' -and $service.Status -ne 'Stopped') {
                Stop-Service -InputObject $service -Force -ErrorAction Stop
            }
        }
        'registry' {
            $path = "HKLM:\$($Entry.path)"
            if (-not $Entry.priorValueExists) {
                if (Test-Path -LiteralPath $path) {
                    Remove-ItemProperty -LiteralPath $path -Name $Entry.valueName -Force -ErrorAction SilentlyContinue
                }
            } else {
                if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -LiteralPath $path -Name $Entry.valueName -Value $Entry.priorValueData -Type $Entry.priorValueKind -Force
            }
        }
        'autostart' {
            Restore-HushBackup -BackupFile $Entry.backupFile
        }
        default { throw "Unknown journal entry type '$($Entry.type)'" }
    }
    $Entry | Add-Member restored $true -Force
    $Entry | Add-Member restoredUtc ([datetime]::UtcNow.ToString('o')) -Force
    Set-HushChangeEntry -Entry $Entry
    return (New-HushResult 'rollback' $Entry.key 'Applied' 'restored prior state')
}

function Restore-HushChanges {
    param([string]$DefinitionName, [string[]]$ActionIds, [switch]$All)
    $journal = Get-HushChangeJournal
    $entries = @($journal.changes | Where-Object {
            -not $_.restored -and
            (($All) -or ($DefinitionName -and $_.definitionName -eq $DefinitionName -and
                ((-not $ActionIds) -or ($ActionIds -contains $_.actionId))))
        })
    $results = @()
    foreach ($entry in $entries) {
        try { $results += Restore-HushChangeEntry -Entry $entry }
        catch { $results += New-HushResult 'rollback' $entry.key 'Error' $_.Exception.Message }
    }
    return $results
}

# ----------------------------------------------------------------------------- autostart backup

function Backup-HushAutostart {
    <# Persist enough info to recreate a removed autostart entry. #>
    param([Parameter(Mandatory)][hashtable]$Entry)
    $paths = Get-HushPaths
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dir = Join-Path $paths.Backups $stamp
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $file = Join-Path $dir ("{0}.json" -f [guid]::NewGuid().ToString('N'))
    $Entry['backedUpUtc'] = [datetime]::UtcNow.ToString('o')
    Write-HushJsonAtomic -Path $file -Object ([pscustomobject]$Entry)
    return $file
}

# =============================================================================
# ----------------------------------------------------------------------------- restore

function Restore-HushBackup {
    <# Recreate an autostart entry from a backup JSON file produced by Backup-HushAutostart. #>
    param([Parameter(Mandatory)][string]$BackupFile)
    $b = Read-HushJson -Path $BackupFile
    if (-not $b) { throw "Backup not found: $BackupFile" }
    $valid = Test-HushBackup -Backup $b -BackupFile $BackupFile
    if (-not $valid.Ok) { throw "Backup failed validation: $($valid.Errors -join '; ')" }
    switch ($b.kind) {
        'registryRun' {
            if (-not (Test-Path -LiteralPath $b.keyPath)) { New-Item -Path $b.keyPath -Force | Out-Null }
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
