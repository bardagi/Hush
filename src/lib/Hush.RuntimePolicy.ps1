#Requires -Version 5.1
<#
    Hush.RuntimePolicy.ps1
    Local exclusions, snooze, and quiet-hours policy.

    This file is dot-sourced by the Hush compatibility loaders.
#>

# ----------------------------------------------------------------------------- exclusions

function Test-HushExcluded {
    param(
        [Parameter(Mandatory)][ValidateSet('process', 'service', 'autostart')][string]$Type,
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
                if (-not (Test-HushQuietHourValue $w.start) -or -not (Test-HushQuietHourValue $w.end)) { continue }
                $s = [timespan]::Parse($w.start); $e = [timespan]::Parse($w.end)
                $inWindow = if ($s -le $e) { ($now -ge $s -and $now -lt $e) } else { ($now -ge $s -or $now -lt $e) } # wrap past midnight
                if ($inWindow) { return [pscustomobject]@{ Snoozed = $true; Reason = "quiet hours $($w.start)-$($w.end)" } }
            } catch { }
        }
    }
    return [pscustomobject]@{ Snoozed = $false; Reason = $null }
}

