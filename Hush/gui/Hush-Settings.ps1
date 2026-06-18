#Requires -Version 5.1
<#
    Hush-Settings.ps1   (GUI)

    A small WPF settings app. Self-elevates (UAC), then lets an administrator:
      * toggle which signed catalog definitions are enforced on this machine,
      * manage a local "never touch" exclusions list,
      * snooze enforcement / set quiet hours,
      * restore previously removed autostarts,
      * preview / run enforcement and see status.

    It only ever reads the locally cached, signature-verified catalog — it cannot
    introduce arbitrary kill targets, so the data-only security model is preserved.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------- self-elevation
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    return
}

# ----------------------------------------------------------------- locate siblings
function Resolve-HushScript([string]$Name) {
    $c = Join-Path $PSScriptRoot $Name
    if (Test-Path $c) { return $c }
    $c = Join-Path (Split-Path $PSScriptRoot -Parent) "src\$Name"
    if (Test-Path $c) { return $c }
    return $null
}
. (Resolve-HushScript 'Hush.Common.ps1')

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$paths = Get-HushPaths

# ----------------------------------------------------------------- helpers
function Get-HushCatalog {
    # Returns verified catalog definitions, or $null if missing/invalid.
    if (-not (Test-Path $paths.ManifestCache) -or -not (Test-Path $paths.ManifestSigCache)) { return $null }
    try {
        $config = Get-HushConfig
        $mb = [System.IO.File]::ReadAllBytes($paths.ManifestCache)
        $sb = [System.IO.File]::ReadAllBytes($paths.ManifestSigCache)
        if (-not (Test-HushSignature -Data $mb -Signature $sb -PublicKeyXml $config.publicKeyXml)) { return $null }
        return ([System.Text.Encoding]::UTF8.GetString($mb) | ConvertFrom-Json).definitions
    } catch { return $null }
}

function Start-HushTask([string]$Name, [string]$ScriptName, [string[]]$ScriptArgs) {
    # Prefer the scheduled task (correct security context); fall back to direct run.
    try {
        if (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue) {
            Start-ScheduledTask -TaskName $Name; return
        }
    } catch { }
    $script = Resolve-HushScript $ScriptName
    if ($script) { & $script @ScriptArgs | Out-Null }
}

# ----------------------------------------------------------------- XAML
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Hush Settings" Height="600" Width="720"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13" Background="#F7F7F8">
  <DockPanel>
    <Border DockPanel.Dock="Top" Background="#1F2937" Padding="16,12">
      <StackPanel>
        <TextBlock Text="Hush" Foreground="White" FontSize="20" FontWeight="SemiBold"/>
        <TextBlock Text="Quiet the background — choose what gets closed." Foreground="#9CA3AF"/>
      </StackPanel>
    </Border>
    <Border x:Name="StaleBanner" DockPanel.Dock="Top" Background="#FEF3C7" Padding="12,8" Visibility="Collapsed">
      <TextBlock x:Name="StaleText" Foreground="#92400E" TextWrapping="Wrap"/>
    </Border>
    <TabControl Margin="8" Background="White">
      <TabItem Header="Definitions">
        <DockPanel>
          <TextBlock DockPanel.Dock="Top" Margin="10" TextWrapping="Wrap"
                     Text="Turn a definition on to enforce it on this machine. Selection is limited to the signed catalog."/>
          <Border DockPanel.Dock="Bottom" Padding="10">
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
              <TextBlock x:Name="DefStatus" VerticalAlignment="Center" Margin="0,0,12,0" Foreground="#6B7280"/>
              <Button x:Name="BtnDefSave" Content="Save and apply" Padding="16,6"/>
            </StackPanel>
          </Border>
          <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel x:Name="DefList" Margin="10"/></ScrollViewer>
        </DockPanel>
      </TabItem>
      <TabItem Header="Exclusions">
        <DockPanel Margin="10">
          <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Margin="0,0,0,8"
                     Text="Never touch these on this machine (one wildcard pattern per line). Layered on top of the built-in safety guardrails."/>
          <Border DockPanel.Dock="Bottom" Padding="0,8,0,0">
            <Button x:Name="BtnExclSave" Content="Save exclusions" Padding="16,6" HorizontalAlignment="Right"/>
          </Border>
          <Grid>
            <Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition/><ColumnDefinition/></Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0" Margin="0,0,6,0">
              <TextBlock Text="Processes" FontWeight="SemiBold"/>
              <TextBox x:Name="ExclProc" AcceptsReturn="True" TextWrapping="Wrap" Height="280" VerticalScrollBarVisibility="Auto"/>
            </StackPanel>
            <StackPanel Grid.Column="1" Margin="6,0">
              <TextBlock Text="Services" FontWeight="SemiBold"/>
              <TextBox x:Name="ExclSvc" AcceptsReturn="True" TextWrapping="Wrap" Height="280" VerticalScrollBarVisibility="Auto"/>
            </StackPanel>
            <StackPanel Grid.Column="2" Margin="6,0,0,0">
              <TextBlock Text="Autostarts" FontWeight="SemiBold"/>
              <TextBox x:Name="ExclAuto" AcceptsReturn="True" TextWrapping="Wrap" Height="280" VerticalScrollBarVisibility="Auto"/>
            </StackPanel>
          </Grid>
        </DockPanel>
      </TabItem>
      <TabItem Header="Snooze">
        <StackPanel Margin="14">
          <TextBlock Text="Temporarily pause enforcement" FontWeight="SemiBold" Margin="0,0,0,8"/>
          <StackPanel Orientation="Horizontal">
            <Button x:Name="BtnSnooze1"  Content="Snooze 1 hour"      Padding="12,6" Margin="0,0,8,0"/>
            <Button x:Name="BtnSnooze4"  Content="Snooze 4 hours"     Padding="12,6" Margin="0,0,8,0"/>
            <Button x:Name="BtnSnoozeT"  Content="Snooze until 7am"   Padding="12,6" Margin="0,0,8,0"/>
            <Button x:Name="BtnSnoozeClr" Content="Clear snooze"       Padding="12,6"/>
          </StackPanel>
          <TextBlock x:Name="SnoozeStatus" Margin="0,8,0,16" Foreground="#6B7280"/>
          <TextBlock Text="Quiet hours (no enforcement during this window)" FontWeight="SemiBold" Margin="0,0,0,8"/>
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="From" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <TextBox x:Name="QhStart" Width="70" Text=""/>
            <TextBlock Text="to" VerticalAlignment="Center" Margin="8,0,6,0"/>
            <TextBox x:Name="QhEnd" Width="70" Text=""/>
            <Button x:Name="BtnQhSave" Content="Save quiet hours" Padding="12,6" Margin="12,0,0,0"/>
            <Button x:Name="BtnQhClear" Content="Clear" Padding="12,6" Margin="8,0,0,0"/>
          </StackPanel>
          <TextBlock Text="Use 24h HH:mm, e.g. 22:00 to 07:00. The fetcher keeps definitions fresh while snoozed." Foreground="#9CA3AF" Margin="0,8,0,0"/>
        </StackPanel>
      </TabItem>
      <TabItem Header="Backups">
        <DockPanel Margin="10">
          <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Margin="0,0,0,8"
                     Text="Autostart entries Hush removed are backed up here and can be restored."/>
          <Border DockPanel.Dock="Bottom" Padding="0,8,0,0">
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
              <Button x:Name="BtnBackupRefresh" Content="Refresh" Padding="12,6" Margin="0,0,8,0"/>
              <Button x:Name="BtnBackupRestore" Content="Restore selected" Padding="12,6"/>
            </StackPanel>
          </Border>
          <ListBox x:Name="BackupList" Height="320"/>
        </DockPanel>
      </TabItem>
      <TabItem Header="Status">
        <StackPanel Margin="14">
          <TextBlock x:Name="StLastFetch"   Margin="0,0,0,4"/>
          <TextBlock x:Name="StLastEnforce" Margin="0,0,0,4"/>
          <TextBlock x:Name="StResult"      Margin="0,0,0,12" Foreground="#6B7280"/>
          <StackPanel Orientation="Horizontal">
            <Button x:Name="BtnFetchNow"   Content="Refresh definitions" Padding="12,6" Margin="0,0,8,0"/>
            <Button x:Name="BtnPreview"    Content="Preview now"          Padding="12,6" Margin="0,0,8,0"/>
            <Button x:Name="BtnRunNow"     Content="Run now"              Padding="12,6"/>
          </StackPanel>
          <TextBlock Text="Preview shows what would be closed without changing anything." Foreground="#9CA3AF" Margin="0,8,0,0"/>
        </StackPanel>
      </TabItem>
    </TabControl>
  </DockPanel>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
function C([string]$n) { $window.FindName($n) }

# ----------------------------------------------------------------- populate Definitions
$catalog = Get-HushCatalog
$enabledDoc = Read-HushJson -Path $paths.Enabled
$enabledSet = @(); if ($enabledDoc -and $enabledDoc.enabled) { $enabledSet = @($enabledDoc.enabled) }

$defCheckboxes = @{}
if (-not $catalog) {
    (C 'DefStatus').Text = 'No verified catalog cached yet — use Status > Refresh definitions.'
} else {
    foreach ($d in $catalog) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Margin = '0,6,0,6'
        $cb.IsChecked = ($enabledSet -contains $d.name)
        $sp = New-Object System.Windows.Controls.StackPanel
        $t1 = New-Object System.Windows.Controls.TextBlock
        $t1.Text = "$($d.displayName) — $($d.description)"; $t1.FontWeight = 'SemiBold'
        $t2 = New-Object System.Windows.Controls.TextBlock
        $t2.Text = "updated $($d.updateDate) · v$($d.definitionVersion) · $($d.name)"
        $t2.Foreground = '#9CA3AF'; $t2.FontSize = 11
        [void]$sp.Children.Add($t1); [void]$sp.Children.Add($t2)
        $cb.Content = $sp
        [void](C 'DefList').Children.Add($cb)
        $defCheckboxes[$d.name] = $cb
    }
}

(C 'BtnDefSave').Add_Click({
    $sel = @($defCheckboxes.Keys | Where-Object { $defCheckboxes[$_].IsChecked })
    Write-HushJsonAtomic -Path $paths.Enabled -Object ([pscustomobject]@{ enabled = $sel })
    Start-HushTask -Name 'Hush-Fetch'   -ScriptName 'Update-HushDefinitions.ps1'
    Start-HushTask -Name 'Hush-Enforce' -ScriptName 'Invoke-Hush.ps1'
    [System.Windows.MessageBox]::Show("Saved. Enforcing: $([string]::Join(', ', $sel))", 'Hush') | Out-Null
})

# ----------------------------------------------------------------- Exclusions
$excl = Read-HushJson -Path $paths.Exclusions
function Join-Lines($a) { if ($a) { [string]::Join("`r`n", @($a)) } else { '' } }
if ($excl) {
    (C 'ExclProc').Text = Join-Lines $excl.processes
    (C 'ExclSvc').Text  = Join-Lines $excl.services
    (C 'ExclAuto').Text = Join-Lines $excl.autostarts
}
(C 'BtnExclSave').Add_Click({
    function Split-Lines($t) { @($t -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    Write-HushJsonAtomic -Path $paths.Exclusions -Object ([pscustomobject]@{
        processes  = Split-Lines (C 'ExclProc').Text
        services   = Split-Lines (C 'ExclSvc').Text
        autostarts = Split-Lines (C 'ExclAuto').Text
    })
    [System.Windows.MessageBox]::Show('Exclusions saved.', 'Hush') | Out-Null
})

# ----------------------------------------------------------------- Snooze / quiet hours
function Get-State { $s = Read-HushJson -Path $paths.State; if (-not $s) { [pscustomobject]@{} } else { $s } }
function Set-Snooze([datetime]$UntilUtc) {
    $s = Get-State
    $s | Add-Member snoozeUntil $UntilUtc.ToString('o') -Force
    Write-HushJsonAtomic -Path $paths.State -Object $s
    Update-SnoozeStatus
}
function Update-SnoozeStatus {
    $s = Get-State
    if ((Test-HushProp $s 'snoozeUntil') -and $s.snoozeUntil) {
        try {
            $u = ConvertTo-HushUtc $s.snoozeUntil
            if ($u -gt [datetime]::UtcNow) { (C 'SnoozeStatus').Text = "Snoozed until $($u.ToLocalTime())"; return }
        } catch { }
    }
    (C 'SnoozeStatus').Text = 'Not snoozed.'
}
(C 'BtnSnooze1').Add_Click({ Set-Snooze ([datetime]::UtcNow.AddHours(1)) })
(C 'BtnSnooze4').Add_Click({ Set-Snooze ([datetime]::UtcNow.AddHours(4)) })
(C 'BtnSnoozeT').Add_Click({
    $next7 = (Get-Date).Date.AddDays(1).AddHours(7)
    if ((Get-Date).Hour -lt 7) { $next7 = (Get-Date).Date.AddHours(7) }
    Set-Snooze ($next7.ToUniversalTime())
})
(C 'BtnSnoozeClr').Add_Click({
    $s = Get-State; $s | Add-Member snoozeUntil $null -Force
    Write-HushJsonAtomic -Path $paths.State -Object $s; Update-SnoozeStatus
})
# Quiet-hours initial values (first window if any).
$st0 = Get-State
if ((Test-HushProp $st0 'quietHours') -and @($st0.quietHours).Count -gt 0) {
    (C 'QhStart').Text = $st0.quietHours[0].start; (C 'QhEnd').Text = $st0.quietHours[0].end
}
(C 'BtnQhSave').Add_Click({
    $s = Get-State
    $s | Add-Member quietHours @([pscustomobject]@{ start = (C 'QhStart').Text.Trim(); end = (C 'QhEnd').Text.Trim() }) -Force
    Write-HushJsonAtomic -Path $paths.State -Object $s
    [System.Windows.MessageBox]::Show('Quiet hours saved.', 'Hush') | Out-Null
})
(C 'BtnQhClear').Add_Click({
    $s = Get-State; $s | Add-Member quietHours @() -Force
    Write-HushJsonAtomic -Path $paths.State -Object $s
    (C 'QhStart').Text = ''; (C 'QhEnd').Text = ''
})
Update-SnoozeStatus

# ----------------------------------------------------------------- Backups
function Update-BackupList {
    (C 'BackupList').Items.Clear()
    if (-not (Test-Path $paths.Backups)) { return }
    foreach ($f in (Get-ChildItem -Path $paths.Backups -Filter *.json -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
        try {
            $b = Read-HushJson -Path $f.FullName
            $target = switch ($b.kind) {
                'registryRun'   { "$($b.keyPath)\$($b.valueName)" }
                'startupFolder' { $b.originalPath }
                'scheduledTask' { "$($b.taskPath)$($b.taskName)" }
                default { $f.Name }
            }
            $item = New-Object System.Windows.Controls.ListBoxItem
            $item.Content = "[$($b.kind)] $target"
            $item.Tag = $f.FullName
            [void](C 'BackupList').Items.Add($item)
        } catch { }
    }
}
(C 'BtnBackupRefresh').Add_Click({ Update-BackupList })
(C 'BtnBackupRestore').Add_Click({
    $sel = (C 'BackupList').SelectedItem
    if (-not $sel) { return }
    try { Restore-HushBackup -BackupFile $sel.Tag; [System.Windows.MessageBox]::Show('Restored.', 'Hush') | Out-Null }
    catch { [System.Windows.MessageBox]::Show("Restore failed: $($_.Exception.Message)", 'Hush') | Out-Null }
})
Update-BackupList

# ----------------------------------------------------------------- Status
function Update-StatusTab {
    $s = Get-State
    $lf = if ((Test-HushProp $s 'lastFetchUtc') -and $s.lastFetchUtc) { (ConvertTo-HushUtc $s.lastFetchUtc).ToLocalTime() } else { 'never' }
    $le = if ((Test-HushProp $s 'lastEnforceUtc') -and $s.lastEnforceUtc) { (ConvertTo-HushUtc $s.lastEnforceUtc).ToLocalTime() } else { 'never' }
    (C 'StLastFetch').Text   = "Last definitions refresh: $lf"
    (C 'StLastEnforce').Text = "Last enforcement run: $le"
    (C 'StResult').Text      = if ((Test-HushProp $s 'lastEnforceResult') -and $s.lastEnforceResult) { "Result: $($s.lastEnforceResult)" } else { '' }
    if ((Test-HushProp $s 'staleDefinitions') -and $s.staleDefinitions) {
        (C 'StaleText').Text = 'Definitions are stale — they have not refreshed recently. Check connectivity or the repo.'
        (C 'StaleBanner').Visibility = 'Visible'
    }
}
(C 'BtnFetchNow').Add_Click({
    Start-HushTask -Name 'Hush-Fetch' -ScriptName 'Update-HushDefinitions.ps1'
    [System.Windows.MessageBox]::Show('Refresh triggered. Reopen the window to see the updated catalog.', 'Hush') | Out-Null
})
(C 'BtnPreview').Add_Click({
    $script = Resolve-HushScript 'Invoke-Hush.ps1'
    $res = & $script -Preview
    $lines = @($res | ForEach-Object { "$($_.Type)  $($_.Target)  [$($_.Status)] $($_.Detail)" })
    $text = if ($lines.Count) { [string]::Join("`r`n", $lines) } else { 'Nothing would be changed.' }
    [System.Windows.MessageBox]::Show($text, 'Hush — preview') | Out-Null
})
(C 'BtnRunNow').Add_Click({
    Start-HushTask -Name 'Hush-Enforce' -ScriptName 'Invoke-Hush.ps1'
    [System.Windows.MessageBox]::Show('Enforcement triggered.', 'Hush') | Out-Null
    Update-StatusTab
})
Update-StatusTab

[void]$window.ShowDialog()
