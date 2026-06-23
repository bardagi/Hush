#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Hush.Security.Tests.ps1

    Asserts the allowlist / guardrails are fail-closed: no mistyped / case-variant /
    whitespace / Unicode look-alike / wildcard / escape / path-traversal / type-confused
    value in a definition (or manifest) can come around them. Pure validator + guardrail
    predicate tests - no admin rights required and nothing on the system is changed.

    Run:  Invoke-Pester -Path .\tests\Hush.Security.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\src\Hush.Common.ps1')
    $script:DefDir = Join-Path $PSScriptRoot '..\definitions'

    function New-HushTestDef {
        # A minimal schema-valid definition; pass -Actions to vary the actions array.
        param([object[]]$Actions = @())
        [pscustomobject]@{
            schemaVersion     = 1
            name              = 'test-def'
            definitionVersion = 1
            updateDate        = '2026-01-01T00:00:00Z'
            actions           = $Actions
        }
    }
}

Describe 'String / identifier validators' {
    It 'accepts a normal process name (with internal spaces)' {
        Test-HushSafeProcessName 'chrome.exe' | Should -BeTrue
        Test-HushSafeProcessName 'Adobe Desktop Service.exe' | Should -BeTrue
    }
    It 'rejects wildcards, quotes, backslashes and traversal in a process name' {
        Test-HushSafeProcessName 'chrome*' | Should -BeFalse
        Test-HushSafeProcessName "chrome'.exe" | Should -BeFalse
        Test-HushSafeProcessName 'a\b.exe' | Should -BeFalse
        Test-HushSafeProcessName '..\evil.exe' | Should -BeFalse
    }
    It 'rejects leading/trailing whitespace and control chars (look-alike dodges)' {
        Test-HushSafeProcessName 'lsass ' | Should -BeFalse
        Test-HushSafeProcessName ' lsass.exe' | Should -BeFalse
        Test-HushSafeProcessName ('lsass' + [char]0x200b + '.exe') | Should -BeFalse  # zero-width space
        Test-HushSafeProcessName "lsass`t" | Should -BeFalse
    }
    It 'rejects non-string values' {
        Test-HushSafeProcessName 123 | Should -BeFalse
        Test-HushSafeProcessName $null | Should -BeFalse
    }
    It 'service names forbid wildcards' {
        Test-HushSafeServiceName 'gupdate' | Should -BeTrue
        Test-HushSafeServiceName 'Win*' | Should -BeFalse
        Test-HushSafeServiceName 'Win?efend' | Should -BeFalse
    }
    It 'definition names and cache file names are strict' {
        Test-HushSafeDefinitionName 'chrome-background' | Should -BeTrue
        Test-HushSafeDefinitionName 'bad/name' | Should -BeFalse
        Test-HushSafeCacheFileName 'chrome-background.json' | Should -BeTrue
        Test-HushSafeCacheFileName '..\..\evil.json' | Should -BeFalse
        Test-HushSafeCacheFileName 'evil.exe' | Should -BeFalse
    }
    It 'sha256 must be 64 hex chars' {
        Test-HushSha256Hex ('a' * 64) | Should -BeTrue
        Test-HushSha256Hex 'xyz' | Should -BeFalse
        Test-HushSha256Hex ('a' * 63) | Should -BeFalse
    }
}

Describe 'Autostart pattern validator (wildcards allowed, but bounded)' {
    It 'accepts real-world autostart patterns' {
        Test-HushSafeAutostartPattern 'GoogleChromeAutoLaunch_*' | Should -BeTrue
        Test-HushSafeAutostartPattern 'Adobe*' | Should -BeTrue
        Test-HushSafeAutostartPattern 'Adobe CCXProcess' | Should -BeTrue
    }
    It 'rejects path separators, traversal and a bare wildcard' {
        Test-HushSafeAutostartPattern 'a\b' | Should -BeFalse
        Test-HushSafeAutostartPattern '..\x' | Should -BeFalse
        Test-HushSafeAutostartPattern '*' | Should -BeFalse
        Test-HushSafeAutostartPattern '**' | Should -BeFalse
    }
}

Describe 'Registry path validator and write guardrail' {
    It 'validates safe sub-key paths and rejects unsafe ones' {
        Test-HushSafeRegistryPath 'SOFTWARE\Policies\Google\Chrome' | Should -BeTrue
        Test-HushSafeRegistryPath 'SOFTWARE\..\..\evil' | Should -BeFalse
        Test-HushSafeRegistryPath 'SOFTWARE\Pol*' | Should -BeFalse
        Test-HushSafeRegistryPath 'HKLM:\SOFTWARE\x' | Should -BeFalse   # no hive/drive injection
    }
    It 'allows writes only under SOFTWARE\Policies\**' {
        Test-HushAllowedRegistryPath -Hive 'HKLM' -Path 'SOFTWARE\Policies\Google\Chrome' | Should -BeTrue
        Test-HushAllowedRegistryPath -Hive 'HKCU' -Path 'SOFTWARE\Policies\Microsoft\Edge' | Should -BeTrue
        Test-HushAllowedRegistryPath -Hive 'HKLM' -Path 'SOFTWARE\Google\Chrome' | Should -BeFalse
    }
    It 'denylist wins even for paths under an allowed prefix' {
        Test-HushAllowedRegistryPath -Hive 'HKLM' -Path 'SOFTWARE\Policies\System' | Should -BeFalse
        Test-HushAllowedRegistryPath -Hive 'HKLM' -Path 'SOFTWARE\Policies\Microsoft\Windows Defender' | Should -BeFalse
        Test-HushAllowedRegistryPath -Hive 'HKLM' -Path 'SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logon' | Should -BeFalse
    }
    It 'blocks the classic code-execution / AV-disable keys' {
        Test-HushProtectedRegistryPath -Hive 'HKLM' -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe' | Should -BeTrue
        Test-HushProtectedRegistryPath -Hive 'HKLM' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Should -BeTrue
        Test-HushProtectedRegistryPath -Hive 'HKLM' -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Should -BeTrue
        Test-HushProtectedRegistryPath -Hive 'HKLM' -Path 'SYSTEM\CurrentControlSet\Services\WinDefend' | Should -BeTrue
    }
}

Describe 'Registry data type matching' {
    It 'matches integer types to DWord/QWord' {
        Test-HushRegistryData -ValueType 'DWord' -Data 0 | Should -BeTrue
        Test-HushRegistryData -ValueType 'DWord' -Data 'x' | Should -BeFalse
        Test-HushRegistryData -ValueType 'QWord' -Data 5 | Should -BeTrue
    }
    It 'matches string and multistring types' {
        Test-HushRegistryData -ValueType 'String' -Data 'hello' | Should -BeTrue
        Test-HushRegistryData -ValueType 'String' -Data 1 | Should -BeFalse
        Test-HushRegistryData -ValueType 'MultiString' -Data @('a', 'b') | Should -BeTrue
        Test-HushRegistryData -ValueType 'MultiString' -Data 'a' | Should -BeFalse
    }
}

Describe 'Quiet-hours validator' {
    It 'accepts strict HH:mm values' {
        Test-HushQuietHourValue '00:00' | Should -BeTrue
        Test-HushQuietHourValue '07:30' | Should -BeTrue
        Test-HushQuietHourValue '23:59' | Should -BeTrue
    }
    It 'rejects loose or out-of-range values' {
        Test-HushQuietHourValue '7:30' | Should -BeFalse
        Test-HushQuietHourValue '24:00' | Should -BeFalse
        Test-HushQuietHourValue '12:60' | Should -BeFalse
        Test-HushQuietHourValue 'noon' | Should -BeFalse
    }
}

Describe 'Backup restore validator' {
    BeforeEach {
        $script:OldHushRoot = $env:HUSH_ROOT
        $script:BackupTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('hush-backup-test-' + [guid]::NewGuid().ToString('N'))
        $env:HUSH_ROOT = $script:BackupTestRoot
    }
    AfterEach {
        if ($script:OldHushRoot) { $env:HUSH_ROOT = $script:OldHushRoot }
        else { Remove-Item Env:\HUSH_ROOT -ErrorAction SilentlyContinue }
    }

    It 'accepts a registry Run backup produced by Hush' {
        $backupFile = Join-Path $script:BackupTestRoot 'backups\20260101-000000\backup.json'
        $backup = [pscustomobject]@{
            kind      = 'registryRun'
            keyPath   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            valueName = 'AcmeUpdater'
            valueKind = 'String'
            valueData = 'C:\Program Files\Acme\updater.exe'
        }
        (Test-HushBackup -Backup $backup -BackupFile $backupFile).Ok | Should -BeTrue
    }
    It 'rejects backup files outside the Hush backup root' {
        $backupFile = Join-Path ([System.IO.Path]::GetTempPath()) 'outside-backup.json'
        $backup = [pscustomobject]@{
            kind      = 'registryRun'
            keyPath   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            valueName = 'AcmeUpdater'
            valueKind = 'String'
            valueData = 'x'
        }
        (Test-HushBackup -Backup $backup -BackupFile $backupFile).Ok | Should -BeFalse
    }
    It 'rejects startup-folder restores outside known Startup folders' {
        $backupFile = Join-Path $script:BackupTestRoot 'backups\20260101-000000\backup.json'
        $backup = [pscustomobject]@{
            kind         = 'startupFolder'
            originalPath = 'C:\Windows\System32\evil.lnk'
            fileName     = 'evil.lnk'
        }
        (Test-HushBackup -Backup $backup -BackupFile $backupFile).Ok | Should -BeFalse
    }
    It 'rejects scheduled task path traversal' {
        $backupFile = Join-Path $script:BackupTestRoot 'backups\20260101-000000\backup.json'
        $backup = [pscustomobject]@{
            kind     = 'scheduledTask'
            taskName = 'AcmeUpdater'
            taskPath = '\..\'
            xml      = '<Task></Task>'
        }
        (Test-HushBackup -Backup $backup -BackupFile $backupFile).Ok | Should -BeFalse
    }
}

Describe 'Protected process guardrail (canonicalises before compare)' {
    It 'blocks critical processes across case / extension / whitespace variants' {
        Test-HushProtectedProcess -Name 'lsass' | Should -BeTrue
        Test-HushProtectedProcess -Name 'LSASS' | Should -BeTrue
        Test-HushProtectedProcess -Name 'lsass.exe' | Should -BeTrue
        Test-HushProtectedProcess -Name 'lsass ' | Should -BeTrue
        Test-HushProtectedProcess -Name 'CSRSS.EXE' | Should -BeTrue
    }
    It 'does not block ordinary apps' {
        Test-HushProtectedProcess -Name 'chrome.exe' | Should -BeFalse
    }
}

Describe 'Protected service guardrail (case-insensitive)' {
    It 'blocks Defender across case variants' {
        Test-HushProtectedService -Name 'WinDefend' | Should -BeTrue
        Test-HushProtectedService -Name 'windefend' | Should -BeTrue
        Test-HushProtectedService -Name 'WINDEFEND' | Should -BeTrue
    }
    It 'honours config-supplied protected services' {
        $cfg = [pscustomobject]@{ protectedServices = @('MyImportantSvc') }
        Test-HushProtectedService -Name 'myimportantsvc' -Config $cfg | Should -BeTrue
    }
    It 'does not block an ordinary service' {
        Test-HushProtectedService -Name 'gupdate' | Should -BeFalse
    }
}

Describe 'Test-HushDefinition - the chokepoint rejects bypass attempts' {
    It 'rejects a wildcard service name' {
        $d = New-HushTestDef @([pscustomobject]@{ type = 'stopService'; name = 'Win*' })
        (Test-HushDefinition -Def $d).Ok | Should -BeFalse
    }
    It 'rejects a wildcard / unsafe process name' {
        $d = New-HushTestDef @([pscustomobject]@{ type = 'killProcess'; match = [pscustomobject]@{ name = 'chrome*' } })
        (Test-HushDefinition -Def $d).Ok | Should -BeFalse
        $d2 = New-HushTestDef @([pscustomobject]@{ type = 'killProcess'; match = [pscustomobject]@{ name = 'a\b.exe' } })
        (Test-HushDefinition -Def $d2).Ok | Should -BeFalse
    }
    It 'rejects a non-string process name' {
        $d = New-HushTestDef @([pscustomobject]@{ type = 'killProcess'; match = [pscustomobject]@{ name = 123 } })
        (Test-HushDefinition -Def $d).Ok | Should -BeFalse
    }
    It 'rejects an invalid autostart scope' {
        $d = New-HushTestDef @([pscustomobject]@{ type = 'removeAutostart'; kind = 'registryRun'; name = 'Foo*'; scope = 'bogus' })
        (Test-HushDefinition -Def $d).Ok | Should -BeFalse
    }
    It 'rejects setRegistryValue outside the Policies allowlist' {
        $reg = [pscustomobject]@{ type = 'setRegistryValue'; hive = 'HKLM'; path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; name = 'evil'; valueType = 'String'; data = 'cmd.exe' }
        (Test-HushDefinition -Def (New-HushTestDef @($reg))).Ok | Should -BeFalse
    }
    It 'rejects setRegistryValue with data/valueType mismatch' {
        $reg = [pscustomobject]@{ type = 'setRegistryValue'; hive = 'HKLM'; path = 'SOFTWARE\Policies\Acme'; name = 'Flag'; valueType = 'DWord'; data = 'not-an-int' }
        (Test-HushDefinition -Def (New-HushTestDef @($reg))).Ok | Should -BeFalse
    }
    It 'accepts a valid Policies registry write' {
        $reg = [pscustomobject]@{ type = 'setRegistryValue'; hive = 'HKLM'; path = 'SOFTWARE\Policies\Google\Chrome'; name = 'BackgroundModeEnabled'; valueType = 'DWord'; data = 0 }
        (Test-HushDefinition -Def (New-HushTestDef @($reg))).Ok | Should -BeTrue
    }
    It 'rejects a non-integer definitionVersion' {
        $d = New-HushTestDef @()
        $d.definitionVersion = '1'
        (Test-HushDefinition -Def $d).Ok | Should -BeFalse
    }
    It 'rejects a string where a boolean flag is expected (disable:"false")' {
        $d = New-HushTestDef @([pscustomobject]@{ type = 'stopService'; name = 'gupdate'; disable = 'false' })
        (Test-HushDefinition -Def $d).Ok | Should -BeFalse
    }
    It 'rejects an unsafe definition name' {
        $d = New-HushTestDef @()
        $d.name = 'bad name/../x'
        (Test-HushDefinition -Def $d).Ok | Should -BeFalse
    }
}

Describe 'Test-HushManifestEntry - traversal and integrity' {
    It 'rejects a traversing file name' {
        $e = [pscustomobject]@{ name = 'x'; file = '..\..\evil.json'; sha256 = ('a' * 64) }
        (Test-HushManifestEntry -Entry $e).Ok | Should -BeFalse
    }
    It 'rejects a malformed sha256' {
        $e = [pscustomobject]@{ name = 'x'; file = 'x.json'; sha256 = 'nope' }
        (Test-HushManifestEntry -Entry $e).Ok | Should -BeFalse
    }
    It 'accepts a well-formed entry' {
        $e = [pscustomobject]@{ name = 'chrome-background'; file = 'chrome-background.json'; sha256 = ('0' * 64) }
        (Test-HushManifestEntry -Entry $e).Ok | Should -BeTrue
    }
}

Describe 'The shipped definitions still validate' {
    It 'chrome-background.json is valid' {
        $def = Get-Content -LiteralPath (Join-Path $script:DefDir 'chrome-background.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        (Test-HushDefinition -Def $def).Ok | Should -BeTrue
    }
    It 'adobe-background.json is valid' {
        $def = Get-Content -LiteralPath (Join-Path $script:DefDir 'adobe-background.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        (Test-HushDefinition -Def $def).Ok | Should -BeTrue
    }
}
