#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Hush.Integration.Tests.ps1

    Exercises the verify -> apply path end-to-end without installing or changing the system:
    a temporary HUSH_ROOT holds a real signed catalog, and the enforcer is run with -Preview
    (dry-run, side-effect free). Asserts the SYSTEM-side trust boundary holds — bad signature,
    wrong schemaVersion, cache/hash mismatch and whole-catalog rollback are all refused — and
    that action-time guardrails / per-entry exclusions behave. No admin rights required.

    Run:  Invoke-Pester -Path .\tests\Hush.Integration.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\src\Hush.Common.ps1')
    # Hush.Common turns StrictMode on; relax it for the TEST HARNESS only so capturing the
    # output of the enforcer (which ends with `exit`) is robust. The enforcer still runs under
    # its own StrictMode when invoked below, so product behaviour is unchanged.
    Set-StrictMode -Off
    $script:Enforcer = (Resolve-Path (Join-Path $PSScriptRoot '..\src\Invoke-Hush.ps1')).Path

    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) ('hush-it-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $Root 'cache') -Force | Out-Null
    $env:HUSH_ROOT = $script:Root

    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
    try {
        $script:PrivXml = $rsa.ToXmlString($true)
        $script:PubXml = $rsa.ToXmlString($false)
    } finally { $rsa.Dispose() }

    $script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    function Write-TestBytes([string]$Path, [string]$Text) {
        [System.IO.File]::WriteAllBytes($Path, $script:Utf8NoBom.GetBytes($Text))
    }

    function Protect-TestManifest([string]$ManifestPath) {
        $bytes = [System.IO.File]::ReadAllBytes($ManifestPath)
        $r = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        try { $r.FromXmlString($script:PrivXml); $sig = $r.SignData($bytes, 'SHA256') } finally { $r.Dispose() }
        [System.IO.File]::WriteAllBytes("$ManifestPath.sig", $sig)
    }

    function New-TestCache {
        # Builds cache\test-reg.json + a signed cache\manifest.json(.sig). A single
        # setRegistryValue action under SOFTWARE\Policies is used because Preview reports it
        # ('would set') without ever touching the registry.
        param([int]$SchemaVersion = 1, [string]$ManifestUpdateDate = '2026-06-01T00:00:00Z')
        $cache = Join-Path $script:Root 'cache'
        $def = [pscustomobject]@{
            schemaVersion     = 1
            name              = 'test-reg'
            displayName       = 'Test'
            definitionVersion = 1
            updateDate        = '2026-01-01T00:00:00Z'
            description       = 'integration test def'
            actions           = @(
                [pscustomobject]@{ type = 'setRegistryValue'; hive = 'HKLM'; path = 'SOFTWARE\Policies\HushTest'; name = 'Flag'; valueType = 'DWord'; data = 0 }
            )
        }
        $defFile = Join-Path $cache 'test-reg.json'
        Write-TestBytes $defFile ($def | ConvertTo-Json -Depth 16)
        $manifest = [pscustomobject]@{
            schemaVersion = $SchemaVersion
            updateDate    = $ManifestUpdateDate
            definitions   = @(
                [pscustomobject]@{ name = 'test-reg'; displayName = 'Test'; definitionVersion = 1; updateDate = '2026-01-01T00:00:00Z'; description = 't'; file = 'test-reg.json'; sha256 = (Get-HushFileSha256Hex -Path $defFile) }
            )
        }
        $mPath = Join-Path $cache 'manifest.json'
        Write-TestBytes $mPath ($manifest | ConvertTo-Json -Depth 16)
        Protect-TestManifest $mPath
    }

    function Set-TestState([hashtable]$Props = @{}) {
        ([pscustomobject]$Props | ConvertTo-Json -Depth 8) | Set-Content -Path (Join-Path $script:Root 'state.json') -Encoding UTF8
    }

    function Invoke-TestEnforcer {
        # The enforcer ends with `exit`; under the call operator that returns control here and
        # the Preview results already written to the pipeline are captured. Filter to a clean
        # array of result objects so callers can pipe/count safely on the refusal path (empty).
        $out = & $script:Enforcer -Preview 2>$null
        @($out | Where-Object { $null -ne $_ })
    }
}

AfterAll {
    if ($env:HUSH_ROOT -and (Test-Path $env:HUSH_ROOT)) {
        Remove-Item -Recurse -Force $env:HUSH_ROOT -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\HUSH_ROOT -ErrorAction SilentlyContinue
}

Describe 'Enforcer (Preview) over a signed cache' {
    BeforeEach {
        New-TestCache
        [pscustomobject]@{ publicKeyXml = $script:PubXml; maxDefinitionAgeHours = 72; protectedServices = @() } |
            ConvertTo-Json | Set-Content (Join-Path $script:Root 'config.json') -Encoding UTF8
        [pscustomobject]@{ enabled = @('test-reg') } | ConvertTo-Json | Set-Content (Join-Path $script:Root 'enabled.json') -Encoding UTF8
        [pscustomobject]@{ processes = @(); services = @(); autostarts = @() } | ConvertTo-Json | Set-Content (Join-Path $script:Root 'exclusions.json') -Encoding UTF8
        Set-TestState @{}
    }

    It 'previews the actions of a valid signed catalog' {
        $res = Invoke-TestEnforcer
        ($res | Where-Object { $_.Type -eq 'setRegistryValue' }).Status | Should -Be 'Preview'
    }
    It 'refuses a tampered manifest signature' {
        $sig = Join-Path $script:Root 'cache\manifest.json.sig'
        $b = [System.IO.File]::ReadAllBytes($sig); $b[0] = $b[0] -bxor 0xFF
        [System.IO.File]::WriteAllBytes($sig, $b)
        ($res = Invoke-TestEnforcer) | Out-Null
        ($res | Where-Object { $_.Status -eq 'Preview' }) | Should -BeNullOrEmpty
    }
    It 'rejects an unsupported manifest schemaVersion' {
        New-TestCache -SchemaVersion 2     # re-signed, so the signature is valid but the schema is not
        ($res = Invoke-TestEnforcer) | Out-Null
        ($res | Where-Object { $_.Status -eq 'Preview' }) | Should -BeNullOrEmpty
    }
    It 'skips a definition whose cached bytes no longer match the signed hash' {
        Add-Content -Path (Join-Path $script:Root 'cache\test-reg.json') -Value ' ' -Encoding UTF8
        ($res = Invoke-TestEnforcer) | Out-Null
        ($res | Where-Object { $_.Status -eq 'Preview' }) | Should -BeNullOrEmpty
    }
    It 'blocks a whole-catalog rollback by manifest updateDate' {
        Set-TestState @{ manifestUpdateDate = '2999-01-01T00:00:00Z' }
        ($res = Invoke-TestEnforcer) | Out-Null
        ($res | Where-Object { $_.Status -eq 'Preview' }) | Should -BeNullOrEmpty
    }
}

Describe 'Action guardrails and per-entry exclusions (Preview)' {
    It 'blocks a protected process before any lookup' {
        $a = [pscustomobject]@{ type = 'killProcess'; match = [pscustomobject]@{ name = 'lsass.exe' } }
        $ctx = [pscustomobject]@{ Preview = $true; Exclusions = $null; Config = $null }
        (Invoke-HushAction -Action $a -Context $ctx).Status | Should -Be 'Blocked'
    }
    It 'blocks a registry write outside the Policies allowlist at action time' {
        $a = [pscustomobject]@{ type = 'setRegistryValue'; hive = 'HKLM'; path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; name = 'x'; valueType = 'String'; data = 'cmd' }
        $ctx = [pscustomobject]@{ Preview = $true; Exclusions = $null; Config = $null }
        (Invoke-HushAction -Action $a -Context $ctx).Status | Should -Be 'Blocked'
    }
    It 'excludes an individual resolved autostart entry, not the whole pattern' {
        Mock Get-HushRunKeyPaths { @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') }
        $fakeKey = [pscustomobject]@{}
        $fakeKey | Add-Member ScriptMethod GetValueNames { @('AKeep', 'ADrop') } -Force
        Mock Get-Item { $fakeKey }
        $a = [pscustomobject]@{ type = 'removeAutostart'; kind = 'registryRun'; name = 'A*'; scope = 'machine' }
        $ctx = [pscustomobject]@{ Preview = $true; Exclusions = [pscustomobject]@{ autostarts = @('AKeep') }; Config = $null }
        $res = Invoke-HushAction -Action $a -Context $ctx
        ($res | Where-Object { $_.Target -like '*AKeep' }).Status | Should -Be 'Excluded'
        ($res | Where-Object { $_.Target -like '*ADrop' }).Status | Should -Be 'Preview'
    }
}
