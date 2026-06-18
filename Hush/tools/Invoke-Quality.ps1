#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'PSScriptAnalyzer'; ModuleVersion = '1.25.0' }
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

[CmdletBinding()]
param([switch]$Fix)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$settingsPath = Join-Path $projectRoot 'PSScriptAnalyzerSettings.psd1'
$powershellFiles = @(Get-ChildItem -Path $projectRoot -Recurse -File |
        Where-Object { $_.Extension -in @('.ps1', '.psd1', '.psm1') })
$failures = New-Object System.Collections.Generic.List[string]
$utf8NoBom = New-Object System.Text.UTF8Encoding($true)

foreach ($file in $powershellFiles) {
    $source = [System.IO.File]::ReadAllText($file.FullName)
    $formatted = Invoke-Formatter -ScriptDefinition $source -Settings $settingsPath
    $formatted = $formatted -replace '(?m)[	 ]+$', ''

    if ($source -cne $formatted) {
        if ($Fix) {
            [System.IO.File]::WriteAllText($file.FullName, $formatted, $utf8NoBom)
            Write-Host "Formatted $($file.FullName.Substring($projectRoot.Length + 1))"
        } else {
            $failures.Add("Formatting differs: $($file.FullName.Substring($projectRoot.Length + 1))")
        }
    }
}

$analysis = @(Invoke-ScriptAnalyzer -Path $projectRoot -Recurse -Settings $settingsPath)
foreach ($result in $analysis) {
    $relativePath = $result.ScriptPath.Substring($projectRoot.Length + 1)
    $failures.Add("$relativePath`:$($result.Line):$($result.Column) [$($result.RuleName)] $($result.Message)")
}

foreach ($jsonFile in Get-ChildItem -Path $projectRoot -Recurse -File -Filter '*.json') {
    try {
        [void](Get-Content -LiteralPath $jsonFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        $relativePath = $jsonFile.FullName.Substring($projectRoot.Length + 1)
        $failures.Add("Invalid JSON: $relativePath`: $($_.Exception.Message)")
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    throw "Quality checks failed with $($failures.Count) issue(s)."
}

Write-Host 'Lint/format/JSON checks passed.' -ForegroundColor Green

# --- Pester unit tests (validator + guardrails) ---
$testsDir = Join-Path $projectRoot 'tests'
if (Test-Path $testsDir) {
    Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction Stop
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $testsDir
    $pesterConfig.Run.Throw = $true          # non-zero exit / throw on any failing test
    $pesterConfig.Output.Verbosity = 'Detailed'
    Invoke-Pester -Configuration $pesterConfig
}

Write-Host 'Quality checks passed.' -ForegroundColor Green
