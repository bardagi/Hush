# Contributing

## Quality checks

Development requires
[PSScriptAnalyzer 1.25.0](https://www.powershellgallery.com/packages/PSScriptAnalyzer/1.25.0).
Install it once, then run the same checks used by CI:

```powershell
Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser
.\tools\Invoke-Quality.ps1
```

The command checks PowerShell formatting, lint and static-analysis rules, Windows PowerShell
5.1 syntax compatibility, and every JSON file. Apply safe formatting changes with:

```powershell
.\tools\Invoke-Quality.ps1 -Fix
```
