# Contributing

## Quality checks

Development requires the exact tool versions CI pins:
[PSScriptAnalyzer 1.25.0](https://www.powershellgallery.com/packages/PSScriptAnalyzer/1.25.0)
and [Pester 5.8.0](https://www.powershellgallery.com/packages/Pester/5.8.0). Install both with
the same script CI uses, then run the same checks CI runs:

```powershell
.\tools\ci\Install-CIModules.ps1 -Module @(
    @{ Name = 'PSScriptAnalyzer'; RequiredVersion = '1.25.0' }
    @{ Name = 'Pester'; RequiredVersion = '5.8.0' }
)
.\tools\Invoke-Quality.ps1
```

The command checks PowerShell formatting, lint and static-analysis rules, Windows PowerShell
5.1 syntax compatibility, and every JSON file. Apply safe formatting changes with:

```powershell
.\tools\Invoke-Quality.ps1 -Fix
```

## Code and catalog boundaries

Runtime entrypoints dot-source `src\Hush.Common.ps1`, which is a compatibility loader for the
split libraries under `src\lib`. Catalog authoring and verification use the smaller
`src\Hush.Catalog.ps1` loader so policy tooling does not load privileged action code.

The JSON files under `tests\fixtures\definitions` are test fixtures only. Use
`tools\New-HushDefinitionsRepository.ps1` to bootstrap the independently released,
signed catalog repository; do not add production policy changes to this application repo.
