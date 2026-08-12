#Requires -Version 5.1
<#
    Hush.Common.ps1
    Compatibility loader for the split Hush library. Existing entrypoints and installed
    scripts continue to dot-source this file; implementation lives under src/lib.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$libDir = Join-Path $PSScriptRoot 'lib'
foreach ($library in @(
        'Hush.Core.ps1',
        'Hush.TargetPolicy.ps1',
        'Hush.CatalogContract.ps1',
        'Hush.CatalogStore.ps1',
        'Hush.RuntimePolicy.ps1',
        'Hush.Journal.ps1',
        'Hush.Platform.ps1',
        'Hush.Actions.ps1'
    )) {
    . (Join-Path $libDir $library)
}
