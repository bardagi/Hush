#Requires -Version 5.1
<#
    Hush.Catalog.ps1
    Minimal catalog-contract loader for authoring and verification tools.

    This intentionally excludes privileged action, journal, and platform helpers. The
    definitions repository can pin a Hush commit and dot-source this loader to validate
    policy data without loading enforcement behavior.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$libDir = Join-Path $PSScriptRoot 'lib'
foreach ($library in @(
        'Hush.Core.ps1',
        'Hush.TargetPolicy.ps1',
        'Hush.CatalogContract.ps1',
        'Hush.CatalogStore.ps1'
    )) {
    . (Join-Path $libDir $library)
}
