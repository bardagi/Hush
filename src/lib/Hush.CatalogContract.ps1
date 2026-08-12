#Requires -Version 5.1
<#
    Hush.CatalogContract.ps1
    Definition and manifest schema contracts.

    This file is dot-sourced by the Hush compatibility loaders.
#>

# ----------------------------------------------------------------------------- schema

$script:HushAllowedActions = @{
    killProcess      = @('match')
    stopService      = @('name')
    removeAutostart  = @('kind', 'name')
    setRegistryValue = @('hive', 'path', 'name', 'valueType', 'data')
}
$script:HushAutostartKinds = @('registryRun', 'startupFolder', 'scheduledTask')
$script:HushAutostartScopes = @('allUsers', 'machine')
$script:HushRegHives = @('HKLM')
$script:HushRegValueTypes = @('String', 'ExpandString', 'DWord', 'QWord', 'MultiString', 'Binary')
# Known boolean flags — if present they must be real booleans (so disable:"false" can't be truthy).
$script:HushBoolActionFields = @('killTree', 'backgroundOnly', 'optional', 'disable', 'disableOnly')

function Test-HushDefinition {
    <# Validate a parsed definition object. Returns @{ Ok = [bool]; Errors = @() } #>
    param([Parameter(Mandatory)]$Def)
    $errors = New-Object System.Collections.Generic.List[string]

    function Has($obj, $name) { Test-HushProp $obj $name }

    if (-not (Has $Def 'schemaVersion')) { $errors.Add('missing schemaVersion') }
    elseif ($Def.schemaVersion -ne 1) { $errors.Add("unsupported schemaVersion '$($Def.schemaVersion)'") }
    foreach ($f in @('name', 'definitionVersion', 'updateDate', 'actions')) {
        if (-not (Has $Def $f)) { $errors.Add("missing $f") }
    }
    if ((Has $Def 'name') -and -not (Test-HushSafeDefinitionName $Def.name)) {
        $errors.Add('name is not a safe identifier')
    }
    if ((Has $Def 'definitionVersion') -and -not ($Def.definitionVersion -is [int] -or $Def.definitionVersion -is [long])) {
        $errors.Add('definitionVersion must be an integer')
    }
    if (Has $Def 'actions') {
        if ($Def.actions -isnot [System.Array]) { $errors.Add('actions must be an array') }
        else {
            $i = -1
            $actionIds = @{}
            foreach ($a in $Def.actions) {
                $i++
                if (-not (Has $a 'type')) { $errors.Add("action[$i] missing type"); continue }
                if (-not (Has $a 'id') -or -not (Test-HushSafeActionId $a.id)) {
                    $errors.Add("action[$i] id must be a unique safe identifier")
                } elseif ($actionIds.ContainsKey($a.id)) {
                    $errors.Add("action[$i] id '$($a.id)' is duplicated")
                } else {
                    $actionIds[$a.id] = $true
                }
                if (($a.type -isnot [string]) -or -not $script:HushAllowedActions.ContainsKey($a.type)) {
                    $errors.Add("action[$i] type '$($a.type)' not allowed"); continue
                }
                foreach ($req in $script:HushAllowedActions[$a.type]) {
                    if (-not (Has $a $req)) { $errors.Add("action[$i] ($($a.type)) missing $req") }
                }
                # Known boolean flags must be real booleans (block disable:"false" truthiness).
                foreach ($bf in $script:HushBoolActionFields) {
                    if ((Has $a $bf) -and ($a.$bf -isnot [bool])) { $errors.Add("action[$i] $bf must be a boolean") }
                }
                if ((Has $a 'backgroundOnly') -and $a.type -ne 'killProcess') {
                    $errors.Add("action[$i] backgroundOnly is only valid for killProcess")
                }
                switch ($a.type) {
                    'killProcess' {
                        if (Has $a 'match') {
                            if (-not (Has $a.match 'name')) { $errors.Add("action[$i] match.name required") }
                            elseif (-not (Test-HushSafeProcessName $a.match.name)) { $errors.Add("action[$i] match.name is not a safe process name") }
                            elseif ((Has $Def 'name') -and $Def.name -eq 'chrome-background' -and
                                [string]$a.match.name -ieq 'chrome.exe' -and
                                (-not (Has $a 'backgroundOnly') -or -not $a.backgroundOnly)) {
                                $errors.Add("action[$i] chrome.exe must set backgroundOnly=true")
                            }
                            # company/path are -like narrowing filters: must be strings (wildcards ok).
                            foreach ($opt in 'company', 'path') {
                                if ((Has $a.match $opt) -and ($a.match.$opt -isnot [string])) { $errors.Add("action[$i] match.$opt must be a string") }
                            }
                        }
                    }
                    'stopService' {
                        if ((Has $a 'name') -and -not (Test-HushSafeServiceName $a.name)) {
                            $errors.Add("action[$i] service name is not a safe name (no wildcards)")
                        }
                    }
                    'removeAutostart' {
                        if ((Has $a 'kind') -and $script:HushAutostartKinds -notcontains $a.kind) {
                            $errors.Add("action[$i] kind '$($a.kind)' invalid")
                        }
                        if ((Has $a 'name') -and -not (Test-HushSafeAutostartPattern $a.name)) {
                            $errors.Add("action[$i] autostart name pattern invalid")
                        }
                        if ((Has $a 'scope') -and $script:HushAutostartScopes -notcontains $a.scope) {
                            $errors.Add("action[$i] scope '$($a.scope)' invalid")
                        }
                        if ((Has $a 'kind') -and $a.kind -eq 'scheduledTask') {
                            if (-not (Has $a 'taskPath') -or -not (Test-HushScheduledTaskPath $a.taskPath)) {
                                $errors.Add("action[$i] scheduledTask taskPath must be an exact safe path")
                            }
                        }
                    }
                    'setRegistryValue' {
                        $hiveOk = (Has $a 'hive') -and ($script:HushRegHives -contains $a.hive)
                        if ((Has $a 'hive') -and -not $hiveOk) { $errors.Add("action[$i] hive invalid") }
                        $typeOk = (Has $a 'valueType') -and ($script:HushRegValueTypes -contains $a.valueType)
                        if ((Has $a 'valueType') -and -not $typeOk) { $errors.Add("action[$i] valueType invalid") }
                        $pathOk = (Has $a 'path') -and (Test-HushSafeRegistryPath $a.path)
                        if ((Has $a 'path') -and -not $pathOk) { $errors.Add("action[$i] registry path invalid") }
                        if ((Has $a 'name') -and -not (Test-HushSafeString $a.name)) { $errors.Add("action[$i] registry value name invalid") }
                        # Registry write guardrail: deny dangerous keys, allow only Policies.
                        if ($hiveOk -and $pathOk -and (Has $a 'name') -and
                            -not (Test-HushAllowedRegistryValue -Hive $a.hive -Path $a.path -Name $a.name)) {
                            $errors.Add("action[$i] registry path not permitted by guardrail")
                        }
                        if ($typeOk -and (Has $a 'data') -and -not (Test-HushRegistryData -ValueType $a.valueType -Data $a.data)) {
                            $errors.Add("action[$i] data does not match valueType '$($a.valueType)'")
                        }
                    }
                }
            }
        }
    }
    [pscustomobject]@{ Ok = ($errors.Count -eq 0); Errors = @($errors) }
}

function Test-HushManifestEntry {
    <# Validate one manifest 'definitions[]' entry. Returns @{ Ok = [bool]; Errors = @() } #>
    param([Parameter(Mandatory)]$Entry)
    $errors = New-Object System.Collections.Generic.List[string]
    if (-not (Test-HushProp $Entry 'name') -or -not (Test-HushSafeDefinitionName $Entry.name)) { $errors.Add('entry name invalid') }
    if (-not (Test-HushProp $Entry 'displayName') -or $Entry.displayName -isnot [string] -or [string]::IsNullOrWhiteSpace($Entry.displayName)) { $errors.Add('entry displayName invalid') }
    if (-not (Test-HushProp $Entry 'description') -or $Entry.description -isnot [string]) { $errors.Add('entry description invalid') }
    if (-not (Test-HushProp $Entry 'file') -or -not (Test-HushSafeCacheFileName $Entry.file)) { $errors.Add('entry file invalid') }
    if (-not (Test-HushProp $Entry 'sha256') -or -not (Test-HushSha256Hex $Entry.sha256)) { $errors.Add('entry sha256 invalid') }
    if ((Test-HushProp $Entry 'definitionVersion') -and -not ($Entry.definitionVersion -is [int] -or $Entry.definitionVersion -is [long])) {
        $errors.Add('entry definitionVersion must be an integer')
    }
    if (-not (Test-HushProp $Entry 'definitionVersion')) { $errors.Add('entry definitionVersion missing') }
    if (-not (Test-HushProp $Entry 'updateDate')) { $errors.Add('entry updateDate missing') }
    else {
        $entryDate = $null
        try { $entryDate = ConvertTo-HushUtc $Entry.updateDate } catch { }
        if (-not $entryDate) { $errors.Add('entry updateDate invalid') }
    }
    [pscustomobject]@{ Ok = ($errors.Count -eq 0); Errors = @($errors) }
}

function Test-HushManifest {
    <# Validate catalog metadata and entry structure. Expiry is optionally advisory for cached data. #>
    param(
        [Parameter(Mandatory)]$Manifest,
        [switch]$AllowExpired
    )
    $errors = New-Object System.Collections.Generic.List[string]
    if (-not (Test-HushProp $Manifest 'schemaVersion') -or $Manifest.schemaVersion -ne 2) {
        $errors.Add('unsupported manifest schemaVersion')
    }
    if (-not (Test-HushProp $Manifest 'catalogVersion') -or
        -not ($Manifest.catalogVersion -is [int] -or $Manifest.catalogVersion -is [long]) -or
        $Manifest.catalogVersion -lt 1) {
        $errors.Add('catalogVersion must be a positive integer')
    }
    $published = $null
    $expires = $null
    if (-not (Test-HushProp $Manifest 'publishedAt')) { $errors.Add('publishedAt missing') }
    else { try { $published = ConvertTo-HushUtc $Manifest.publishedAt } catch { $errors.Add('publishedAt invalid') } }
    if (-not (Test-HushProp $Manifest 'expiresAt')) { $errors.Add('expiresAt missing') }
    else { try { $expires = ConvertTo-HushUtc $Manifest.expiresAt } catch { $errors.Add('expiresAt invalid') } }
    if ($published -and $expires -and $expires -le $published) { $errors.Add('expiresAt must be after publishedAt') }
    if ($expires -and -not $AllowExpired -and [datetime]::UtcNow -gt $expires) { $errors.Add('manifest expired') }
    if (-not (Test-HushProp $Manifest 'definitions') -or $null -eq $Manifest.definitions -or
        $Manifest.definitions -is [string]) {
        $errors.Add('definitions must be an array')
    } else {
        $names = @{}
        $files = @{}
        foreach ($entry in @($Manifest.definitions)) {
            $valid = Test-HushManifestEntry -Entry $entry
            if (-not $valid.Ok) { $errors.Add(($valid.Errors -join '; ')); continue }
            if ($names.ContainsKey($entry.name)) { $errors.Add("duplicate definition name '$($entry.name)'") }
            else { $names[$entry.name] = $true }
            if ($files.ContainsKey($entry.file)) { $errors.Add("duplicate definition file '$($entry.file)'") }
            else { $files[$entry.file] = $true }
        }
    }
    [pscustomobject]@{
        Ok             = ($errors.Count -eq 0)
        Errors         = @($errors)
        CatalogVersion = if (Test-HushProp $Manifest 'catalogVersion') { [int64]$Manifest.catalogVersion } else { 0 }
        PublishedAt    = $published
        ExpiresAt      = $expires
    }
}

function Test-HushManifestDefinitionMatch {
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)]$Definition)
    $fields = @('name', 'displayName', 'definitionVersion', 'updateDate', 'description')
    foreach ($field in $fields) {
        if (-not (Test-HushProp $Definition $field) -or -not (Test-HushProp $Entry $field)) { return $false }
        if ([string]$Entry.$field -cne [string]$Definition.$field) { return $false }
    }
    return $true
}

