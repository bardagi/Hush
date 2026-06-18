# Hush

**Quiet the background.** Hush is a lightweight, secure Windows tool that periodically pulls a
signed policy *catalog* from a public GitHub repo and closes/removes the background apps,
services, and autostarts you don't want — chosen per machine through a simple GUI.

> Example: enforce "close Chrome in the background" on one machine and "close Adobe in the
> background" on another, from the same central catalog.

---

## How it works

```
        GitHub (public repo)                 Windows machine
   ┌──────────────────────────┐      ┌───────────────────────────────────────┐
   │ definitions/             │      │  Hush-Fetch   (LOCAL SERVICE, no power)│
   │   manifest.json (+ .sig) │  ───▶│   download → verify signature → hash   │
   │   chrome-background.json │ HTTPS│   → anti-rollback → schema → cache\     │
   │   adobe-background.json  │      │                                         │
   └──────────────────────────┘      │  Hush-Enforce (SYSTEM)                  │
                                      │   re-verify cache → apply enabled defs  │
   pinned RSA public key  ───────────│   (guardrails, exclusions, snooze)      │
                                      │                                         │
                                      │  Hush Settings (GUI, self-elevating)    │
                                      │   toggle defs · exclusions · snooze ·   │
                                      │   restore backups · preview/run         │
                                      └───────────────────────────────────────┘
```

Two scheduled tasks split responsibility by privilege:

| Task | Runs as | Network? | Can stop processes? | Job |
|------|---------|----------|---------------------|-----|
| `Hush-Fetch`   | `LOCAL SERVICE` | yes | **no** | download, verify, cache |
| `Hush-Enforce` | `SYSTEM`        | **no** | yes | apply cached, re-verified policy |

The most-privileged component (SYSTEM) never touches the network; the network-facing component
has no power to change the system. The enforcer **re-verifies the signed catalog** before
trusting the cache, so even a compromised fetcher cannot make SYSTEM apply forged instructions.

## Security model (why this is safe to run as SYSTEM)

- **Data, not code.** Definitions only describe allowlisted actions (`killProcess`,
  `stopService`, `removeAutostart`, `setRegistryValue`). There is no "run command" action, so a
  compromised repo cannot get code execution — only bounded, reversible changes.
- **Signed catalog, pinned key.** `manifest.json` is signed (RSA-2048 / SHA-256) and verified
  against a public key pinned in each machine's `config.json`. Every definition is SHA-256
  checked against the signed manifest. The private key stays offline.
- **Fail-closed.** Bad download / bad signature / bad schema → keep the last verified cache and
  apply nothing new.
- **Anti-rollback.** A definition with a lower `definitionVersion` than what's cached/applied is
  rejected (no serving an old, weaker policy).
- **Non-overridable guardrails.** Hush refuses to kill critical OS processes (lsass, csrss,
  winlogon, services, smss, …) or disable protected services (Defender, etc.) even if a signed
  definition asks.
- **Local exclusions.** A per-machine "never touch" list layered on top of the guardrails.
- **Hardened install.** `C:\ProgramData\Hush` is writable only by SYSTEM/Administrators (the
  cache adds write for LOCAL SERVICE only), so a standard user can't swap the SYSTEM-run script.
- **Auditable.** Every action → `logs\hush.log` and the `Hush` Windows Event Log source.

## Repo layout

```
Hush/
├─ install/   Install-Hush.ps1, Uninstall-Hush.ps1
├─ src/       Update-HushDefinitions.ps1 (fetcher), Invoke-Hush.ps1 (enforcer),
│             Hush.Common.ps1 (shared), config.example.json
├─ gui/       Hush-Settings.ps1 (WPF, self-elevating)
├─ tools/     New-HushSigningKey.ps1, Protect-HushManifest.ps1
└─ definitions/   manifest.json (+.sig), chrome-background.json, adobe-background.json
```

Requires only **Windows PowerShell 5.1** (built into Windows 10/11) — no modules to install.

---

## Operator setup (one time)

1. **Make a signing key** (keep the private half offline):
   ```powershell
   .\tools\New-HushSigningKey.ps1 -OutDir .
   # -> hush-public.xml (pin this), hush-private.xml (KEEP OFFLINE)
   ```
2. **Publish the definitions repo.** Put the `definitions/` folder in a public GitHub repo.
   Keep the included `.gitattributes` so git does not rewrite line endings (that would break the
   signature).
3. **Sign the catalog** whenever you add/edit a definition:
   ```powershell
   .\tools\Protect-HushManifest.ps1 -DefinitionsDir .\definitions -PrivateKeyPath .\hush-private.xml
   git add definitions ; git commit -m "update policy" ; git push
   ```
   This regenerates `manifest.json` + `manifest.json.sig`. (The `manifest.json` checked in here
   is illustrative — your run is authoritative.)

## Per-machine install (elevated)

```powershell
.\install\Install-Hush.ps1 `
    -RepoRawBaseUrl 'https://raw.githubusercontent.com/your-org/hush-definitions/main/definitions' `
    -PublicKeyPath  '.\hush-public.xml' `
    -EnabledDefinitions chrome-background      # optional starting selection
```

Then open **Start Menu → Hush Settings** (it self-elevates) to choose which definitions to
enforce, set exclusions, snooze, restore backups, or preview/run now.

## Authoring a definition

A definition is declarative JSON. Required: `schemaVersion` (1), `name`, `displayName`,
`definitionVersion` (bump on every change), `updateDate`, `description`, `actions`.

Action types:

| type | required | notes |
|------|----------|-------|
| `killProcess`      | `match.name` | optional `match.company`/`match.path`, `killTree`, `optional` |
| `stopService`      | `name` | `disable` also sets Startup=Disabled |
| `removeAutostart`  | `kind`, `name` | `kind` = `registryRun` \| `startupFolder` \| `scheduledTask`; `scope`, `disableOnly`, `optional` |
| `setRegistryValue` | `hive`,`path`,`name`,`valueType`,`data` | `hive` = HKLM \| HKCU |

Removed autostarts are backed up to `backups\` and can be restored from the GUI. Mark anything
risky (e.g. updater tasks) `optional`/`disableOnly` to keep things reversible. See
`definitions/chrome-background.json` for a complete example.

## Uninstall

```powershell
.\install\Uninstall-Hush.ps1            # remove tasks/shortcut/event source, keep data
.\install\Uninstall-Hush.ps1 -RemoveData # also delete C:\ProgramData\Hush
```

## Testing locally (no install)

Point Hush at a local tree via `HUSH_ROOT` and exercise the verify → apply path without
touching ProgramData or the schedule. See the verification section of the plan for the full
matrix (signature negatives, guardrails, exclusions, anti-rollback, snooze, backup/restore).
