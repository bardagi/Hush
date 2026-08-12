# Hush definitions catalog

These files are the seed/fixture catalog for the Hush code repository. The live public catalog
is published separately at `bardagi/hush-definitions` so policy changes can ship independently
of the Hush binaries.

The live repository should keep this layout:

```text
definitions/
  manifest.json
  manifest.json.sig
  *.json
  .gitattributes
```

Edit only the individual definition JSON files. On the offline signing machine, regenerate the
manifest and detached signature with:

```powershell
..\tools\Protect-HushManifest.ps1 `
  -DefinitionsDir .\definitions `
  -PrivateKeyPath .\hush-private.xml.dpapi
```

The Hush client trusts the pinned public key and the signed manifest, not the Git repository or
HTTPS transport. Never commit a private key or publish an unsigned catalog commit.

## Definition contract

Every action must include a stable, safe `id` matching `[A-Za-z0-9._-]+`. The ID is the
operator-facing selection and rollback key; do not change it when editing an action's
description or impact. An action marked `optional: true` is disabled by default and runs only
when the machine's `enabled.json` explicitly selects that ID:

```json
{
  "enabled": ["chrome-background"],
  "optionalActions": {
    "chrome-background": ["stop-gupdate"]
  }
}
```

All other actions run when their definition is enabled. Definitions should include a concise
`comment` on optional actions because the GUI displays it before selection. Process termination
is non-reversible; service startup/state changes, HKLM policy values, and autostarts are journaled
and restored to their captured prior state when a definition/action is disabled or Hush is
uninstalled.

Scheduled-task actions require an exact `taskPath`; broad task-name-only selectors are rejected,
and Hush's own task names are reserved. The SYSTEM enforcer accepts `HKLM` registry actions only,
and the shipped policy allowlist currently contains the Chrome `BackgroundModeEnabled` value.
`HKCU` is intentionally unsupported until a per-profile implementation exists. `allUsers`
autostart scope covers machine-wide locations plus currently loaded user hives/profiles; it does
not claim to load every user hive.
