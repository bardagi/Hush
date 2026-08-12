# Hush findings ledger

This is the authoritative implementation ledger for the usability, security, and stability
review. A finding is `Fixed` only when the corresponding behavior is implemented and its
targeted validation has passed. `Deferred` means the remaining check needs a disposable,
elevated Windows environment and is not being represented as complete.

## Status summary

| ID | Severity | Area | Status |
|---|---|---|---|
| F-001 | Critical | Installer ACL / SYSTEM script integrity | Fixed |
| F-002 | High | Optional actions execute unconditionally | Fixed |
| F-003 | High | Persistent changes are not reversible | Fixed |
| F-004 | High | Active catalog snapshot is rewritten in place | Fixed |
| F-005 | High | Preview cannot inspect a disabled definition | Fixed |
| F-006 | High | GUI and enforcer race on state.json | Fixed |
| F-007 | Medium | Async operation and failure reporting is misleading | Fixed |
| F-008 | Medium | Signed action selectors and registry policy scope are broad | Fixed |
| F-009 | Medium | Backups and logs are readable by too many principals | Fixed |
| F-010 | Medium | HKCU semantics are incorrect under SYSTEM | Fixed |
| F-011 | Medium | Runtime test coverage does not include install/rollback/concurrency | Deferred |

## Findings

### F-001 — Installer ACL / SYSTEM script integrity — Fixed

**Evidence:** The original installer copied SYSTEM-executed scripts before applying ACLs and
used additive grants, allowing a pre-created `ProgramData\Hush` tree to retain attacker ACEs
or reparse points.

**Impact:** A standard user could potentially replace a script later executed by SYSTEM.

**Implementation:** `src/Hush.InstallSecurity.ps1` now validates the exact install root,
rejects reparse points, unsafe owners, and unknown explicit ACEs, then applies an explicit
allowlist before `install/Install-Hush.ps1` copies scripts. Root, `bin`, `cache`, `logs`,
`backups`, and `config.json` have separate ACL policies; LOCAL SERVICE can read the config and
write cache/log telemetry but cannot read backups. `install/Uninstall-Hush.ps1` resets ACLs
only after rollback and before removal.

**Files/interfaces:** `src/Hush.InstallSecurity.ps1`, `install/Install-Hush.ps1`,
`install/Uninstall-Hush.ps1`; installer ACL/reparse preflight.

**Verification:** `.\tools\Invoke-Quality.ps1 -Fix` — lint, JSON, and 70 Pester checks pass;
`Installer tree trust boundary` covers an explicit Everyone ACE and a directory junction.

**Remaining limitation:** The effective ACL/no-standard-user-write assertion and a full
elevated install exercise still require a disposable Windows VM (tracked by F-011).

### F-002 — Optional actions execute unconditionally — Fixed

**Evidence:** `optional` was validated but ignored by the enforcer.

**Impact:** Enabling a definition could silently disable update or licensing components.

**Implementation:** Every action now requires a stable safe `id`. `enabled.json` persists
`optionalActions`; optional actions default to `NotSelected` and run only when their ID is
selected. The GUI renders per-action checkboxes with impact comments. Shipped definition
fixtures and `tests/fixtures/definitions/README.md` use the new contract.

**Files/interfaces:** `src/Hush.Common.ps1`, `src/Invoke-Hush.ps1`, `gui/Hush-Settings.ps1`,
`src/lib/Hush.CatalogContract.ps1`, `tests/fixtures/definitions/*.json`, `README.md`,
`tests/fixtures/definitions/README.md`.

**Verification:** Pester `keeps optional actions disabled unless their stable ID is selected`
and 70-test quality gate pass.

**Remaining limitation:** GUI rendering is covered by script/lint validation, not an automated
WPF click test.

### F-003 — Persistent changes are not reversible — Fixed

**Evidence:** Service startup state and registry values had no prior-state journal; disabling
a definition or uninstalling did not restore them.

**Impact:** Users could be left with disabled services, policies, or autostarts.

**Implementation:** `changes.json` is a SYSTEM-owned per-action journal. Service startup and
running state, registry value existence/type/data, and autostart backups are captured before
mutation. Restore returns to the captured state, does not force-enable previously disabled
services, is idempotent, and preserves pending entries on failure. Disabling selections asks
for confirmation; uninstall runs `-RollbackAll` and aborts on any error. Process termination
is marked non-reversible in preview output.

**Files/interfaces:** `src/Hush.Common.ps1`, `src/Invoke-Hush.ps1`, `gui/Hush-Settings.ps1`,
`install/Uninstall-Hush.ps1`, `README.md`.

**Verification:** Pester journal tests cover capture, idempotent restore, and simulated restore
failure; the quality gate passes 73/73.

**Remaining limitation:** Live service/registry/task restore is not exercised against the host;
the journal behavior is unit-tested with mocked services and validated backup schemas.

### F-004 — Active catalog snapshot is rewritten in place — Fixed

**Evidence:** Fetch previously removed and rewrote the active snapshot while the pointer still
referenced it.

**Impact:** Concurrent enforcement or interruption could observe a partial catalog.

**Implementation:** Fetches are serialized with `cache\catalog.lock`, staged in unique
directories, validated completely, published as immutable snapshot directories, and switched
with an atomic pointer. Unchanged bytes reuse an already complete snapshot. Pointer resolution
validates all manifest-listed files/hashes and falls back to the newest complete snapshot.
Cleanup never removes the active snapshot.

**Files/interfaces:** `src/Update-HushDefinitions.ps1`, `src/Hush.Common.ps1`.

**Verification:** Integration tests cover complete pointer reads and interrupted-pointer
fallback; the quality gate passes 73/73.

**Remaining limitation:** A multi-process stress test and interrupted filesystem write need a
disposable Windows test harness (F-011).

### F-005 — Preview cannot inspect a disabled definition — Fixed

**Evidence:** Preview only considered enabled definitions and saving immediately enforced.

**Impact:** Users could not inspect a new definition before enabling it.

**Implementation:** `Invoke-Hush.ps1 -PreviewDefinition` always implies dry-run and accepts
optional IDs. The GUI exposes a preview button on every catalog definition and saves selections
without enforcement. Optional impact text is shown beside each toggle.

**Files/interfaces:** `src/Invoke-Hush.ps1`, `gui/Hush-Settings.ps1`, `README.md`.

**Verification:** Integration test previews `test-reg` while `enabled.json` is empty and
confirms the file is unchanged; quality gate passes 73/73.

**Remaining limitation:** WPF interaction remains manually verified rather than UI-automated.

### F-006 — GUI and enforcer race on state.json — Fixed

**Evidence:** GUI preferences and SYSTEM telemetry shared one read-modify-write document.

**Impact:** Enforcement could overwrite a newly requested snooze or quiet-hours setting.

**Implementation:** GUI-owned `preferences.json` stores snooze/quiet-hours. Runtime telemetry,
anti-rollback versions, operation status, and catalog health remain in enforcer-owned
`state.json`. First read migrates only the legacy preference fields. Catalog fetch/enforce
operations use the shared lock and atomic JSON writes.

**Files/interfaces:** `src/Hush.Common.ps1`, `src/Invoke-Hush.ps1`, `gui/Hush-Settings.ps1`,
`install/Install-Hush.ps1`, `src/config.example.json`.

**Verification:** Preference migration test confirms runtime fields are not copied; quality
gate passes 73/73.

**Remaining limitation:** A concurrent GUI/enforcer process stress test remains part of F-011.

### F-007 — Async operation and failure reporting is misleading — Fixed

**Evidence:** GUI reported queued scheduled tasks as success and action errors still exited 0;
fetch failure and expiry were not visible.

**Impact:** Operators could not tell whether a requested operation completed or failed.

**Implementation:** Fetch and enforce records include operation IDs, requested/completed times,
status, exit code, and error details. The GUI waits up to 30 seconds, reports still-running
operations, and refreshes status. Enforcer returns non-zero on action/operation errors while
blocked/excluded actions remain non-fatal. Stale, expired, last-successful-fetch, and last
failure state are surfaced.

**Files/interfaces:** `src/Update-HushDefinitions.ps1`, `src/Invoke-Hush.ps1`,
`gui/Hush-Settings.ps1`.

**Verification:** Integration tests assert failed enforcer and fetch status documents and
non-zero exits; quality gate passes 73/73.

**Remaining limitation:** Scheduled-task timing is not tested on a live installed task.

### F-008 — Signed action selectors and registry policy scope are broad — Fixed

**Evidence:** Scheduled-task removal matched only `TaskName`, autostart patterns could be too
broad, and registry policy writes allowed arbitrary values below a broad prefix.

**Impact:** An authoring error could affect unrelated tasks or policy surfaces.

**Implementation:** Scheduled-task definitions require an exact `taskPath`; Hush task names are
reserved. Autostart patterns need at least three literal characters. Registry writes fail closed
unless the exact HKLM path/value allowlist matches. Action-time checks repeat the guardrails.

**Files/interfaces:** `src/Hush.Common.ps1`, `src/lib/Hush.CatalogContract.ps1`, shipped
definition fixtures, `README.md`, `tests/fixtures/definitions/README.md`.

**Verification:** Pester covers short patterns, task paths/reserved names, exact Chrome policy
value, dangerous paths, and action-time blocking; quality gate passes 73/73.

**Remaining limitation:** The external GitHub catalog repository still has to be created and
published by an operator; this repository now provides the reproducible bootstrap and pinned
CI generator for that handoff.

### F-009 — Backups and logs are readable by too many principals — Fixed

**Evidence:** The previous recursive root grant exposed backup and log content to Users and
LOCAL SERVICE.

**Impact:** Recovery files could disclose registry values, startup files, or task XML.

**Implementation:** Installation ACLs now isolate cache, logs, backups, configuration, and the
change journal. Users receive only the traversal/read rights needed to launch the elevated GUI;
backups and journal remain SYSTEM/Administrators-only. LOCAL SERVICE can write cache and fetch
telemetry but cannot read backups.

**Files/interfaces:** `src/Hush.InstallSecurity.ps1`, `install/Install-Hush.ps1`, `README.md`.

**Verification:** Installer trust-boundary tests pass with the 70-test quality gate.

**Remaining limitation:** Effective principal access still needs the disposable elevated
install check tracked by F-011.

### F-010 — HKCU semantics are incorrect under SYSTEM — Fixed

**Evidence:** SYSTEM enforcement accepted HKCU actions, targeting SYSTEM's profile instead of
the intended interactive user.

**Impact:** A definition could report success without changing the intended user profile.

**Implementation:** The SYSTEM action schema and action-time guardrail accept HKLM only. Docs
state that HKCU requires a future per-profile implementation. `allUsers` autostarts explicitly
mean machine-wide locations plus currently loaded user hives/profiles; Hush does not claim to
load every profile.

**Files/interfaces:** `src/Hush.Common.ps1`, `src/lib/Hush.CatalogContract.ps1`, tests,
`README.md`, `tests/fixtures/definitions/README.md`,
`src/config.example.json`.

**Verification:** Pester rejects HKCU definitions and accepts only the exact shipped HKLM Chrome
policy value; quality gate passes 73/73.

**Remaining limitation:** Per-profile HKCU enforcement is intentionally not implemented.

### F-011 — Runtime test coverage is incomplete — Deferred

**Evidence:** The original 57-test suite lacked installer ACL, optional selection, rollback,
operation status, and snapshot interruption coverage.

**Implementation completed:** The suite now has 70 tests covering those focused paths, plus
schema/docs updates and PowerShell 7/5.1 compatibility checks.

**Verification:** `.\tools\Invoke-Quality.ps1 -Fix` passes 73/73 under PowerShell 7 with
PSScriptAnalyzer/JSON checks; Windows PowerShell 5.1 Pester passes 73/73.

**Remaining limitation:** A disposable elevated install/uninstall exercise, effective ACL
standard-user-write assertion, GUI automation, and multi-process concurrency stress test have
not been run in this worktree. Keep this finding `Deferred` until that harness is executed.

## Change log

| Date | Change |
|---|---|
| 2026-08-12 | Initial ledger created from the repository review. |
| 2026-08-12 | Implemented installer ACL/reparse preflight, explicit optional action IDs, reversible journal/rollback, immutable catalog snapshots, separated preferences/runtime state, operation status, guardrails, HKCU rejection, and synchronized documentation. |
| 2026-08-12 | Added focused regression coverage; PowerShell 7 quality gate and Windows PowerShell 5.1 Pester both pass 73/73. |
| 2026-08-12 | Split the runtime library into ordered modules, added a catalog-only loader, moved policy files to test fixtures, and added the pinned definitions-repository bootstrap path. |
