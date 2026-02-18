## Description
**THE Pr0b3r** is a modular, StrictMode-safe Windows security enumeration framework designed for **operator-friendly** assessments and repeatable reporting.

Version 2 moves away from a single “do everything and dump output” script and into a **test registry + menu-driven console** with:
- Dynamic test discovery from disk
- Scoped test browsing (Workstation / Server / Domain / DMZ)
- Consistent, deduplicated Findings output
- Optional AD operator console (transport selection, Kerberos readiness, telemetry)
- Dependency-safe modules (tests can remain lightweight)

If you liked the original “Pea-style” idea, this is that-but with a proper framework behind it.

---

## Key Features

### ✅ Operator Experience
- Interactive **menu UI** for browsing categories/tests
- Environment profile detection (Workstation/Server/Domain)
- Search runner (find tests by name or ID)
- Findings summary + findings viewer

### ✅ Hardening & Reliability
- `Set-StrictMode -Version Latest`
- Dependency-safe design (modules can load even when optional capabilities are missing)
- “Best-effort” fallbacks (RSAT vs LDAP protocols)
- Failover DC rotation for AD LDAP queries

### ✅ Findings Framework
- Standardised findings schema: `Id`, `Category`, `Title`, `Severity`, `Status`, `Message`, `Recommendation`, `Timestamp`
- Deduping by ID

### ✅ Extensible Plugin Model
- Tests discovered dynamically from:
```

Tests/<Scope>/<Category-TestName>/
├── test.json
├── test.ps1  (or test.psm1)

````
- Just drop a folder in and it registers automatically.

---

## Quick Start

### Run (recommended)
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\pr0ber.ps1
````

### Typical Flow

1. Prober bootstraps `ProberState`
2. Detects `EnvProfile`
3. Discovers tests from `/Tests`
4. Starts the main menu UI

---

## Scopes & What They Mean

Scopes are used for filtering tests in the UI:

* `Workstation` - endpoint/security baseline tests
* `Server` - server/hardening/service checks
* `Domain` - AD-focused tests (delegation, kerberoast, ADCS, tiering, etc.)
* `DMZ` - externally exposed / boundary environment checks
* `All` - universal tests (shows in all scope browsing)

> Note: `All` means “always eligible for display” when browsing Workstation/Server/Domain/DMZ.

---

## Menus

### Main Menu

* Browse Test Categories
* Browse Tests For Environment (auto-detected scope)
* Search Test
* Show Framework Status
* Show Findings
* Active Directory Console (optional subsystem)

### Active Directory Console (Optional)

Provides an operator UX around AD enumeration, including:

* Context build / authentication
* Transport selection (LDAPS/LDAP/GC)
* Kerberos ticket acquisition (SSPI bind)
* Security telemetry scoring banner

> If you are not domain-joined and have no credentials/tickets, AD modules will degrade safely.

---

## Findings

### Severity Levels

* `Good`
* `Info`
* `Low`
* `Medium`
* `High`
* `Critical`

### Findings Summary

The UI prints a summary banner derived from `ProberState.Findings`, e.g.:

```
[!] Findings => Critical:2 High:1 Medium:1 Low:0 Info:0 Good:0
```

### ShortTag IDs (v2)

Findings IDs can be made short and stable by hashing a fingerprint string:
* Keeps IDs unique without being unreadable

Example:

```powershell
$fingerprint = "{0}|{1}|{2}" -f $path,$source,$location
$tag = fncShortHashTag $fingerprint
fncAddFinding -Id ("WEAK_AUTORUN_$tag") ...
```

---

## Developer Guide: Creating Custom Tests

### 1) Create a Test Folder

Create a folder under `Tests/<Scope>/`:

Example:

```
Tests/Workstation/Privilege Escalation-Weak Service Permission Abuse/
```

Folder naming format is flexible, but recommended:

```
<Category>-<TestName>
```

### 2) Add `test.json`

Inside the folder, create `test.json`:

```json
{
  "Id": "PRIVESC-SERVICE-PERMISSION-ABUSE",
  "Name": "Weak Service Permission Abuse",
  "Function": "fncGetPrivEscServicePermissionAbuse",
  "Category": "Privilege Escalation",
  "Scopes": ["All"],
  "RequiresAdmin": false,
  "Description": "Detects services where the current user can modify configuration, start/stop, or alter security descriptors."
}
```

#### Field Requirements

Required:

* `Id`
* `Name`
* `Function`

Recommended:

* `Category`
* `Scopes` (defaults to `All` if missing)
* `RequiresAdmin`
* `Description`

`Scopes` supported values:

* `All`, `Workstation`, `Server`, `Domain`, `DMZ`
* `Shared` is treated as `All`

### 3) Add the Test Script

Add either:

* `test.ps1` (script), or
* `test.psm1` (module)

`test.psm1` is preferred for clean exports, but both are supported.

Example `test.ps1`:

```powershell
function fncGetPrivEscServicePermissionAbuse {
    fncPrintMessage "Checking service permissions..." "info"

    # Your logic here...

    fncAddFinding `
        -Id "PRIVESC_SVC_PERM_ABCDE" `
        -Category "Privilege Escalation" `
        -Title "Weak Service Permissions" `
        -Severity "High" `
        -Status "Detected" `
        -Message "Service XYZ is modifiable by current user." `
        -Recommendation "Fix service ACLs / remove write permissions."
}
```

### 4) Use Framework Helpers (Recommended)

Your tests should prefer these helpers if present:

* `fncPrintMessage` / `fncPrintSectionHeader`
* `fncAddFinding`
* `fncSafeArray` / `fncSafeString` / `fncSafeCount`
* AD tests: `fncEnsureADAuth`, `fncADQuery`, `fncEnsureKerberos`

### 5) Ensure Your Function Exists

The registry will:

1. Import your `test.ps1`/`test.psm1`
2. Verify that your function (`Function` in JSON) exists
3. Register the test

If your function name is wrong, Prober will log/print:

* `Function not found after import`

---

## AD Test Development Notes

If you are writing AD tests:

* Call `fncEnsureADAuth` (or `fncEnsureADTransport`) first
* Use `fncADQuery` (RSAT-safe abstraction via LDAP protocols)
* Expect non-domain joined systems
* Expect missing RSAT
* Fail gracefully and create a Low/Info finding where useful

---

## Logging & Debugging

* Console output uses `fncPrintMessage` levels:

  * `success`, `info`, `warning`, `error`, `debug`
* Debug output is gated by:

  * `$global:config.DEBUG` or `$global:OutputDebug`

---

## Compatibility / Requirements

* Windows PowerShell 5.1 or PowerShell 7+
* Some tests require admin (test.json `RequiresAdmin: true`)
* AD features benefit from:

  * Domain connectivity
  * RSAT module (optional)
  * Valid credentials or Kerberos tickets

---

## Legal Disclaimer

Don’t be a dick.

Only run this on systems where you have explicit authorisation.

---

## Credits / Links

* Project: THE Pr0b3r
* Repo: [https://github.com/deannreid/The-Prober](https://github.com/deannreid/The-Prober)
