# Implementation Plan — Interactive Mode + Git-Driven Policy Lifecycle

This plan assumes `REVIEW.md` findings are accepted as-is. Phase 0 bug fixes are
bundled into Step 1.1 of Phase 1 so each step can be reviewed as a unit.

---

## Phase 1 — Interactive TUI & Config Management

### Step 1.1 — Bug fixes from REVIEW.md (no new features)

**Files touched:** `src/main.py`, `src/bigip_client.py`, `src/utils.py`,
`src/report_generator.py`, `src/policy_exporter.py`

**Changes:**
- `main.py:273-276` — Fix inverted `verify_ssl` string-to-bool conversion
  (`in ("0","false","no")` → `in ("1","true","yes")`).
- `main.py:37` — Remove duplicate import line; keep line 39 only.
- `main.py:545,719` — Remove unused `iterable = successes` assignments.
- `main.py:1-18` — Fix garbled module docstring.
- `bigip_client.py:110` — Do NOT clear `self._password` in `authenticate()`;
  add a comment explaining the deliberate trade-off. Only zero it out in `close()`.
- `bigip_client.py:284-297` — Remove dead `_parse_content_range_total` helper.
- `utils.py:26-38` — Add regex pattern to `_MaskFilter` covering HTTPS credential
  URLs: `(https?://[^:@/\s]+:)[^@/\s]+(@)` → `\g<1>***MASKED***\g<2>`.
- `report_generator.py:623-807` — Remove dead first copy of `_build_policy_report_fragment`.
- `report_generator.py:838-945` — Remove dead first copy of `generate_html_dashboard`.
- `policy_exporter.py:561` — URL-encode `reported_filename` with
  `urllib.parse.quote(reported_filename, safe="")` before constructing `dl_path`.

**Tests:** Existing test suite must stay green. Add:
- `tests/test_utils.py` — Assert `_MaskFilter` masks a log record containing
  `https://user:secret@host/repo.git`.
- `tests/test_main_ssl.py` — Parameterised: `"true"` → `verify_ssl=True`,
  `"false"` → `verify_ssl=False`, `"1"` → `True`, `"0"` → `False`.

---

### Step 1.2 — `src/config_manager.py` — new module

**Files created:** `src/config_manager.py`

**Responsibilities:**
- `load_config(path: Optional[str]) -> AppConfig` — read YAML/JSON; migrate legacy
  flat `bigip:` block to `devices: [{name: "default", ...}]` automatically.
- `save_config(config: AppConfig, path: str) -> None` — write with `open(…, "w")`
  then `os.chmod(path, 0o600)`; raise `ValueError` if any device dict contains
  a `password` key (reject passwords on disk).
- `DeviceConfig`, `AuditConfig`, `GitConfig`, `BaselineConfig` typed dataclasses.
- `validate_config(config: AppConfig) -> List[str]` — returns list of error strings
  (empty = valid). Checks: required fields present, host is non-empty, no device has
  `password`, `concurrent_exports` in 1-20, etc.
- Backwards compat: if config contains `gitlab:` block but not `git:`, copy it to
  `git:` and emit a `DeprecationWarning` log line.
- Deprecation: `--gitlab-*` CLI flags continue to work; `main.py` emits a
  `DeprecationWarning("--gitlab-* flags are deprecated; use --git-* equivalents")`
  when they are used (but still honours them).

**Config schema changes:** Extend `config.yaml.example` with the new multi-device
and `git:` / `baselines:` blocks as specified in the task description.

**Tests:** `tests/test_config_manager.py`
- Legacy schema migration: flat `bigip:` block → `devices[0]` round-trip.
- Round-trip read/write: load example, mutate a field, save, reload, assert equality.
- Permission bits: after `save_config`, `stat(path).st_mode & 0o777 == 0o600`.
- Password rejection: `save_config` raises `ValueError` if any device has `password`.
- Deprecation warning: loading a `gitlab:` block emits a `DeprecationWarning`.
- `validate_config` returns an error for an empty host; returns empty list for valid config.

---

### Step 1.3 — Refactor `main.py` to source config through `config_manager`

**Files touched:** `src/main.py`

**Changes:**
- Replace `_load_config()` + ad-hoc `bigip_cfg.get(…)` calls with
  `config_manager.load_config(path)` returning a typed `AppConfig`.
- `_resolve()` stays but operates on typed fields, not raw dict lookups.
- Hoist `_PASS_THRESHOLD` into `AppConfig.audit.pass_threshold` with a 90.0 default;
  propagate it into `_print_summary()` and `report_generator` call sites.
- Per-device password env-var convention:
  `BIGIP_PASS__<NAME_UPPER_UNDERSCORE>` is tried first; `BIGIP_PASS` is the fallback.
- Add `--interactive` flag (bool, default `False`). If `--interactive` is present
  OR if no positional audit flags are given AND stdin is a TTY, enter interactive mode.

**No new tests** beyond checking the config integration path; existing tests cover CLI.

---

### Step 1.4 — `src/interactive.py` — new module

**Files created:** `src/interactive.py`

**Dependencies added to `requirements.txt`:** `questionary>=2.0`

**Architecture:** simple state machine — each screen is a function returning the
next screen name (`str`) or `None` to exit. A top-level `run_interactive(config_path)`
dispatches on the returned name.

**Screens / functions:**

| Function | Responsibility |
|---|---|
| `screen_main_menu()` | Top-level 7-option menu |
| `screen_run_audit()` | Device multi-select → mode → baseline source → partitions → format → confirm+run |
| `screen_manage_devices()` | Sub-menu: list / add / edit / remove / test |
| `screen_list_devices()` | Print table; return to parent |
| `screen_add_device()` | Guided form; optional reachability check; write config |
| `screen_edit_device()` | Pick one → field-by-field questionary prompts |
| `screen_remove_device()` | confirm(default=False) → write config |
| `screen_test_connection()` | Pick device → authenticate → fetch hostname → close |
| `screen_manage_git()` | Sub-menu: show / set URL+branch+dir / toggle auto-push / sync / status / author |
| `screen_git_sync()` | Call `GitLabStateManager.sync_from_remote()`; print result |
| `screen_review_pending()` | Phase 2 stub — prints "not yet implemented" |
| `screen_manage_baselines()` | Set `baselines.waf_fallback` and `baselines.bot_fallback` |
| `screen_view_last_run()` | Glob `output_dir/reports/` for dashboards; print table + offer browser open |

**Key implementation notes:**
- Non-TTY guard at module entry: `if not sys.stdin.isatty(): return` + hint.
- `questionary.password()` for prompts that touch credentials; result is never
  passed to `config_manager.save_config()`.
- "Run an audit" re-uses `_run_waf_audit()` / `_run_bot_audit()` from `main.py`
  unchanged; the interactive layer only assembles parameters.
- After an audit completes, offer `webbrowser.open(dashboard_path)`.
- Destructive operations (remove device, overwrite source-of-truth) use
  `questionary.confirm("Are you sure?", default=False)`.

**Tests:** `tests/test_interactive.py`
- Non-TTY short-circuit: with `sys.stdin` replaced by a non-TTY `StringIO`, calling
  `run_interactive()` returns immediately without prompting.
- `screen_test_connection` closes the `BigIPClient` after success and failure.
- Destructive operations do not proceed when `questionary.confirm` returns `False`
  (mock `questionary` to return `False`).

---

### Step 1.5 — Update `main.py` entry point

**Files touched:** `src/main.py`

**Changes:**
- At the top of `main()`: if interactive mode is selected (no audit flags + TTY, or
  `--interactive`), call `interactive.run_interactive(config_path)` and return its
  exit code.
- All existing flag paths unchanged; no flag removal.
- Add deprecation warnings for `--gitlab-*` flags (log, not hard error).

**No new tests** beyond the existing integration tests.

---

### Step 1.6 — `README.md` update for Phase 1

**Files touched:** `README.md`

**Content:** interactive-mode invocation, transcript-style screenshot of the main menu
and the "Run an audit" flow, config schema reference for the new `devices:` and `git:` blocks.

---

## Phase 2 — Git as Source of Truth & Change Acceptance Workflow

### Step 2.1 — `src/change_workflow.py` — new module

**Files created:** `src/change_workflow.py`

**Public API:**

```python
@dataclass
class PendingChange:
    change_id:      str          # SHA-256 of device|fullPath|normalised_target_content
    mode:           str          # "waf" | "bot"
    policy_path:    str
    device_hostname: str
    device_mgmt_ip:  str
    status:         str          # "NEW" | "CLEAN" | "DRIFTED"
    exported_file:  Path
    sot_file:       Optional[Path]
    score:          float
    summary:        Dict[str, int]   # critical/warning/info counts
    report_md:      Optional[Path]
    report_html:    Optional[Path]
    run_id:         str

@dataclass
class CommitResult:
    success: bool
    sha:     str
    message: str
    error:   str

def build_pending_manifest(
    results: List[ComparisonResult],
    exported_policies: List[Dict],      # enriched with local_path, fullPath
    output_dir: str,
    repo_dir: str,
    run_id: str,
    device_hostname: str,
    device_mgmt_ip: str,
) -> Path: ...

def load_pending_changes(repo_dir: str) -> List[PendingChange]: ...

def accept_change(
    change: PendingChange,
    commit_message: str,
    sign: bool = False,
    author_name: str = "",
    author_email: str = "",
) -> CommitResult: ...

def reject_change(change: PendingChange, reason: str) -> None: ...

def diff_change(change: PendingChange) -> str: ...

def canonicalize_xml(path: Path) -> str: ...

def canonicalize_json(path: Path) -> str: ...
```

**`change_id` computation:**
```
SHA-256( f"{device_hostname}|{policy_path}|{canonicalize_xml/json(exported_file)}" )
```
Stable across re-runs as long as device, policy path, and normalised content are
identical.

**Canonicalization:**
- `canonicalize_xml`: parse with `policy_parser._parse_tree`; serialize with
  `lxml.etree.tostring(sort_keys=False)` after sorting attributes; or with stdlib
  using `xml.etree.ElementTree.indent` + sorted attribute dicts. Falls back to
  stdlib if lxml absent.
- `canonicalize_json`: `json.dumps(json.load(fh), sort_keys=True, indent=2)`.

**Diff output:** `difflib.unified_diff` over canonicalized lines, context=5.

**`.auditor-state.json`** (gitignored, at repo root): tracks resolved change IDs.

```json
{
  "resolved": {
    "a3f…": {
      "action": "accepted" | "rejected",
      "at": "2026-04-24T14:30:00Z",
      "reason": "…",
      "commit": "abc123"
    }
  }
}
```

**Files touched:** also `src/gitlab_state.py` (add 3 methods):
- `commit_specific_paths(paths: List[str], message: str, sign: bool) -> str` (returns SHA)
- `has_uncommitted_at(path: str) -> bool`
- `current_branch() -> str`

**Tests:** `tests/test_change_workflow.py`
- `canonicalize_xml`: two semantically identical XMLs with reordered attributes
  produce identical output; whitespace-only reorder produces zero diff.
- `canonicalize_json`: sort_keys normalisation; nested dicts.
- `change_id` stability: same inputs → same ID; changing any field → different ID.
- `build_pending_manifest` on a synthetic result list writes a parseable JSON file.
- Classification: policy with no SoT file → `NEW`; matching export → `CLEAN`;
  differing export → `DRIFTED`.
- `accept_change` (git-init temp dir fixture, no network):
  writes exported file over SoT path; makes exactly one commit touching exactly
  that path; updates `.auditor-state.json`.
- `reject_change`: working tree clean afterwards; `.auditor-state.json` updated.
- XML/JSON diff: known drift produces non-empty diff; identical files produce empty diff.

---

### Step 2.2 — Integrate change classification into the WAF/BOT audit workflows

**Files touched:** `src/main.py`, `src/gitlab_state.py`

**Changes:**

1. In `_run_waf_audit()` and `_run_bot_audit()`, after the per-policy comparison loop:
   - If `gitlab_state is not None`, classify each policy as `NEW` / `CLEAN` / `DRIFTED`
     by calling `change_workflow.classify_result(cmp_result, sot_file_path)`.
   - Call `change_workflow.build_pending_manifest(…)` to write
     `runs/<mode>/<run_id>/pending_changes.json`.
   - Do **not** auto-commit SoT files (except when `--gitlab-update-source-truth` is
     passed, which keeps CI/batch behaviour intact with the existing flag).

2. `gitlab_state.archive_run()` already copies reports; extend it to also copy
   `pending_changes.json` if present.

3. `sync_from_remote()` change: after `pull --ff-only`, if the pull fails because the
   branch has diverged, log an error and return `False` (abort, don't merge). Existing
   behaviour is `check=False` on the pull, which silently ignores divergence.

**Tests:** integration test in `tests/test_main_integration.py` (temp-dir fixture,
mocked `BigIPClient`):
- With SoT absent: manifest contains `"status": "NEW"`.
- With matching SoT: manifest contains `"status": "CLEAN"`.
- With differing SoT: manifest contains `"status": "DRIFTED"` and non-zero summary counts.

---

### Step 2.3 — "Review pending changes" interactive screen

**Files touched:** `src/interactive.py`

**Replaces** the Phase 1 stub `screen_review_pending()`.

**Flow:**
1. Load all unresolved `PendingChange` items via `change_workflow.load_pending_changes(repo_dir)`.
2. For each change (sorted: DRIFTED first, then NEW, then CLEAN), display a summary line.
3. Present an action menu: Accept / Reject / View report / Diff / Skip / Quit.
4. **Accept:** `questionary.text()` pre-filled with the default commit message;
   offer `questionary.confirm("Open $EDITOR for a longer message?")`;
   call `change_workflow.accept_change(…)`;
   if `auto_push` is off, print the `git push` command.
5. **Reject:** `questionary.text("Reason:")` → `change_workflow.reject_change(…)`.
6. **View report:** `webbrowser.open(str(change.report_html))`.
7. **Diff:** call `change_workflow.diff_change(change)` → print paginated with
   Python's `pydoc.pager`.
8. **Skip:** advance to the next item.
9. Batch actions at the end of the list:
   - "Accept all NEW (first-run import)" — behind `questionary.confirm(default=False)`.
   - "Accept all DRIFTED from this device" — behind confirm.

---

### Step 2.4 — CLI non-interactive equivalents

**Files touched:** `src/main.py`

**New flags:**

| Flag | Behaviour |
|---|---|
| `--review-pending` | Load and print pending list; exit 2 if any unresolved changes exist |
| `--accept-change <change_id>` | Accept a single change; requires `--message "…"` |
| `--accept-all-clean` | Accept all NEW imports; requires `--yes` |
| `--yes` | Suppress confirmation prompts (CI use) |

These flags are mutually exclusive with the existing `--WAF` / `--BOT` audit triggers
(checked in `_build_parser()`).

**Tests:** `tests/test_cli_phase2.py`
- `--review-pending` with no pending changes → exit 0.
- `--review-pending` with one DRIFTED change → exit 2.
- `--accept-change <id> --message "msg"` → calls `accept_change` exactly once.
- `--accept-all-clean` without `--yes` → error message, no action.

---

### Step 2.5 — `README.md` update for Phase 2

**Files touched:** `README.md`

**Content:** explain the NEW / CLEAN / DRIFTED run lifecycle; transcript of the
review-pending TUI flow (Accept, Reject, Diff); the CLI non-interactive equivalents;
`.auditor-state.json` schema reference; the `pending_changes.json` manifest schema.

---

## Cross-phase constraints (checklist for every PR)

- [ ] No new `Any` return types on public functions.
- [ ] All new public functions have full type hints.
- [ ] `get_logger(…)` used for every new log line; no bare `print()` in library code.
- [ ] `_MaskFilter` coverage: any new log line that formats a dict potentially
      containing credentials has a targeted test.
- [ ] `ensure_dir()` used for every new output directory; no bare `os.makedirs`.
- [ ] No password stored or written to disk (tested in `test_config_manager.py`).
- [ ] `questionary` is the only new dependency; no Textual, Rich, Typer, Click.
- [ ] `lxml` optional: new canonicalization helpers work with the stdlib fallback.
- [ ] Existing CLI flags unchanged and tested end-to-end with the existing fixture set.
- [ ] `--gitlab-*` flags emit a `DeprecationWarning` but remain functional.
