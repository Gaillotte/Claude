# Engine contract

What both engines, the bash `scan_pipeline.sh` and the future Python `scan_pipeline.py`, must honour. It is
written so that someone could implement the Python engine from it, and it was checked against the code and
against real runs (Appendix A). Companion files: `docs/report.schema.json` (the JSON Schema of the raw report),
`tests/conformance/check_schema.py` (validates a real report against it), `docs/engine_divergences.md` (every
place the two engines are allowed to differ), `tests/conformance/conformance.py` and `golden/` (the normalised
comparison).

**Reference engine.** `scan_pipeline.sh` at commit `4b2746b` (`git show 4b2746b:scan_pipeline.sh`, 6,698 lines).
Line numbers written as `L123` below refer to that file. The working-tree script was refactored afterwards (the
embedded Python moved to `transit/`); a clean-fixture report from the refactored script has the same keys, and
`check_schema.py` passes against it.

**The hardened bash engine (2026-11-13).** After the contract was first written, the bash engine was hardened: the
twelve items of the decision record in `docs/engine_divergences.md` (D-003 to D-006, D-008, D-015, D-029, D-031,
D-037, D-038, D-039 and D-042) and thirteen further edits that a review made to them (F1 to F13: `LC_ALL=C`, YARA exit
status, trivy shape check, a NUL byte in the private-key rule, UTF-16 XML, a linear comment strip,
`engine:search_incomplete`, `env -S` shebangs, control files in the nothing-scanned count, the symlink policy and
`zip -y`, `engine:file_listing_failed`, an unreadable ScanCode report, the manifest written through a temporary file,
temporary-file traps), which the owner decided to keep. **This document describes that hardened engine**, and the
golden files in `tests/conformance/golden/` (26 cases) were captured from it.
`git diff c92757d 6091337 -- scan_pipeline.sh fetch_repo.sh ai_transit.sh` shows exactly what changed. Where a
sentence still cites `4b2746b` it is for the shape of a message or the line of a rule, not for behaviour. Each
behaviour that changed is listed in section 11 as *closed*, with what it used to do, so that an older report or an
older note can still be read. The Python engine MUST reproduce the hardened behaviour: an item of the register that is
marked "closed: bash fixed" is no longer a divergence.

## 0. How to read this document

* **MUST** binds both engines. "Bash does X" describes the oracle; it becomes a requirement only where this
  document says MUST. Where the oracle looks wrong, section 11 says so and names a divergence entry (`D-nnn`)
  instead of blessing it.
* **Evidence tags.** `(E7)` was verified by experiment E7 in Appendix A, on this host. `(golden)` is confirmed by
  `tests/conformance/golden/`. `(J)` and `(K)` are pinned by an assertion of Layer J or Layer K of
  `tests/run_tests.sh` (Layer K covers F1 to F7 only). `(E22)` to `(E28)` are experiments run for the catch-up of
  2026-11-13 (Appendix A) on behaviour no assertion pins. `(code)` was read from the reference script and not run,
  with the reason when that matters. `(unverified: why)` could not be checked here.
* **Where it was verified.** bash 5.2.21, GNU grep 3.11, Python 3.11.17, running as root, locale `C.UTF-8`
  (`C` where stated). Of the external scanners only `npm`, `file`, `strings`, `unzip` and `jq` exist on this host.
  gitleaks, semgrep, trivy, scancode, clamscan, yara and detect-secrets were replaced by small stub programs, so
  everything about their real output shape and exit codes is `(unverified: tool not installed)` beyond what the
  stub exercised. Failures that need a non-root user (an unwritable directory) are
  `(unverified: running as root)`. The statements about the hardened engine were checked on the same host on
  2026-11-13 (bash 5.2.21, Python 3.11, running as root, `LC_ALL=C` forced by the script itself).

## 1. Command line

```
scan_pipeline.sh <directory_to_scan> [directory_for_report] [scanning_name]
```

1. **Options do not exist.** Every word that begins with `--` is removed, wherever it appears, including a lone
   `--` and `--quiet` (E4). The remaining words, in order, are positionals 1, 2, 3; positionals after the third
   are ignored (E4). A word with a single leading dash is a positional. A directory literally named `--x` can
   only be scanned as `./--x` (E4). The script does not understand `--min-severity medium` or `--since X`:
   the value becomes a positional and the run stops with `Directory not found: medium` (E18). Behaviour is
   steered by environment variables only (section 2).
2. **Checks, in this order.** All of them happen before the first write to disk (E4).

| # | Condition | stderr message (wording is not contract) | Exit | stdout | Report | Sidecars | `WORK_DIR` created |
|---|-----------|------------------------------------------|------|--------|--------|----------|--------------------|
| 1 | no positional left | `Usage: <$0> <directory_to_scan> [directory_for_report] [scanning_name]  [VERBOSITY=...]` | 1 | empty | no | no | no |
| 2 | positional 1 is not an existing directory (missing, a regular file, or the empty string) | `Directory not found: <value>` | 1 | empty | no | no | no |
| 3 | positional 2 is non-empty and not an existing directory | `Directory not found: <value>` | 1 | empty | no | no | no |
| 4 | positional 3 contains `/`, starts with `.`, contains a control character, or is longer than 150 characters | `scanning_name must not contain '/', control characters or a leading dot, and is limited to 150 characters: <value>` | 1 | empty | no | no | no |

   All four were run (E4). The report directory is never created. A symlink to a directory counts as a directory (E21).
3. **The scanned directory string.** Trailing slashes are removed, except for a lone `/` (E4, golden
   `trailing_slash`). Nothing else is done to it: it is not resolved, `..` is not collapsed, a relative path stays
   relative. This string is `SCAN_DIR`; every path in `file_results` and `findings_by_file` is `SCAN_DIR` + `/` +
   the relative path (E1). The conformance harness only ever passes absolute paths; what a relative one does is
   in section 11 (A19).
4. **`scanning_name`.** Empty or absent means "use the run timestamp" `%Y%m%d_%H%M%S` (local time) (E4). Accepted
   (E4): spaces, `-`, dots after the first character, `..` inside, a name of exactly 150 characters. Refused:
   `a/b`, `.hid`, `..x`, a TAB, 151 characters. Whether the length counts characters or bytes for non-ASCII
   names is `(unverified: no non-UTF-8 locale tested)`. The name decides the report file name only when a report
   directory is given (section 3); it is always stored as `scan_name` in the JSON (E4, `rep_empty`).
5. **Empty strings.** An empty positional 2 is treated as absent (reports go to the default location) while
   positional 3 is still honoured as `scan_name` (E4). An empty positional 3 means "timestamp".

## 2. Environment

Read by `scan_pipeline.sh`:

| Variable | Default | Effect |
|----------|---------|--------|
| `WORK_DIR` | `/opt/ai-transit` | Root for everything the engine writes outside the report directory: `reports/` (default report location), `quarantine/` (mode 700, never used by the engine), `approved/` (never used; D-027), the sidecars, `findings_*.jsonl`, `filelist_*` (the file listing of layer 5), `gitleaks_*` temp directory, `scancode_<ts>.json`. Also where `.diff_files` and `yara-rules/*.yar` are read from, and the base of `OFFLINE_CACHE`. The three sub-directories are created with `mkdir -p` once the arguments are valid (E4, E5). |
| `VERBOSITY` | `normal` | Only the value `quiet` has an effect: it silences `info`/`ok` lines (stdout) and the progress line. `verbose` and any other value behave as `normal` (E5). Warnings and failures on stderr are **not** silenced. With `quiet`, stdout is exactly the verdict line (E5). |
| `MIN_SEVERITY` | `high` | `low`/`medium`/`high`/`critical`, case-insensitive, mapped to a threshold 1/2/3/4. Any other value silently means `high` (E15). An empty value means `high`. Section 6. |
| `SINCE_COMMIT` | unset | Non-empty: diff mode may apply (section 8.6). Unset or empty: a `.diff_files` in `WORK_DIR` is ignored with a stderr WARN that is not recorded in the report (E17). |
| `OFFLINE` | `true` (forced) | Not a switch. Any value other than `true` prints `OFFLINE=<v> ignored: scan_pipeline.sh has no online mode` on stderr; the run proceeds offline, nothing is recorded in the report and `summary.warn` does not change (golden `offline_false_ignored`, D-025). Offline operation means: the child environment gets `SEMGREP_SEND_METRICS=off`, `DO_NOT_TRACK=1`, `CHECKPOINT_DISABLE=1`, `PIP_NO_INDEX=1`; Semgrep reads staged rule files (`--metrics=off`); trivy reads its staged database; pip-audit, safety and npm audit are never run (an `OFFLINE:` WARN when requirement or lock files exist); ScanCode is not given `--vulnerability` (code). |
| `OFFLINE_CACHE` | `$WORK_DIR/offline-cache` | Base of the three staged-data locations below. |
| `SEMGREP_RULES_DIR` | `$OFFLINE_CACHE/semgrep-rules` | Holds `owasp-top-ten.yaml`, `cwe-top-25.yaml`, `security-audit.yaml`, `secrets.yaml` (E10) for layer 2, and `javascript.yaml` for the per-file JavaScript analysis of layer 5 (D-037, J). `prepare_offline_cache.sh` stages all five. Without `javascript.yaml` that analysis does not run and layer 5 is `partial` (section 7). |
| `TRIVY_CACHE_DIR` | `$OFFLINE_CACHE/trivy-db` | Must contain `db/*` for trivy to run (E11). |
| `CLAMAV_DB_DIR` | `$OFFLINE_CACHE/clamav` | `*.cvd`/`*.cld` here, or in `/var/lib/clamav`, else the layer is marked skipped (E11). |
| `RUN_SCA` | `false` | Exactly the string `true` enables layer 3 (case-sensitive; `1` and `TRUE` do not) (code; golden `layers_on`). Disabled: coverage `skipped:disabled (RUN_SCA is not true)`. Also adds `SCA-CVE` to `standards`. |
| `RUN_SCANCODE` | `false` | Same for layer 6; adds `ScanCode-Licence-Copyright` to `standards`. |
| `REPO_INPUT` | empty | Copied verbatim to the report key `repo_input` (E4). |
| `TMPDIR` | `/tmp` | Base for `aitransit_*` view files and the report-data temp directory (section 3.5). |
| `JAR_MAX_ENTRIES` / `JAR_READ_BUDGET_MB` / `JAR_VIEW_MB` / `JAR_MAX_UNCOMPRESSED_MB` / `JAR_TIME_BUDGET_S` | 50000 / 64 / 32 / 1024 / 90 | Limits of the Java archive scanner. |
| `OFFICE_MAX_ENTRIES` / `OFFICE_READ_BUDGET_MB` / `OFFICE_TIME_BUDGET_S` | 20000 / 256 / 90 | Limits of the office-document scanner. A comment above `scan_office` (L2488-L2490) says 64 MB; the code (L2529) and CLAUDE.md say 256, and 256 governs. |
| `LC_ALL` | forced to `C` | The script exports `LC_ALL=C` before it does anything else, whatever the caller set (K, F1). Every rule is ASCII and is meant to see bytes: in a UTF-8 locale GNU grep's `.` and `[^x]` do not match an invalid byte, so one 0xFF in a line stopped a line-spanning rule such as curl-pipe-bash from matching it, and a file with an encoding error became "binary" to the plain greps. The consequences are that `grep` and `sort` work on bytes (`repo_hash` sorts byte-wise) and that the console sanitiser sees the two bytes of a C1 control (S1). The Python engine matches bytes and sorts byte-wise, which is the same thing. |
| `PATH` | environment | Tools are found with `command -v` at run time. |

The `JAR_*` and `OFFICE_*` values are parsed as floats; a value that is not a number or is not above 0 means the
default; entry counts and byte budgets are truncated to integers (code, L1838-L1852, L2519-L2530). Each limit
that is reached becomes a WARN (`jar:inspection_incomplete(...)`, `office:inspection_incomplete(...)`, and for
the declared-size limit `jar:declared_uncompressed_size_over_limit(...)`). The office helper also arms a
`SIGALRM` at the time budget plus 10 s so that one runaway pattern is interrupted (code). Fixed caps that are
not environment-tunable: jar entry 4 MB, nested archive 16 MB, nesting 2; office part 8 MB, slice 4 MB, embedded
container 32 MB, view 32 MB, nesting 3 (code).

Read by `ai_transit.sh` or `fetch_repo.sh` only, not by the engine: `OUTPUT_DIR`, `GITHUB_TOKEN`, `MAX_SIZE_MB`.
`ai_transit.sh` passes the engine exactly `REPO_INPUT`, `WORK_DIR`, `VERBOSITY`, `MIN_SEVERITY`, `OFFLINE=true`
and `SINCE_COMMIT` (code, `ai_transit.sh` L127-L129). The `REPORT_*` variables the shell hands to its report
helper are internal, not contract. The environment of the gitleaks child has `GITLEAKS_CONFIG` and
`GITLEAKS_CONFIG_TOML` removed (section 9, S8).

## 3. Outputs

### 3.1 Console channels

| Helper | Channel | `quiet` | Sanitised |
|--------|---------|---------|-----------|
| `info`, `ok` | stdout, prefix `[INFO]  ` / `[OK]    ` | suppressed | yes |
| `warn` (also used by `record_warn`) | stderr, `[WARN]  ` | **not** suppressed | yes |
| `fail_f` (also used by `record_fail`) | stderr, `[FAIL]  [<file>] <message>` | **not** suppressed | yes |
| `fail` | stderr, `[FAIL]  `, then `exit 1` | not suppressed | yes |
| progress line `[L5]  [n/total] path` | stderr, only when stderr is a terminal | suppressed | yes (see below) |

"Sanitised" means every control byte of the message is replaced by `?` (section 9, S1) (E13). The wording of
these lines is not contract (section 10).

The progress line carries a file name, which is repository text, so it is sanitised too: the Python engine MUST
sanitise it and then cut it to 80 characters (R-10 of the design review). The bash engine prints it raw (code, L6323 to
L6325 of the reference script, unchanged by the hardening), so a name with an escape sequence can still drive the
terminal while a bash run is in progress on a terminal. In the C locale the bash sanitiser replaces a C1 control
(U+0080 to U+009F, which a UTF-8 terminal obeys; U+009B is a CSI) as the pair of bytes `C2 80` to `C2 9F`, one `?` for
the pair, and prints every other two-byte character unchanged (K, F1).

### 3.2 Last stdout line and exit status

On a run that reaches the end, the last stdout line is exactly `PASS` or `FAIL` (E5). Anything else is an abort.

| Situation | Last stdout line | Exit | Report files | Sidecars |
|-----------|------------------|------|--------------|----------|
| Completed, verdict PASS (WARNs allowed) | `PASS` | 0 | yes | yes |
| Completed, verdict FAIL | `FAIL` | 1 | yes | yes |
| Argument refused (section 1) | none | 1 | no | no |
| Aborted after validation, e.g. `WORK_DIR` cannot be created (E5) | an `[INFO]`/`[OK]` line, **not** a verdict | 1 | no | no |
| bash older than 4 | none | 1, `[ERROR] bash 4+ required` on stderr | no | no |
| Killed by a signal | none | 128+n | no | no |

`(code)` for the last two rows; the abort rows were run. A partially staged Semgrep rule set used to be an abort row
too (A5); since D-005 the run completes (J). A caller MUST treat a missing verdict line, and a
missing sidecar, as FAIL: `ai_transit.sh` does (`VERDICT=$(cat .scan_verdict || echo FAIL)`). What the Python engine does on an internal error is D-028. No other exit
status is produced by a normal run. The exit status never distinguishes WARN from PASS.

### 3.3 Sidecar files

Both are written to `${WORK_DIR}/`, never to the report directory, even in three-argument usage (E4).

| File | Content | Written |
|------|---------|---------|
| `.scan_verdict` | `PASS` or `FAIL` followed by one newline (E4) | after both reports exist |
| `.scan_report_json` | the path of the JSON report, as constructed (`<report_dir>/report_scan_<name>.json`, or `<WORK_DIR>/reports/report_<ts>.json`), followed by one newline; a relative `report_dir` stays relative (E4) | immediately after `.scan_verdict` |

Order at the end of a run: JSON report, HTML report, `.scan_verdict`, `.scan_report_json`, the verdict on stdout,
then `exit 1` unless PASS. The bash engine does not remove the sidecars at the start; stale ones from an earlier run
survive an aborted run (code). `ai_transit.sh` deletes `.fetch_result`, `.diff_files`, `.scan_verdict` and
`.scan_report_json` (and, since the hardening, the `.diff_files.*` and `.manifest.*` temporaries of a fetch that was
killed) before every run for that reason (code). **The Python engine removes both sidecars right after the report
directories exist, so no earlier run's sidecar survives an aborted run (D-040).** Two runs sharing one `WORK_DIR` at
the same time overwrite each other's sidecars `(unverified: not run)`.

### 3.4 Report files

* Three-argument usage with a non-empty `directory_for_report`: `<report_dir>/report_scan_<name>.json` and
  `<report_dir>/report_scan_<name>.html` (E4). A name with a space is kept (E4).
* Otherwise (one argument, or an empty report directory): `<WORK_DIR>/reports/report_<TS>.json` and `.html`,
  where `<TS>` is the local time `%Y%m%d_%H%M%S` at script start (E4). Two runs in the same second overwrite each
  other (A21).
* The HTML file always has the same stem as the JSON file (`ai_transit.sh` derives it with `${REPORT_JSON%.json}.html`).
* The JSON file is written to `<report>.tmp` and renamed into place, so a failed write cannot leave a truncated
  report (code). An existing report of the same name is replaced without a message.
* **HTML content.** Not compared byte for byte. It MUST contain: the verdict; the scanned directory; the three
  counters; one row for every entry of `file_results` with the path, the status and the message; and every path,
  message and the directory HTML-escaped (section 9, S3). The reference markup is a dark table page titled
  `AI Transit Report — <TS>` with `<h1>Verdict: <V></h1>`, a `Directory: <code>…</code> | Date: <TS>` line and rows
  `<tr><td><code>path</code></td><td class='pass|warn|fail'>STATUS</td><td>message</td></tr>`. It has no coverage
  block and no finding records (code, L6619-L6659).

### 3.5 Temporary files

| Created | Where | Removed |
|---------|-------|---------|
| `findings_XXXXXX.jsonl`, one JSON object per FAIL, folded into the report at the end | `$WORK_DIR` | by an `EXIT` trap, also after an abort (E10: absent after the abort) |
| `filelist_XXXXXX`, the NUL-separated listing of layer 5 (its exit status is read, 8.5) | `$WORK_DIR` | right after it is read, and by the `EXIT` trap if a signal ends the run (code) |
| `gitleaks_XXXXXX/` holding the generated config, an empty ignore directory and the gitleaks report | `$WORK_DIR` | `rm -rf` right after gitleaks returns; **not** after an abort (code) |
| `aitransit_{jar,office,pdf,pdfn,bat,xml}_XXXXXX` text views | `$TMPDIR` | at each scanner's exit point; none were left after a 362-file corpus run (E16). The XML view is also removed by the `EXIT` trap when a signal ends the run (K, F5) |
| a `mktemp -d` directory with the NUL-delimited streams for the report builder | `$TMPDIR` | by a `RETURN` trap; none left (E16) |
| `<report>.json.tmp` | report directory | renamed into place |
| `scancode_<ts>.json`, the ScanCode result | `$WORK_DIR/reports/` | **kept** (only with `RUN_SCANCODE=true`) |

After the 362-file corpus run `TMPDIR` was empty and `WORK_DIR` held only `reports/`, `approved/`, `quarantine/`
and the two sidecars (E16). The Python engine MUST create temporary files with unpredictable names and mode 0600,
and MUST remove them on every exit path including an abort (S16).

### 3.6 What the callers read

* `ai_transit.sh`: the two sidecars; `.verdict`, `.summary.pass`, `.summary.warn`, `.summary.fail` and
  `.findings_by_file` of the report (through `jq`, with a control-byte filter); on FAIL it opens the newest
  `<WORK_DIR>/reports/report_*.json`, not the sidecar's path. It passes one argument, so the report is always at
  the default location (code).
* `generate_excel_report.py` reads `repo_input`, `directory`, `timestamp`, `repo_hash`, `verdict`, `summary.*`
  and, per entry of `file_results`, `status` and `message`. It splits `message` on `" | "`, reads the `[FAIL]`
  or `[WARN]` tag at the start of each piece and derives a severity from `:CRITICAL:` or `:MEDIUM:` inside it. It
  strips the `directory` prefix from the keys, so **every `file_results` key must be `__global__`, the directory,
  or start with `directory + "/"`** (invariant in `check_schema.py`). It lists only files whose status is FAIL
  or WARN (this hides an `ALLOWED` message on a PASS file, A12).

## 4. The JSON report

The report is a single JSON object, UTF-8, written with Python's `json` (the bash engine uses `indent=2`,
`ensure_ascii=False`, a trailing newline; none of that is contract). **Ordering of keys, of array elements and of
object members is not part of the contract.** `docs/report.schema.json` is the machine-readable form and uses only
`type`, `properties`, `required`, `additionalProperties`, `items`, `enum`, `pattern` and `minimum`. Every key is
present in every report written by a completed run; no key is optional at the top level.

| Key | Type | Meaning |
|-----|------|---------|
| `verdict` | string `PASS` \| `FAIL` | Never `WARN`. |
| `decision` | string `APPROVED` \| `REJECTED` | `APPROVED` exactly when `verdict` is `PASS`. |
| `status_color`, `status_background` | strings `#RRGGBB` | PASS `#198754` / `#D1E7DD`, FAIL `#B02A37` / `#F8D7DA`. |
| `scan_name` | string | Positional 3, or the run timestamp. |
| `source.directory` | string | `SCAN_DIR` as given (section 1.3). Dropped by the conformance normaliser. |
| `source.sha256` | 64 lower-case hex | Content hash, **compared by the conformance harness** (it is in every golden file). See below. |
| `coverage` | object | Layer id to state (section 7). Nine ids, **all nine present in every report written by a completed run**: the hardened bash engine records `L1_ioc_yara` and `L6_licence` in every case (it used to leave them out: A6, A8, closed by D-006 and D-008). The Python engine MUST record all nine too (golden: every case). |
| `coverage_complete` | boolean | True when no state differs from `ran`. |
| `coverage_gaps` | array of strings | The layer ids whose state does not start with `ran`, sorted. |
| `timestamp` | string `YYYY-MM-DDTHH:MM:SSZ` | UTC. Dropped by the normaliser. |
| `repo_input` | string | `REPO_INPUT`, or empty. Dropped by the normaliser. |
| `directory` | string | Equal to `source.directory`. Dropped by the normaliser. |
| `repo_hash` | 64 lower-case hex | `sha256` of `find "$SCAN_DIR" -type f \| sort` (path list with the directory prefix, newline-terminated, sorted byte-wise because the script runs in the C locale). Depends on the location, so it is dropped by the normaliser. |
| `standards` | array of strings | `OWASP-Top10-2021`, `CWE-Top25`, `CERT-Secure-Coding`, then `SCA-CVE` if `RUN_SCA=true`, then `ScanCode-Licence-Copyright` if `RUN_SCANCODE=true`, then `PDF-Active-Content`, `Build-Script-Hardening`, `HTML-Active-Content`, `XML-Build-Hardening`, `Package-Manifest-Integrity`, `Gradle-Build-Hardening`, `Install-Time-Python`, `Known-Credential-Formats`, `PowerShell-Hardening`, `Windows-Batch-Hardening`, `Java-Archive-Hardening`, `Office-Document-Hardening`. As a set, it is compared. |
| `summary.pass`, `.warn`, `.fail` | integers ≥ 0 | **Event counters, not file counts** (section 6, A13). |
| `findings` | array of records | One per FAIL that survived the allowlist and `--min-severity`. Record fields below. |
| `findings_by_file` | object path → string | The FAIL messages of the file joined with `" \| "` (no trailing separator). Key is `SCAN_DIR/relative`, or `SCAN_DIR` for a whole-directory finding, or `__global__` for a finding about the scan itself (the `engine:` family, section 5.1). |
| `file_results` | object path → `{status, message}` | `status` is `PASS`, `WARN` or `FAIL`. `message` is the file's `[WARN] …` / `[FAIL] …` messages joined with `" \| "`, empty for a clean PASS. Keys: every scanned file, the pseudo-entry `__global__` (missing tools, offline notes, the exclusions WARN, the `engine:` FAILs about the whole scan), and `SCAN_DIR` itself (whole-directory results). A symlink is a key too (section 8.5). |

**`findings[]` record** (all ten fields always present; E6, golden):

| Field | Type | Value |
|-------|------|-------|
| `tool` | non-empty string | See the derivation table in section 5.3. |
| `category` | `security` \| `sast` \| `secret` \| `malware` \| `ioc` \| `cwe` \| `owasp` | |
| `severity` | `INFO` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` | From the one classifier (section 6.3). |
| `rule_id`, `rule_name` | strings | |
| `file` | non-empty string | **Relative** to `SCAN_DIR`; `.` for a whole-directory finding; `__global__` for a finding about the whole scan (the `engine:` messages recorded there); unchanged (so absolute) if the file does not sit under `SCAN_DIR/` (E7). |
| `line` | integer ≥ 0 or null | From `:line<digits>` in the message. |
| `column` | integer or null | Always null today. |
| `message` | non-empty string | The message exactly as passed to `record_fail`. |
| `references` | array of strings | `["CWE-798"]` for gitleaks and detect-secrets, `["CWE-n"]` for `CWE-n:` messages, otherwise empty. |

**`source.sha256`.** The SHA-256 of the output of
`cd "$SCAN_DIR" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum`: one line per regular file,
`<64 hex>  <./relative path>` (two spaces), paths sorted byte-wise, symlinks excluded, **no directory excluded**
(`.git` and `node_modules` count). Falls back to `repo_hash` if the pipeline fails. A file whose name contains a
backslash or newline gets `sha256sum`'s escaped form `\<hash>  <escaped name>`; not run
`(unverified: no such name hashed; taken from the sha256sum format)`. An independent Python recomputation matched
the golden value of all three fixtures (E19).

**Invariants JSON Schema (in this subset) cannot state.** `check_schema.py` enforces them on every report:
`decision` and the two colours follow `verdict`; `coverage_gaps` is exactly the sorted list of layers whose state
does not start with `ran`, and `coverage_complete` is its emptiness; `directory` equals `source.directory`;
`summary.fail` equals `len(findings)`; a PASS has no findings and no FAIL file; every `findings_by_file` key is a
`file_results` entry with status FAIL; every `file_results` key is `__global__`, the directory or under it; a FAIL
status has a `[FAIL]` message and a WARN status a `[WARN]` message; every finding's message appears in
`findings_by_file` for its file (a finding whose `file` is `.` is looked up under the directory, one whose `file` is
`__global__` under `__global__`). One invariant does **not** hold in the bash engine and is deliberately not
checked: "a FAIL verdict has at least one FAIL file" (A7).

**Encoding.** A file name that is not valid UTF-8 appears in `file_results`, `findings_by_file` and
`findings[].file` with each invalid byte replaced by U+FFFD (golden `hostile_non_utf8_name`); two different
invalid names can therefore collide on one key (A23). Control characters in names are JSON-escaped (golden
`hostile_escape_name`).

**Conformance normalisation** (`conformance.py:normalize`): drops `timestamp`, `directory`, `repo_hash`,
`repo_input`, `source.directory`; makes paths relative (the scanned directory is removed, the work directory is
written `<WORK>`, the name of the ScanCode result `scancode_<TS>.json`); sorts `coverage_gaps`; splits each `message` on
`" | "` and compares the sorted pieces; sorts `findings` by (file, rule_id, line, message); compares `findings[]` fields
except `column`. The raw report is the contract; the normalised one is only how two raw reports are compared.

**Accepted divergences of the Python engine.** For `--engine python` only, `conformance.py` applies the table
`PYTHON_ACCEPTED_DIVERGENCES` to the normalised report before it is compared with the bash golden (or with the live
bash report, for `diff`). An entry names a divergence of the register, the cases it applies to, one `file_results` entry
and one message prefix, so it can drop that message and lower `summary.warn` by one and nothing else; an entry that
matches nothing in a case it names is itself a failure (the divergence is closed: delete the entry). **The table is
empty.** The design (section 14.1, WP-13) asked for one entry, for the WARN `transitignore:exclusions_applied(` of D-004,
because bash could not produce it; the hardened bash engine does, and `golden/ignored.json` and the two
`transitignore_*` goldens carry it, so the Python engine is compared with the goldens exactly.

## 5. Finding messages

A message is the string passed to `record_fail` / `record_warn`. Tests, the allowlist, the severity classifier and
the structured-record builder all match on these strings, so they are contract. Stored as
`[FAIL] <message>` or `[WARN] <message>` in `file_results[*].message`, joined by `" | "`; FAIL messages without the
tag are joined the same way in `findings_by_file`.

### 5.1 Grammar per producer

`<N>` is an integer, `<SEV>` a severity word, `{x}` text that varies. Messages are shown as stored.

| Producer | Shape | Notes |
|----------|-------|-------|
| gitleaks (L1) | `gitleaks:<rule>:line<N>` | `<rule>` is `RuleID` with `:` replaced by `_` (E7); `line` with no digits if gitleaks gave no `StartLine`. Whole-directory: `gitleaks:secrets_detected` (exit 1 and no readable report), `gitleaks:scan_error_exit_<rc>` (exit ≥ 2), `gitleaks:more_leaks_not_listed_<n>` (more than 200 leaks; `<n>` = total − 200). Cap: 200 per-leak records. |
| detect-secrets (L1) | `detect-secrets:<N>_high_entropy_string(s)` | against `SCAN_DIR`. WARN on `__global__`: `detect-secrets:scan_error_exit_<rc>` (exit other than 0), `detect-secrets:output_could_not_be_read` (stdout is not a JSON object with a `results` object); what a failed run printed and could be read is still acted on (J, D-015). |
| ClamAV (L1) | `clamav:malware_detected` | against `SCAN_DIR`; **only exit 1** of `clamscan` produces it. Exit 0 is clean; any other exit is clamscan failing: WARN `clamav:scan_error_exit_<rc>` on `__global__`, no finding (J, D-015; it was A15). |
| YARA (L1) | `yara:ioc_match:<rule file basename>` | against `SCAN_DIR`, once per rule file with output, whatever that yara's exit status. WARN on `__global__`: `yara:scan_error_exit_<rc>:<rule file basename>` for each rule file whose yara run exited non-zero (a syntax error in the rule, a crash), and `yara rules directory has no .yar files — IOC scan skipped` (no colon) when the directory exists but is empty (K, F2; J, D-008). |
| Semgrep (L2) | `semgrep[<ruleset>]:<check_id>:line<N>:<SEV>:<message, at most 120 chars>` | `<SEV>` is Semgrep's `ERROR`/`WARNING`/`INFO` (default `INFO`). Because offline is the only mode, `<ruleset>` is the **absolute path of the staged YAML file**, not `p/owasp-top-ten` (E10, A18). One record per ruleset, so a rule hit by two rulesets appears twice (E10). WARN on `__global__`, one per rule set that failed: `semgrep:scan_error_exit_<rc> (<rule file name>)` (exit other than 0 and 1) and `semgrep:output_could_not_be_read (<rule file name>)` (stdout is not a JSON object whose `results` is a list), where `<rule file name>` is the file name only, e.g. `owasp-top-ten.yaml`; the findings of the other rule sets are kept (J, D-015). |
| Semgrep per file (L5) | `semgrep:js:<N>_findings` | `.js .ts .jsx .tsx .mjs .cjs` only, when `semgrep` exists **and** `$SEMGREP_RULES_DIR/javascript.yaml` is staged; the rule set is that file, never a registry name (D-037, J). Semgrep missing: WARN `semgrep missing` on the file. Staged file missing: Semgrep is not run on the file, one WARN `OFFLINE:semgrep javascript rule set not staged in <dir> — per-file JavaScript SAST did NOT run; …` on `__global__` for the whole run, and layer 5 is `partial` (section 7). Semgrep failing on the file: WARN `semgrep:js:scan_error_exit_<rc>` (exit other than 0 and 1) or `semgrep:js:output_could_not_be_read` on the file, and layer 5 is `partial`. |
| trivy (L3) | `trivy:<N>_vulnerable_dependencies` | against `SCAN_DIR`. WARN on `__global__`: `trivy:scan_error_exit_<rc>` (exit other than 0), `trivy:output_could_not_be_read` (stdout is not a trivy document: a JSON object with `SchemaVersion` or `Results`, `Results` a list of objects whose `Vulnerabilities`, if present, is a list) (K, F3; J, D-015). |
| pip-audit, safety, npm audit (L3) | `pip-audit:<N>_CVEs_in_dependencies`, `safety:vulnerable_python_dependency`, `npm-audit:<N>_vulnerable_packages` | **Unreachable today**: with offline forced they are replaced by an `OFFLINE:` WARN (code, A24). |
| bandit | `bandit:Severity: <LEVEL>:<test id>` | `<LEVEL>` MEDIUM or HIGH. Real bandit `(unverified: not installed)`. |
| cppcheck | `cppcheck:<error\|warning>: <text>` | first match only. |
| shellcheck, hadolint, checkov | `shellcheck:warnings`, `hadolint:dockerfile_issue`, `checkov:<N>_CIS_IaC_findings` | |
| grep rules | `CWE-<n>:<snake_case_description>`, `OWASP-A<nn>:<description>`, `CVE-2021-44228:Log4Shell_JNDI_injection` | the bulk of the rules. `CWE-798:known_credential_format_<provider>` for the 18 provider formats. |
| jar / office FAIL | `CWE-<n>:<description>(<count>[: <detail>[; <detail>…]])` | e.g. `CWE-22:jar_entry_path_traversal_zip_slip(1: ../x)`. The vocabularies are the `fail_map` tables at L2388 and L4332. |
| jar / office / odf / rtf WARN | `jar:<description>(…)`, `office:<description>(…)`, `odf:…`, `rtf:…` | `warn_map` tables at L2415 and L4363. `<detail>` is sanitised (S7). |
| pdf | `CWE-<n>:PDF_<description>`; WARN `pdf:<description>`, `pdf:stream_filter_not_decoded(<filter,filter>)_those_streams_were_not_inspected` | |
| other scanners | `<scanner>:<description>` | `pkg`, `npm`, `composer`, `pip`, `setup`, `cmake`, `html`, `make`, `maven`, `ant`, `bat`, `powershell`, `shell`, `crypto`, `binary` (`binary:unexpected_executable_mime:<mime>`), `archive`. |
| ScanCode (L6) | WARN `licence:<spdx>`; FAIL or WARN `scancode_vuln:<id>[<SEV>] in <pkg>==<version>`; WARN `scancode:scan_error — check <path>`, `scancode:no_report_generated`, `scancode:python3_missing — cannot parse report`, `scancode:report_could_not_be_read` | `[SEV]` is in brackets, so it is **not** a severity marker (section 6.3). The report of an earlier run with the same timestamp is removed before ScanCode starts, so it cannot pass for this run's. `scancode:report_could_not_be_read`: the report exists but the reader exited non-zero (not JSON, JSON of the wrong shape, ScanCode killed while it wrote) (E25). |
| missing tool | `<tool> missing[ — <hint>]`, no colon | `gitleaks`, `detect-secrets`, `clamscan`, `yara or rules directory missing`, `semgrep`, `trivy`, `pip-audit/safety`, `npm`, `scancode`, and per file `bandit`, `cppcheck`, `shellcheck`, `hadolint`, `checkov`. Recorded on `__global__` for layer tools and on the file for per-file tools. |
| offline notes | `OFFLINE:<free text>` | WARN on `__global__`. |
| engine notes | `gitleaks:inline_allow_comments_not_disabled (…)`, `gitleaks:repository_allowlist_ignored (…)` | WARN. |
| exclusions | WARN `transitignore:exclusions_applied(<n> pattern(s))` | on `__global__`, whenever `.transitignore` yields at least one pattern; `<n>` is that number and nothing else from the file is in the message (D-004, J). |
| symlinks | FAIL `symlink:target_outside_the_scanned_directory`; WARN `symlink:not_followed_its_target_is_not_scanned_through_the_link` | on the link itself, from `find -type l` over the same prune arguments as the file listing; section 8.5 (code; E22). Both go through `record_fail` / `record_warn`, so the FAIL can be allowlisted (rule `symlink` or `target_outside_the_scanned_directory`, path the link's relative path) and lowered by `--min-severity` like any other. |
| the scan itself (`engine:`) | FAIL `engine:nothing_scanned`, FAIL `engine:file_listing_failed`, FAIL `engine:search_incomplete` | no detail segment; `engine:nothing_scanned` and `engine:file_listing_failed` on `__global__`, `engine:search_incomplete` on the file whose search could not finish, once per file. **Never allowlisted and never lowered by `--min-severity`** (section 6.2). Section 8 says when each is recorded. The Python engine adds further `engine:<kind>[:<detail>]` messages for its own failures (a scanner that raised, a file that could not be read, an unlistable directory, a time budget); they follow the same rules and are listed in `docs/python_engine_design.md` section 8.3. |
| allowlist | `ALLOWED:<original message> (reason: <reason>)` | WARN, replaces the FAIL (section 6.2). |
| min-severity | `LOW_SEV(below --min-severity <MIN_SEVERITY>):<original message>` | WARN, replaces the FAIL; `<MIN_SEVERITY>` is printed as given, not normalised (section 6.3). |

### 5.2 Rule-id prefixes that exist today

Found by extracting every `record_fail` / `record_warn` call and every `fail_map` / `warn_map` entry of the
reference script (the extraction script is in Appendix A, E20).

* **`CWE-<n>:`** (40 values, FAIL and/or WARN): 22, 78, 79, 88, 89, 94, 95, 119, 120, 134, 190, 200, 250, 295,
  319, 321, 326, 327, 338, 377, 415, 426, 494, 502, 506, 522, 601, 611, 693, 703, 732, 776, 798, 829, 912, 915,
  918, 1021, 1188, 1321.
* **`OWASP-A02:`, `OWASP-A05:`, `OWASP-A08:`, `OWASP-A09:`** and **`CVE-2021-44228:`**.
* **Tool prefixes:** `gitleaks`, `detect-secrets`, `clamav`, `yara`, `semgrep`, `trivy`, `pip-audit`, `safety`,
  `npm-audit`, `bandit`, `cppcheck`, `shellcheck`, `hadolint`, `checkov`, `scancode`, `scancode_vuln`, `licence`.
* **Scanner prefixes:** `jar`, `office`, `odf`, `rtf`, `pdf`, `pkg`, `npm`, `composer`, `pip`, `setup`, `cmake`,
  `html`, `make`, `maven`, `ant`, `bat`, `powershell`, `shell`, `crypto`, `binary`, `archive`.
* **Meta prefixes:** `ALLOWED:`, `LOW_SEV(…):`, `OFFLINE:`, `engine:` (a message about the scan itself, produced by the
  engine and never from repository text; section 5.1), `transitignore:` (the exclusions WARN), and `symlink:`.
* **Free-text (no colon):** the `<tool> missing …` family, and `yara rules directory has no .yar files — IOC scan
  skipped`.

A new rule MUST use an existing prefix or add its own to this list; the full text of each message is the
reference script's source and `tests/conformance/pattern_inventory.py`. The Python engine MUST emit identical
strings for the same rule (the tests assert on them, for instance `CWE-89:SQL_injection_…`).

### 5.3 How the structured record is derived from the message

`_emit_finding` (L323-L374) derives `tool`, `category`, `rule_id`, `rule_name` and `references` from the message
text, first match wins. Run against the real function (E6):

| Message starts with | tool | category | rule_id | rule_name | references |
|---------------------|------|----------|---------|-----------|------------|
| `semgrep[` | `semgrep` | `sast` | text between `]:` and the next `:` | the whole message | |
| `detect-secrets:` | `detect-secrets` | `secret` | `high_entropy_string` | `High Entropy String` | `CWE-798` |
| `clamav:` | `clamav` | `malware` | text after `clamav:` | `Malware Detected` | |
| `gitleaks:` | `gitleaks` | `secret` | between `gitleaks:` and next `:` | `Secret Detected` | `CWE-798` |
| `yara:` | `yara` | `ioc` | text after `yara:` | `IOC Match` | |
| `bandit:` | `bandit` | `sast` | text after the **second** colon | `Bandit Finding` | |
| `cppcheck:` / `shellcheck:` | same | `sast` | text after the prefix | `Cppcheck Finding` / `ShellCheck Finding` | |
| `CWE-*:*` | `grep-pattern` | `cwe` | `CWE-<n>` | text after the first colon | `["CWE-<n>"]` |
| `OWASP-*:*` | `grep-pattern` | `owasp` | `OWASP-A<nn>` | text after the first colon | |
| `^[a-z][a-z0-9_-]{1,30}:[^:]+` | the prefix | `security` | text up to the next colon, or to the end of the message | the whole message | |
| anything else (e.g. `CVE-2021-44228:…`) | `unknown` | `security` | empty | the whole message | |

Consequently `engine:nothing_scanned` has tool `engine`, category `security`, rule id `nothing_scanned`, rule name
`engine:nothing_scanned`, severity HIGH and `file` `__global__` (golden `transitignore_everything`), and
`symlink:target_outside_the_scanned_directory` has tool `symlink` (E22). A WARN has no record.

`line` is the integer after the first `:line` anywhere in the message. `severity` is section 6.3. The `file` field
is `file` with `SCAN_DIR/` removed, or `.` when `file` is `SCAN_DIR`. The Python engine MUST produce the same
`tool`, `category`, `severity`, `file`, `line` and `message` for the same finding; where this table is plainly
wrong (`bandit` rule id, `CVE-…` tool) the register decides (A16, D-016).

## 6. Verdict and severity

### 6.1 The three states

* `GLOBAL_VERDICT` starts `PASS` and flips to `FAIL` on the first `record_fail` that survives sections 6.2 and 6.3.
  It never flips back. WARN never changes it (E9, E10).
* Per file (`FILE_STATUS`): `record_fail` sets `FAIL` unconditionally. `record_warn` sets `WARN` **only if the file
  has no status yet**. `record_pass` sets `PASS` only if the file has no status yet. Consequence: a file whose
  first event was a PASS and whose later event is a WARN stays `PASS` while carrying a `[WARN]` message (E12, A12).
* Messages accumulate as `[TAG] <message> | `. `record_pass` adds no message.
* Counters (`summary`): `record_pass` always increments `pass`, even when the file already has a WARN or FAIL
  status; `record_warn` increments `warn` once per call; `record_fail` increments `fail` once per surviving FAIL.
  A file with six events counts six times. The clean fixture has 2 PASS files and `summary.pass` = 4 (golden
  `clean`).
* A FAIL or WARN is mirrored on stderr.

### 6.2 `record_fail`, step by step

1. `rel_path` = file with a leading `SCAN_DIR/` removed; unchanged otherwise (so for a whole-directory finding it
   is `SCAN_DIR` itself).
2. **Allowlist.** Two tokens are tried in order: the text before the first `:` of the message, then the text
   between the first and second `:` (for a message with no colon both are the whole message). For each token the
   key `<token>::<rel_path>` is looked up. The first hit with a **non-empty** reason ends the step:
   `record_warn(file, "ALLOWED:<message> (reason: <reason>)")`, no FAIL, no record, no verdict change. So
   `CWE-798` matches `CWE-798:hardcoded_credential`, and so does `hardcoded_credential` (E3); `gitleaks` alone
   matches every gitleaks finding for that path; for `semgrep[…]:<check_id>:…` the second token is the check id.
3. **Threshold.** The message is classified (6.3). If its number is below the threshold:
   `record_warn(file, "LOW_SEV(below --min-severity <MIN_SEVERITY>):<message>")`, and stop (E9). The allowlist is
   consulted before the threshold (E21: a Semgrep `INFO` finding that is allowlisted gets `ALLOWED:`, not `LOW_SEV(…)`).
4. Otherwise: write the structured record, append to `FINDINGS`, set the status `FAIL`, append `[FAIL] <message> | `,
   `FAIL_COUNT++`, print on stderr, set `GLOBAL_VERDICT=FAIL`.

**The `engine:` family skips steps 2 and 3.** A FAIL about the scan itself (`engine:nothing_scanned`,
`engine:file_listing_failed`, `engine:search_incomplete`; the Python engine's own `engine:` kinds too) is recorded by
`record_fail_hard`, which goes straight to step 4: it is never looked up in the allowlist and never compared with the
threshold. The repository controls `.transit-allow.json` and the operator controls `--min-severity`, and neither may turn
"nothing was examined" into a pass (K, F6; E23, which also ran `MIN_SEVERITY=critical` with an allowlist entry for the
rule and the file). A message starting `engine:` that arrives through `record_fail` (the Python engine's `Verdict`, a
wrapper) is treated the same way: the Python engine MUST NOT let `engine:` be allowlisted or lowered.

**`.transit-allow.json`** is read from the root of the scanned directory. It is a JSON array of objects with
string members `rule`, `path`, `reason`.

* Matching is exact string equality: `rule` against a token (case-sensitive: `cwe-798` does not match), `path`
  against `rel_path` (no glob, no `./`, no absolute path) (E3).
* An entry whose `reason` is missing or empty is never used (E3).
* A JSON document that is not an array, or does not parse, yields an empty allowlist without any message (E3).
* An entry with a non-string `rule`, `path` or `reason` (a number, `null`) is dropped, **and so is every entry after
  it** (E3). A `reason` containing a newline is cut at the newline (E3). Both are accidents (A10).
* Entries are only ever read from the scanned repository itself, which the repository's author controls. The
  `ALLOWED:` WARN with the reason is the audit trail.

### 6.3 One severity classification

`_classify_severity` (L270-L294) is the only place a message becomes a severity; the threshold check and the
record's `severity` both use it, so they cannot disagree. Numbers: INFO and LOW = 1, MEDIUM = 2, HIGH = 3,
CRITICAL = 4. Run against the real function on 23 messages (E6):

1. A message starting with `gitleaks:` or `clamav:` is CRITICAL.
2. A message starting with `semgrep[` is classified from the fixed position `semgrep[…]:<rule>:line<N>:<WORD>:`
   only, never from the free text after it: `ERROR` and `HIGH` are 3, `WARNING` is 2, `INFO` is 1, `CRITICAL` is 4,
   an unknown word is HIGH. Text such as `:LOW:` quoted from the repository cannot downgrade it (E6).
3. Every other message is searched, case-insensitively, anywhere, for `:INFO:`, then `:LOW:`, then
   `:WARNING:`/`:MEDIUM:`, then `:ERROR:`/`:HIGH:`, then `:CRITICAL:`, **in that order, first hit wins** (E6:
   `x:LOW:and:CRITICAL:` is LOW). No marker means HIGH. Brackets are not markers (`[HIGH]`), and a space after the
   colon is not one (`bandit:Severity: MEDIUM:B602` is HIGH, A16).

`--min-severity` (the `MIN_SEVERITY` variable) lowers or raises the bar for turning a FAIL into a WARN. With the
default `high`, only MEDIUM, LOW and INFO findings are downgraded. `MIN_SEVERITY=critical` lets the whole
`vulnerable` fixture PASS (E15). `MIN_SEVERITY=low` (threshold 1) downgrades nothing. The `INFO` and `LOW` records that can appear in `findings[].severity` come only from a Semgrep `INFO`
result or a `:LOW:`/`:INFO:` marker, and only when the threshold is 1.

An `engine:` message has no marker, so its record says HIGH (golden `transitignore_everything`); the threshold is not
consulted for it (section 6.2).

`severity` in the record MUST NOT be derived from repository-controlled text (S7).

## 7. Coverage block

`coverage` maps a layer id to a state string. A state is one of `ran`, `skipped:<reason>`, `partial:<reason>`.
`coverage_gaps` lists, sorted, every id whose state does not **start with** `ran`; `coverage_complete` is true
when that list is empty. A verdict alone cannot tell "clean" from "nothing examined", so automated consumers MUST
gate on coverage, not on the verdict. Every state that exists today (all exercised with stubs unless noted; the
states added by the hardening of 2026-11-13 are pinned by Layer J and K and by the nine golden cases it added):

| Layer id | State | When | Exact text |
|----------|-------|------|------------|
| `L1_secrets_gitleaks` | `ran` | gitleaks exit 0 or 1 (E7) | `ran` |
| | skipped | exit 2 or more; a FAIL `gitleaks:scan_error_exit_<rc>` is also recorded (E7) | `skipped:gitleaks failed (exit <rc>)` |
| | skipped | not installed (golden) | `skipped:gitleaks not installed` |
| `L1_secrets_entropy` | `ran` | detect-secrets exit 0 and its output is the JSON document with a `results` object (J, D-015) | `ran` |
| | skipped | exit other than 0; WARN `detect-secrets:scan_error_exit_<rc>`; what it printed and could be read is still acted on | `skipped:detect-secrets failed (exit <rc>)` |
| | skipped | exit 0 but the output is not that document (a traceback, an empty output, another JSON); WARN `detect-secrets:output_could_not_be_read` | `skipped:detect-secrets output could not be read` |
| | skipped | not installed | `skipped:detect-secrets not installed` |
| `L1_malware` | `ran` | clamscan exit 0 (clean) or 1 (`clamav:malware_detected`) and signatures staged (E11) | `ran` |
| | skipped | no `*.cvd`/`*.cld` in `CLAMAV_DB_DIR` or `/var/lib/clamav`; **clamscan still runs** and its exit 0 or 1 is used (E11) | `skipped:no ClamAV signatures available` |
| | skipped | exit other than 0 and 1 (a database it cannot open, an unreadable path): the layer did not run and **no malware is reported**; WARN `clamav:scan_error_exit_<rc>`; this replaces the state of the row above (J, D-015, golden `clamscan_error_stub`) | `skipped:clamav failed (exit <rc>)` |
| | skipped | not installed | `skipped:clamav not installed` |
| `L1_ioc_yara` | `ran` | yara and `$WORK_DIR/yara-rules` present with at least one `*.yar`, and **every** rule file ran with exit 0; a hit is a FAIL `yara:ioc_match:<rule file>` (J, D-008, golden `yara_ran_stub`) | `ran` |
| | skipped | a rule file's yara exited non-zero (the first such status); WARN `yara:scan_error_exit_<rc>:<rule file>` for each; a hit that run printed is still a FAIL (K, F2) | `skipped:yara failed (exit <rc>)` |
| | skipped | the rules directory exists but holds no `*.yar`; WARN `yara rules directory has no .yar files — IOC scan skipped` (J, D-008) | `skipped:yara rules directory has no .yar files` |
| | skipped | yara or `$WORK_DIR/yara-rules` missing (golden) | `skipped:yara or rules directory missing` |
| `L2_owasp_cwe` | `ran` | semgrep present, all four rule files staged, every run ended with exit 0 or 1 and printed JSON with a `results` list (E10) | `ran` |
| | partial | some rule files staged; the run **completes** with the staged ones, and the WARN `OFFLINE:semgrep rulesets not staged (…)` is recorded. It used to abort the whole run (A5; J, D-005, golden `semgrep_partial_stub`) | `partial:rulesets missing (<names, space separated>)` e.g. `(security-audit secrets)` |
| | skipped | no rule file staged | `skipped:no semgrep rulesets staged for offline use` |
| | skipped | a run ended with an exit other than 0 and 1 (the first failure names the state; WARN `semgrep:scan_error_exit_<rc> (<rule file name>)` for each); replaces `partial:` because a failed Semgrep is the bigger gap (J, D-015, golden `semgrep_crash_stub`) | `skipped:semgrep failed (exit <rc>)` |
| | skipped | a run's output is not JSON with a `results` list; WARN `semgrep:output_could_not_be_read (<rule file name>)` | `skipped:semgrep output could not be read` |
| | skipped | not installed | `skipped:semgrep not installed` |
| `L3_dependency_cve` | skipped | `RUN_SCA` not `true` (golden) | `skipped:disabled (RUN_SCA is not true)` |
| | `ran` | trivy present, `$TRIVY_CACHE_DIR/db/*` exists, exit 0 and a trivy JSON document (E11; K, F3) | `ran` |
| | skipped | no staged database: trivy is **not started**, there is no `trivy: no known CVEs` line and no PASS event (J, D-015) | `skipped:trivy database not staged for offline use` |
| | skipped | exit other than 0; WARN `trivy:scan_error_exit_<rc>` | `skipped:trivy failed (exit <rc>)` |
| | skipped | exit 0 but the output is not a trivy document (`{}`, an error object, a list); WARN `trivy:output_could_not_be_read` (K, F3) | `skipped:trivy output could not be read` |
| | skipped | not installed (golden `layers_on`) | `skipped:trivy not installed` |
| `L4_patterns` | `ran` | after the per-file loop, always, even with zero files (golden `diff_mode_zero_files`) | `ran` |
| | skipped | the file listing did not complete; FAIL `engine:file_listing_failed` (E24) | `skipped:file listing failed (find exit <rc>)` |
| | skipped | `.transitignore` removed every file of a repository that has files; FAIL `engine:nothing_scanned` (J, D-004, golden `transitignore_everything`) | `skipped:nothing scanned (every file excluded)` |
| `L5_per_language_sast` | `ran` | same as `L4_patterns` | `ran` |
| | partial | the loop ran, but a per-file tool could not do its job: the reasons, once each and joined by `; ` (J, D-037, golden `js_ruleset_unstaged_stub`) | `partial:<reason>[; <reason>]`, today `partial:javascript rule set not staged` (semgrep present, `javascript.yaml` not staged), `partial:semgrep javascript failed (exit <rc>)`, `partial:semgrep javascript output could not be read` |
| | skipped | the same two conditions as `L4_patterns` | `skipped:file listing failed (find exit <rc>)`, `skipped:nothing scanned (every file excluded)` |
| `L6_licence` | skipped | `RUN_SCANCODE` not `true` (golden) | `skipped:disabled (RUN_SCANCODE is not true)` |
| | `ran` | scancode produced a report that the reader could parse (E9) | `ran` |
| | skipped | not installed (golden `layers_on`) | `skipped:scancode not installed` |
| | skipped | exit other than 0; WARN `scancode:scan_error — check <path>` (J, D-006, golden `scancode_failed_stub`) | `skipped:scancode failed (exit <rc>)` |
| | skipped | exit 0 and no report; WARN `scancode:no_report_generated` | `skipped:scancode produced no report` |
| | skipped | `python3` missing; WARN `scancode:python3_missing — cannot parse report` | `skipped:python3 not available` |
| | skipped | the report exists and cannot be read; WARN `scancode:report_could_not_be_read` (E25) | `skipped:scancode report could not be read` |

Notes. The id set is closed: nine ids, and **a completed run records all nine** (since D-006 and D-008, bash no longer
leaves `L1_ioc_yara` or `L6_licence` out). A tool that was started and ended with a status the engine does not
understand, or printed output it cannot parse, is **never `ran`** (S9, D-015): a WARN names it and the state says
`skipped:` or `partial:`; the Python engine MUST NOT revive the old behaviour (A15). A diff run with no matching files
is still `ran` for L4 and L5. Because a failed Semgrep replaces `partial:rulesets missing`, the second state is lost
when both happen in one run; the WARN `OFFLINE:semgrep rulesets not staged (…)` is still in the report.

## 8. File selection

### 8.1 Two different sets

Whole-directory tools receive `SCAN_DIR` itself: gitleaks, detect-secrets, ClamAV, YARA (L1), Semgrep (L2), trivy
(L3), ScanCode (L6). The per-file layers (L4 universal patterns, L5 type scanners) work on a list built by `find`.
Diff mode, `.transitignore` and the default exclusions shape the second set; ClamAV and Semgrep also get the
exclusions as `--exclude-dir <name>` for each; **gitleaks, detect-secrets, YARA, trivy and ScanCode get none**,
so they look inside `node_modules`, `.git` and every `.transitignore`d path (code, L190-L202).

### 8.2 `DEFAULT_EXCLUDE_DIRS`

`node_modules .git vendor .tox __pycache__ .venv venv dist build .next .nuxt .cache target coverage` (14 names).

### 8.3 How an exclusion name is applied

For every name `N` (the 14 defaults, then every `.transitignore` line) the `find` expression prunes the paths that match
the glob `<root>/N` or `<root>/*/N`, where `<root>` is `SCAN_DIR` with the glob characters `\ * ? [` escaped (D-001,
D-002, closed in bash; J, Layer I). The root is **not** part of what is matched, so:

* An ancestor of `SCAN_DIR` named like an exclusion does nothing: scanning `/work/build/repo` finds the files of
  `repo`. It used to prune everything and pass (A1).
* The 14 built-in names prune **directories** only (`-type d`): a regular file named `vendor`, `target`, `build` or
  `coverage` is scanned. It used to be skipped (A2). A `.transitignore` entry may name a file or a directory.
* It matches at any depth (`sub/docs` and `docs` both exclude `sub/docs/d.py`), because `*` in a `find -path` glob also
  matches `/`.

### 8.4 `.transitignore`

Read from `SCAN_DIR/.transitignore`, one pattern per line. Blank lines and lines starting with `#` are skipped. One
trailing CR is removed from each line, and **a last line without a trailing newline is read** (D-003, J). Each
remaining line is used verbatim as `N` above, i.e. as a `find -path` glob anchored on the scan root. Measured (E2, E27):

* `name` and `a/b` (no slash at either end) exclude as expected; `*.log` excludes any file whose name ends in `.log`.
* `docs/` (trailing slash) excludes nothing. `/h.py` (leading slash) and `!keep` (negation) have no effect. The
  syntax is **not** gitignore, although CLAUDE.md calls it that (real gitignore syntax is still an open decision,
  D-003). A CRLF file works since the CR is removed.
* A single `*` excludes every file: the scan examines nothing, which is now a FAIL (`engine:nothing_scanned`, 8.5,
  D-004, golden `transitignore_everything`). It used to pass (E14, A4).
* The file itself is scanned like any other file (it is in `file_results`), but it does not count as "something was
  examined" (8.5).
* A pattern is also given to Semgrep and ClamAV unmodified.
* **Exclusions leave a trace (D-004).** Both engines record the WARN `transitignore:exclusions_applied(<n> pattern(s))`
  on `__global__` whenever the file yields at least one pattern (golden `ignored`, `transitignore_crlf_noeol`); `<n>` is
  the number of patterns and nothing else from the file is in the message. The Python engine also refuses a file with
  more than 64 globs or a pattern over 256 characters (D-044): as a whole, with a console note, which can only make the
  scan examine more; and it reads `.transitignore` only as a regular, non-symlink file of at most 1 MiB (D-036).
* The bash engine has no cap on the number of patterns. A file of tens of thousands of lines makes the `find` command
  line exceed the argument limit: `find` does not start (exit 126), which is `engine:file_listing_failed` (8.5; E27 ran
  30,000 patterns), so it fails closed. A cap in bash is an open item.

### 8.5 What `find` lists

`find "$SCAN_DIR" <prune args> -type f -print0`, written to a temporary file so that its exit status is read. Regular
files only: **symlinks to files and to directories are not listed as files** (E8); they are reported as links, below.
Hidden files are included. **No file is skipped because of its name** (the bash engine skipped `.manifest_sha256.txt`
at any depth: A25, D-038); a path that is no longer a regular file when its turn comes is skipped (code, L6304-L6306).
The fetcher's own `.manifest_sha256.txt` at the root is scanned like any file; `ai_transit.sh` keeps that one file out of
the ZIP (`zip -x` matches the stored name, so a nested file of that name is archived, after being scanned), and
`fetch_repo.sh` writes it through a temporary file outside the copy, never through a symlink the repository planted at
that name, and without listing itself (code).

* **The listing must complete.** If `find` exits non-zero (a directory it cannot read; a command line too long to start)
  the run records the FAIL `engine:file_listing_failed` on `__global__` and `L4_patterns` and `L5_per_language_sast`
  are `skipped:file listing failed (find exit <rc>)`. The files the incomplete listing did contain are still scanned
  (E24, run with a `find` that exits 1; a real unreadable directory is `(unverified: running as root)`). The Python
  engine has no `find`: it MUST record the same FAIL on `__global__` and set both layers to
  `skipped:file listing failed (<cause>)`, with a short cause of its own (it never leaves either `ran`), and it may add
  one `engine:directory_unreadable:<reason>` FAIL per directory it could not list (design 8.3). In the Python engine an
  unlistable directory is a FAIL and a path longer than PATH_MAX is listed (D-041); in bash a path longer than PATH_MAX
  is still listed by `find`, cannot be opened by the script and is dropped without a trace (A26, E28).
* **Nothing scanned.** If `.transitignore` yields at least one pattern, the listing completed, no file other than the
  three *control files* was listed, and a listing with the built-in exclusions alone does contain a file that is not a
  control file, the run records the FAIL `engine:nothing_scanned` on `__global__` and `L4_patterns` and
  `L5_per_language_sast` are `skipped:nothing scanned (every file excluded)`. The control files are the root
  `.transitignore`, `.transit-allow.json` and `.manifest_sha256.txt`: they are scanned like any file and do not count as
  "something was examined" (a `.transitignore` of `[!.]*` keeps only them, E23). An empty repository, one whose files are
  all under the built-in exclusions, and a diff run with no changed file keep their old behaviour (`ran`); in a diff run
  only the changed files count, so a run whose changed files were all removed by `.transitignore` is
  `engine:nothing_scanned` too (J, D-004). The FAIL is neither allowlistable nor lowered by `--min-severity` (6.2).
* **Symlinks.** A second `find -type l` over the same prune arguments reads each link's target text without following it
  (the repository chooses both strings; they are only compared). A link whose target text is absolute, or climbs above
  the scan root (a relative target whose `..` components, taken in order from the link's own directory, go above it),
  is the FAIL `symlink:target_outside_the_scanned_directory` on the link; every other link, to a file or a directory,
  is the WARN `symlink:not_followed_its_target_is_not_scanned_through_the_link`. Nothing is read through a link, so
  what it points at is not examined: `ai_transit.sh` therefore stores links as links in the ZIP (`zip -y`) instead of
  reading their targets into the approved archive (E22, code). The Python engine MUST report the same two findings on
  the same links and MUST NOT follow a link, not even one swapped in while the scan runs.

### 8.6 Diff mode

`DIFF_FILES_ONLY` is true when `${WORK_DIR}/.diff_files` exists **and** `SINCE_COMMIT` is non-empty (E17). The file has
one of two formats, told apart by a NUL byte (a file name cannot hold one) (D-042, J, golden `diff_mode_nul_names`):

* **NUL-separated**, what `fetch_repo.sh` writes (`git diff -z --name-only`): names relative to the scan directory,
  never quoted, each ended by a NUL byte (the last may lack it). A `:` or a newline in a name is part of the name. The
  engine joins `SCAN_DIR/<name>`, and the joined string must equal what `find` prints, so it works with a relative
  `SCAN_DIR` too (E26).
* **Colon list**, what it used to write and what an existing sidecar may still hold: absolute paths each **terminated**
  by `:` (`<DEST>/<path>:…`, then a newline). The last entry without a colon is dropped, and the surviving strings must
  be **equal** to what `find` prints, so a relative `SCAN_DIR` against absolute entries matches nothing (E17, E26; A19).
  A name that holds `:` is split in two, and git quotes a non-ASCII or special name (`"\303\251.py"`), which matches no
  file: such a changed file is never scanned (A27). The Python engine MUST read both formats, and for the colon list
  rebuild a name that holds `:` by joining up to 16 pieces and C-unquote git's quoted names; what it cannot resolve it
  counts, records as the WARN `engine:diff_entries_unresolved(<n>)` on `__global__` and marks `L4_patterns` and
  `L5_per_language_sast` `partial` (D-042).

In both, an entry is kept only if it names an existing regular file. With diff mode on and an empty set, nothing is
scanned and the run passes with L4 and L5 `ran` (E17, golden `diff_mode_zero_files`); a set whose files were all removed
by `.transitignore` is a FAIL (8.5). Only the per-file layers are restricted; whole-directory tools still read
everything. A stale `.diff_files` without `SINCE_COMMIT` is ignored with a stderr WARN (E17, golden
`stale_diff_files_ignored`).

### 8.7 Binary files and unreadable content

* The grep rules (`grep_check`, `grep_check_i`) run **without `-I`**, so they examine a file that contains NUL bytes or
  invalid UTF-8; a match still counts (E8). They do not use `-a`: on a binary file grep prints "Binary file matches" and
  exits 0, which is a match. `grep_check_excl` (a pattern with an exclusion pattern, such as the unpinned VCS
  requirement) and the private-key test read as text, **with `-a`**: without it a NUL byte made the first grep print
  nothing to the pipe, the second read nothing, and one NUL silenced the rule (D-029, A29, K F4). In the C locale an
  invalid UTF-8 byte no longer makes a file binary (K, F1).
* `_known_cred_check` (the 18 provider formats and the JWT warning) runs **with `-I`**: a file with a NUL byte is
  skipped by it. One NUL byte added to a source file hides a known-format token (E8, A14; D-014 is accepted for the
  Python engine only). The same rule is applied to jar and office text views.
* **`grep_flat`** (the three external-entity rules of `scan_xml` and the one of `scan_powershell_xml`, which must see a
  declaration split across lines) searches the file as one record (`grep -z`). `grep_flat` has no size cap in either
  engine (D-039): it used to answer "no match" for a file over 5,242,880 bytes (A28). A `grep` that could not run to
  the end (exit 2 or more: out of memory, an I/O error, the file gone) is neither a match nor a clean file: the FAIL
  `engine:search_incomplete` on the file, once per file, with no invented XXE finding and no PASS event for the file
  (K, F6). `scan_xml` reads a view of the document that is decoded from UTF-16 or UTF-32 (a byte-order mark, or the NUL
  pattern of a wide encoding without one) and has its comments removed with `str.find`; an opener with no closer leaves
  the rest of the file visible (K, F5). Without `python3` the raw file is searched.
* By extension, a regular file is a binary regardless of content: `.so .dll .dylib .exe .elf .bin` is a FAIL
  `binary:unexpected_binary_in_AI_repo` (plus `binary:IOC_strings_detected` if `strings` finds a URL or shell word);
  `.zip .tar .gz .tgz .bz2 .xz` is a FAIL `archive:requires_dedicated_rescan` (plus a zip-slip check on `.zip`).
  `.jar .war .ear .aar`, the office types and `.pdf` have their own container scanners. An executable with a
  harmless extension is caught only if it has no known extension (below).
* A file with no recognised extension is first routed by shebang, then `file --mime-type`: `application/x-executable`,
  `x-sharedlib`, `x-dosexec` is a FAIL `binary:unexpected_executable_mime:<mime>`; anything else PASS. If `file` is not
  installed that step is skipped without a warning (code, A22). **The shebang is reduced to the interpreter it names
  before it is compared** (D-031, K F7): `#!/bin/bash -e` is `#!/bin/bash`, `#!/usr/bin/env python3 -u` is
  `#!/usr/bin/env python3`, and for `env` the options (`-i`, `-v`, `-0`, `-u NAME`, `-C DIR`, `--unset=…`, `--chdir=…`,
  `NAME=value` words) are skipped and the words of `-S` are read as the command line they are, in every spelling
  (`-S "bash -e"`, `-Sbash -e`, `-iSbash`, `--split-string='bash -e'`). A CR at the end of the line is not part of the last
  word, only the first 1024 characters are read, and a one-line script without a trailing newline is read. The line is
  hostile text: it is split into words without any expansion and only compared, never run. Routes: `python`, `ruby`,
  `node`, `php`, `pwsh` or `powershell` anywhere in the reduced line; a path ending in `/bash`, `/sh`, `/zsh` or `/ksh`,
  or `env bash` or `env sh`, goes to the shell scanner. A line that names no interpreter routes nowhere. (A shebang with
  arguments used to match nothing: A30.)
* A file that starts with `{\rtf`, named `.txt`, `.md`, `.rst` or with no known extension, is scanned as an
  office document (code, L6282, L6291). A `.xml` that is Flat OPC or Word/Excel 2003 XML is scanned as both.

### 8.8 The dispatch (`classify_file`, L6193-L6293)

1. `scan_universal_patterns` (layer 4) runs on **every** file first.
2. **Basename rules**, in this order, case-sensitive: `Dockerfile*`, `Makefile*` `makefile*` `GNUmakefile*`,
   `CMakeLists.txt` `CMakeLists.*.txt`, `package.json` `composer.json`, `requirements*.txt` `constraints*.txt`,
   `gradle.properties` `gradle-wrapper.properties` `*.gradle` `*.gradle.kts`, `setup.py` `conanfile.py`. They end
   the dispatch.
3. **Extension**, taken after the last `.` of the full path and **lower-cased** (so `.PS1` and `.PY` route like
   `.ps1` and `.py`; a file with no dot routes on its whole path and falls through) (golden `rules_corpus`: `case_upper.PY` is FAIL; CLAUDE.md "PowerShell").
4. `.json`, `.md`, `.txt`, `.rst` have one inline credential rule each (`CWE-798:hardcoded_credential_in_JSON` /
   `…_in_doc`); anything unmatched goes to `scan_unknown` (section 8.7).
5. Every scanner ends with `record_pass(file)` unless it recorded a FAIL (the container scanners differ: `scan_jar`
   never passes, it WARNs `jar:vendored_compiled_code_not_reviewable` when nothing else is wrong). A scanner whose
   `grep_flat` search could not finish has recorded `engine:search_incomplete` and records no PASS (8.7).

**The machine-readable dispatch is `build_pdf_filetypes.FAMILIES`**: a list of 34 dicts with `key`, `title`,
`scanner`, `ext` (list of extensions), `shebang`, `tools`, `fail`, `warn`, `note`. `build_pdf_filetypes.routed_patterns()`
returns the extension and basename sets, and `python3 build_pdf_filetypes.py --check` compares them with
`classify_file`: it reported 109 extensions, 7 basename patterns and 34 scanner families, matching (E17). The Python
engine's `dispatch.py` MUST route exactly that set and the check MUST be pointed at it when the bash engine is
retired. The *rules* inside each scanner are not restated here: they are the reference script's source plus
`tests/conformance/patterns.json` (the pattern inventory), and `tests/fixtures/rules/` is the corpus where each
file is crafted to trigger or deliberately not trigger one rule.

## 9. Security properties the Python engine must preserve

Each is a statement a test can check. "Repository text" means a file name, an archive entry or part name, file
contents, a tool's output, `.transit-allow.json` and `.transitignore`.

* **S1. Console is control-free.** No byte of repository text that is a C0 control (0x00-0x1F except the final
  newline), DEL, or a C1 control (U+0080-U+009F) reaches stdout or stderr; each is replaced by `?`. Test: scan a
  directory with names containing `ESC ] 0 ; pwned BEL`, CR, TAB, DEL and U+009B; every byte of both streams
  after removing the engine's own `ESC[…m` colour sequences is printable or LF (E13). *Bash additionally fails to
  strip Unicode format characters such as U+202E (bidi override) (E13); the Python engine MUST also replace
  U+202A-U+202E, U+2066-U+2069, U+061C, U+200E and U+200F (D-017), and MUST sanitise the progress line too (3.1).*
* **S2. Backslash text is data.** A name containing the characters `\033` is printed with those four characters,
  never expanded to ESC. Test: file `lit\033[31mred.txt` (E13). The bash lint "`scan_pipeline.sh` never passes `$*`
  through `echo -e`" retires with the bash engine.
* **S3. HTML is escaped.** In the HTML report every path, every message and the scanned directory have `&`, `<`,
  `>`, `"`, `'` escaped (`&` first). Test: a file named `<img src=x onerror=1>.py` and a jar with a `<script>` entry
  name; the report contains no `<img` and no `<script` from them (golden `hostile_html_name`, Layer D). *Bash also
  leaves raw control bytes in the HTML (E13); the Python engine SHOULD escape them (D-017).*
* **S4. The JSON is always valid.** The report parses with a strict UTF-8 JSON parser for any file name, including
  non-UTF-8 and control characters (golden `hostile_non_utf8_name`, `hostile_escape_name`). A name that cannot be
  decoded is replaced, never dropped and never raising.
* **S5. The report appears whole or not at all.** It is written beside the destination and renamed. Test: make the
  destination unwritable and confirm no truncated `.json` exists (`(unverified: running as root)`).
* **S6. Repository text never reaches a shell.** Every external program is started with an argument list; no
  `shell=True`, no `os.system`, no `eval`. Test: files named `sub$(touch PWNED1).txt`, `` bt`touch PWNED2`.txt ``,
  `q"uote's.txt`, `semi;touch PWNED3.txt`, `-n.txt`, `--x.txt`, `*.txt`; all are scanned, no `PWNED*` file appears
  (E13b). A name beginning with `-` is passed after `--` or as an absolute path.
* **S7. Severity is never read from repository text.** A Semgrep message takes its severity from the fixed field
  only; a jar or office detail is neutralised before it enters a message: non-printable and `|` become `?`, a colon
  that opens `info`/`low`/`warning`/`medium`/`error`/`high`/`critical:` becomes `?`, at most 6 distinct details of 110
  (jar) or 120 (office) characters. The Python engine SHOULD carry severity as a field from the producer and not
  parse it back out of text (D-016). Test: a jar with an entry named `a:LOW:b` still FAILs; a file whose content
  holds `:LOW:` does not change a grep rule's severity.
* **S8. gitleaks runs on our terms.** (a) The config is a generated file containing only
  `[extend]` / `useDefault = true`, passed with `--config`; the repository's `.gitleaks.toml` is never read.
  (b) `--gitleaks-ignore-path` points at an empty directory where gitleaks lists the option; the repository's
  `.gitleaksignore` is never read. (c) `--ignore-gitleaks-allow` is passed where gitleaks lists it, otherwise a
  WARN `gitleaks:inline_allow_comments_not_disabled (…)` is recorded. (d) `GITLEAKS_CONFIG` and
  `GITLEAKS_CONFIG_TOML` are removed from the child's environment. (e) `--no-git --source <SCAN_DIR> --report-format
  json --report-path <private file>` always; `--no-banner`, `--redact`, `--log-level error` where listed. (f) The
  child's stdout and stderr are discarded and never printed (`-v` would print the secret and raw bytes); secrets
  are redacted and never stored. (g) A repository that ships `.gitleaks.toml` or `.gitleaksignore` gets the WARN
  `gitleaks:repository_allowlist_ignored (…)`. (h) Exit 0 is clean, exit 1 is leaks (each leak a FAIL, 200 at most,
  then `gitleaks:more_leaks_not_listed_<n>`; a FAIL `gitleaks:secrets_detected` if exit 1 left no readable report),
  anything else is a FAIL `gitleaks:scan_error_exit_<rc>` with coverage `skipped:gitleaks failed (exit <rc>)`.
  Test: a stub `gitleaks` that records its arguments and environment, and a repository that ships both files
  (golden `gitleaks_stub_leak`, E7; Layer C2). Real gitleaks `(unverified: not installed)`.
* **S9. Fail closed, and say so.** A layer's state is `ran` only if its tool was found, was invoked, ended with a
  status the engine understands and printed output it could parse. Otherwise it is `skipped:<reason>` or
  `partial:<reason>` **and** a WARN is recorded. A crashing Semgrep or detect-secrets MUST NOT read as `ran`
  with no findings, and a crashing ClamAV MUST NOT read as `malware_detected` (E18, A15). The bash engine has
  satisfied this since the hardening of 2026-11-13 for gitleaks, detect-secrets, ClamAV, YARA, Semgrep (layer 2 and the
  per-file JavaScript run), trivy and ScanCode (J, D-005, D-006, D-008, D-015, D-037; K, F2, F3). The per-file tools
  of layer 5 are not covered by it (D-015 does not list them): a crash of bandit, cppcheck or checkov is still read as
  "no finding" (`… || true`), and any non-zero exit of shellcheck or hadolint is a FAIL, a crash included. The Python
  engine MUST NOT copy the first.
* **S10. Tool output is never echoed raw.** Captured, parsed, and only sanitised excerpts reach the console.
* **S11. Containers are never extracted to disk, and every limit is reported.** Jar and office content is read
  through bounded in-memory reads; each limit reached (section 2) is a WARN that says the container was not fully
  read. Part and entry **names** are checked for every entry even when the entry limit is reached. Test: the
  `JAR_*`/`OFFICE_*` knobs on the small fixtures `jar_late_slip.jar`, and a document padded past the budget gives
  `…inspection_incomplete`.
* **S12. Hostile input costs bounded time.** Every compiled pattern is linear or time-boxed; a hostile 3 KB file
  never takes more than 20 s (the standing requirement for the jar and office helpers; a lint forbids `[^>]*`, `.*?`
  and the like in them). Python's `re` backtracks, so the Python engine MUST bound the cost of every pattern on every
  line length, by a reported per-line cap or by a linear-time matcher; it MUST enforce a per-file time budget whose
  expiry is a FAIL, and a fuzz gate over every registered pattern (D-043, D-035), see PYTHON_PORT_PLAN 5.2. The bash engine
  needs none of it: GNU grep is linear, and the one bash helper that was quadratic, the comment strip of `scan_xml`, is
  linear since F5 (K). `(unverified: engine not written)`.
* **S13. An allowlist can only lower, and visibly.** A FAIL can become a WARN through the allowlist or
  `--min-severity`, never a PASS, and the WARN carries `ALLOWED:` + reason or `LOW_SEV(…)`. The verdict is
  irreversible once FAIL.
* **S14. The scanned directory is read-only.** The engine writes nothing under `SCAN_DIR` (the report directory may
  lie elsewhere). `(code; unverified: tree hash before and after not compared)`.
* **S15. Hostile `.transit-allow.json` and `.transitignore`.** Neither can make the engine crash, read outside the
  repository, or hide an effect: parse failures fail closed (no allowlist entries honoured), and exclusions are
  reported (D-004, both engines): a WARN whenever `.transitignore` yields a pattern, and a FAIL when its patterns leave
  nothing to scan (8.4, 8.5).
* **S16. Temporary files.** Unpredictable names, mode 0600 in a private directory, removed on every exit path.

## 10. Not part of the contract

* Order of: `findings`, keys of `file_results` / `findings_by_file` / `coverage`, `coverage_gaps` elements as long
  as they are the right set, `standards`. The bash engine iterates associative arrays in hash order, and the Python
  engine sorts (D-024).
* JSON whitespace, indentation, key order; HTML markup, CSS and row order.
* Timing, progress output, the order scanners run within a layer, parallelism.
* Text printed by external tools, their stderr, their version banners.
* The wording of every console line (`info`, `ok`, `warn`, `fail_f`, `fail`, usage and refusal messages) **except**
  that the last stdout line is `PASS` or `FAIL` on a completed run. Messages that are *recorded in the report* are
  contract (section 5).
* `timestamp`, `repo_hash`, `repo_input`, `directory`, `source.directory`, the default report file name's
  timestamp, temporary-file names, the name of the ScanCode output.
* Hash iteration order, locale-dependent sort order of `repo_hash`.
* Anything marked `unverified` above until it is verified.

## 11. Behaviour that looks accidental

Everything below was observed in the reference engine (`4b2746b`). An item marked **closed** was fixed in the bash engine
on 2026-11-13 (the hardening described at the top of this document); the text says what the reference engine did and what
bash does now, and the Python engine implements the hardened behaviour, so it is no longer a divergence. The other items
are still true of bash; the Python engine does **not** automatically inherit them: each has a divergence entry that
records the decision. "Verified" means reproduced by a run in Appendix A.

* **A1. An ancestor directory named like an exclusion silently empties the scan** (D-001) — **closed**: the patterns are
  anchored on the scan root (8.3). In the reference engine `find -path '*/build/*'`
  tests the whole path, so `/srv/build/repo` yields no files; the run passes with L4/L5 `ran`. Verified (E1): the
  same file is FAIL under `plain/repo` and PASS under `build/repo`. In the normal flow `ai_transit.sh` scans
  `$WORK_DIR/fetch/repo_<ts>`, so a `WORK_DIR` such as `/opt/build/ai-transit` is enough.
* **A2. A file named like an excluded directory is skipped** (D-002) — **closed**: the built-in names prune directories
  only. A regular file called `vendor`, `target`, `build`, `dist` or `coverage` was never scanned (E2).
* **A3. `.transitignore` is not gitignore** (D-003): `docs/` and `/x` and `!x` do nothing (E2, E27). **Closed in part**:
  CRLF patterns never matched and a last line with no newline was lost; both are read now (8.4). Real gitignore syntax is
  still an open decision.
* **A4. Exclusions leave no trace** (D-004) — **closed**: the WARN `transitignore:exclusions_applied(…)` and, when
  nothing is left to scan, the FAIL `engine:nothing_scanned` (8.4, 8.5). `.transitignore` containing `*` made a hostile
  repository pass with nothing scanned and no WARN in the report (E14).
* **A5. A partially staged Semgrep rule set aborts the entire run** (D-005) — **closed**: the run completes and the state
  is `partial:rulesets missing (…)` (section 7, golden `semgrep_partial_stub`). The last statement of
  `scan_owasp_cwe` is `[[ -z … ]] && record_layer … ran`; with `partial:` already recorded the test is false, the
  function returns 1, and `set -e` exits: exit 1, no report, no sidecars, last stdout line an `[OK]` line (E10).
  The state `partial:…` therefore could not appear in a report; the golden files could not contain it. The fix wrote
  the closing statements of `scan_owasp_cwe` as `if`, which cannot return 1.
* **A6. A failing ScanCode vanishes from the coverage block** (D-006) — **closed**: every failure records a `skipped:`
  state (section 7, golden `scancode_failed_stub`), and a report that cannot be read is one more (E25). `scancode:scan_error`,
  `scancode:no_report_generated` and `scancode:python3_missing` return before `record_layer`, so `L6_licence` is
  absent and cannot be in `coverage_gaps`; with every other tool present `coverage_complete` would be true (E9).
* **A7. A ScanCode vulnerability forces FAIL even if the finding was allowlisted or below the threshold** (D-007).
  `scan_scancode` counts `fail_count` before `record_fail` decides and then calls `fail_f` itself: verdict FAIL,
  `summary.fail` 0, no finding, no FAIL file (E9).
* **A8. YARA is never recorded as `ran`** (D-008) — **closed**: `ran`, or `skipped:` with a reason, in every case
  (golden `yara_ran_stub`). `L1_ioc_yara` existed only in the skipped case (E11). The exit status of yara was thrown
  away too (`yara … | grep -q .`: a rule file with a syntax error read as "ran, no IOC"), and under `pipefail` a yara
  that was still writing when `grep -q` left died of SIGPIPE and its hits were lost; both closed (K, F2).
* **A9. `file_results[*].message` is cut with a character-set `rstrip(" | ")`** (D-009), which strips any trailing
  spaces and pipes of the *message text*, not just the separator. `findings_by_file` and `findings[].message` keep
  them (E10b). The conformance normaliser splits on `" | "` and would not see it.
* **A10. Allowlist loading** (D-010): one non-string member drops every later entry; a newline in `reason` truncates
  it; an entry without a non-empty `reason` is silently ignored (E3). All of it fails closed.
* **A11. A whole-directory finding cannot be allowlisted by a stable path** (D-011). For `gitleaks:secrets_detected`,
  `clamav:malware_detected`, `detect-secrets:…`, `trivy:…`, `yara:…`, `rel_path` is `SCAN_DIR` as typed (E7: only
  the exact `SCAN_DIR` string matched, not `.`, not an absolute path when `SCAN_DIR` was relative). Under
  `ai_transit.sh` that string changes every run, so such an entry is unusable.
* **A12. A file can be `PASS` with a `[WARN]` message** (D-012). Status is first-writer-wins for PASS/WARN (E12). The
  Excel Findings tab, which lists only FAIL/WARN files, then omits that WARN.
* **A13. `summary` counts events** (D-013). Not an error, but the Excel sheet labels them "Fichiers PASS/WARN/FAIL".
  Callers rely on the numbers; the Python engine copies them.
* **A14. One NUL byte hides every known-format credential** (D-014): `_known_cred_check` uses `grep -I` (E8). The
  name-based `CWE-798:hardcoded_credential` rule is unaffected. Still open in bash (D-014 is accepted for the Python
  engine only). The private-key rule had the same blind spot and is closed (A29).
* **A15. Tool failures read as clean, or as malware** (D-015) — **closed** for Semgrep (layer 2 and per file),
  detect-secrets, trivy, clamscan and yara (section 7; goldens `semgrep_crash_stub`, `clamscan_error_stub`). Their output
  that did not parse counted as zero findings with `ran` (E18, trivy by code); every non-zero exit of `clamscan`,
  including a scan error, was `clamav:malware_detected` (E18); and trivy with no staged database printed
  `trivy: no known CVEs` and counted a PASS although coverage said `skipped` (E11): it is not started now. **Still open
  in bash:** with no signatures staged the layer is `skipped:` although `clamscan` runs and its result is used (E11), and
  a crash of bandit, cppcheck or checkov reads as "no finding" (section 9, S9).
* **A16. The structured record is wrong in places** (D-016): `bandit` `rule_id` is ` HIGH:B602` (E6) and its severity
  is always HIGH (the space defeats `:HIGH:`); `cppcheck` `rule_id` is the whole text; `CVE-2021-44228:…` has tool
  `unknown`; `jar:…(1)` has the count inside `rule_id`.
* **A17. Bidi controls reach the console and the HTML keeps raw control bytes** (D-017) (E13).
* **A18. The Semgrep ruleset label is an absolute path** (D-018) and so differs between hosts (E10).
* **A19. A relative `SCAN_DIR`** (D-019) keeps relative keys; gitleaks absolute paths then do not sit under it, so
  `file_results` keys and `findings[].file` are absolute for those findings (E7); an absolute `.diff_files` against a
  relative `SCAN_DIR` scans nothing and passes (E17). **Closed for the NUL-separated `.diff_files`** (it works with a
  relative `SCAN_DIR`, E26); still true of the colon list (E26).
* **A20. Invalid `MIN_SEVERITY` means `high` with no message; `VERBOSITY=verbose` does nothing** (D-020) (E5, E15).
* **A21. Report names have one-second resolution** (D-021). Two default-named runs in the same second overwrite.
* **A22. A missing `file(1)` is not mentioned** (D-022): unknown-extension files are PASSed without the MIME check
  and without a WARN `(code, L5883; unverified: not run without file)`.
* **A23. Non-UTF-8 names collapse to U+FFFD** (D-023). Copied for compatibility.
* **A24. Dead branches**: the pip-audit, safety and npm-audit FAIL paths cannot run while `OFFLINE` is forced (D-026).
* **A25. A file named `.manifest_sha256.txt` is never examined, at any depth** (D-038) — **closed**: no file is skipped
  by name (8.5). The reference engine skipped that name wherever it was (L6304-L6306), while `fetch_repo.sh` writes it
  only at the root and `ai_transit.sh` excluded only the root one from the ZIP, so a nested file of that name carried any
  payload into the approved archive; a repository whose only payload was the nested file passed (design F15, reproduced
  on scratch repositories).
* **A26. A path longer than PATH_MAX and an unlistable directory pass silently** (D-041). `find … 2>/dev/null` lost an
  unlistable directory without a word — **closed**: its exit status is read, `engine:file_listing_failed` (8.5, E24). A
  path longer than PATH_MAX is listed by `find` and cannot be opened by the script, which skips it: the repository
  passes and the file is absent from `file_results` — **still true in bash** (E28), fixed in the Python engine, which
  walks and opens through directory descriptors.
* **A27. A diff-mode name with `:` or non-ASCII characters is dropped** (D-042) — **closed for the NUL-separated
  `.diff_files`**, which `fetch_repo.sh` now writes (8.6, golden `diff_mode_nul_names`). In the colon list such a name is
  split, or quoted by git, and never scanned (design F16).
* **A28. `grep_flat` ignores a file over 5 MiB** (D-039) — **closed** (8.7). It answered "no match" above 5,242,880
  bytes, so every external-entity rule of `scan_xml` and `scan_powershell_xml` went blind on an XML padded past that size
  (an external entity was FAIL at 4,000,059 bytes and PASS at 5,300,055; design F15).
* **A29. One NUL byte silences the `excl` rules and the private-key rule** (D-029) — **closed** (8.7): the first `grep`
  of `grep_check_excl` and of the key test took the file for binary and printed nothing to the second.
* **A30. A shebang with arguments is not routed** (D-031) — **closed** (8.7): `#!/bin/bash -e` matched none of the
  `case` patterns, so an extensionless script got no shell analysis.
* **A31. Per-file Semgrep for JavaScript needed the registry** (D-037) — **closed**: `--config=p/javascript` resolves
  against the network; offline it returned nothing and layer 5 was `ran`. It now reads the staged `javascript.yaml`, or
  layer 5 is `partial` (section 7).
* **A32. Other behaviours of the reference engine closed by the review edits** (F1 to F13, no register entry):
  (a) in a UTF-8 locale an invalid byte stopped `.` and `[^x]` matching, so `curl … \xff | bash` was no curl-pipe-shell
  (`LC_ALL=C`, section 2); (b) an XML in UTF-16 or UTF-32 was invisible to every rule of `scan_xml`, which are ASCII, while
  parsers read it (8.7); (c) the comment strip of `scan_xml`, `<!--.*?-->`, was quadratic in the number of unclosed
  openers (25,000 of them took 11 s; K, F5); (d) `zip -r` followed symlinks, so a link to a directory put that tree, and a link to
  a file outside the repository that file, into the approved archive although the scan lists regular files only
  (`zip -y`, 8.5, E22); (e) `fetch_repo.sh` wrote its manifest through a symlink the repository had planted at that name,
  into any file the user could write, with lines whose path part the repository chose.
* Also: `semgrep:js:<N>_findings` has no severity, so it is always HIGH; the comment above `scan_office` gives the
  wrong default budget (section 2); `log()` is defined and never used; `quarantine/` and `approved/` are created
  and never used by the engine.

## Appendix A. Verification log

Every run used a private `WORK_DIR` under the session scratchpad and a copy of the script taken at the start
(`scan_pipeline.snapshot.sh`, identical to `git show 4b2746b:scan_pipeline.sh`). Stubs are shell scripts on `PATH`
that print a fixed result.

| ID | What was run | Result |
|----|--------------|--------|
| E1 | The same vulnerable file under `e1/plain/repo` and `e1/build/repo` | FAIL with 1 file; PASS with `file_results` = `__global__` only and L5 `ran`. |
| E2 | A repo with `docs/ build/ keep/ sub/docs/ secrets/`, a file named `vendor` and `target`, then four `.transitignore` variants | `build/`, `vendor`, `target` never scanned; `docs/` ineffective; `*.log` effective; last line without newline lost; CRLF ineffective; `!keep`, `/h.py` ineffective. |
| E3 | 14 allowlist variants (rule `CWE-798` and `hardcoded_credential`, empty / missing reason, `./bad.py`, absolute path, non-list, bad JSON, numeric rule before a valid entry, upper-case rule, glob path, newline in reason, numeric reason, null path) | Only the first two and the newline case matched; the numeric rule and numeric reason lost the later valid entry. |
| E4 | 19 argument variants: no args, only `--` words, missing directory, empty directory string, missing report dir, empty report dir, name with `/`, leading dot, TAB, 150 and 151 characters, `a.b`, `..x`, space, empty name, 4th argument, `--quiet` between positionals, `./--odd`, a file as directory | As in section 1; every refusal exit 1, no stdout, no files; sidecars in `WORK_DIR`; `scan_name` kept when the report dir is empty. |
| E5 | `WORK_DIR` under a regular file; `VERBOSITY=quiet`, `bogus`, `verbose` | exit 1 with an INFO line last; `quiet` = 1 stdout line `PASS` and 6 stderr lines; `bogus` and `verbose` = 12 stdout lines, identical. |
| E6 | The real `_classify_severity` on 23 messages; the real `_emit_finding` on 26 messages (functions extracted from the snapshot) | Sections 5.3 and 6.3 tables. |
| E7 | Stub gitleaks: absolute and relative file in its report, a `:` in the rule id, exit 2, exit 1 with no report, allowlist for the directory in three spellings | `gitleaks:generic_api-key:line3`; `skipped:gitleaks failed (exit 2)` + `gitleaks:scan_error_exit_2`; `gitleaks:secrets_detected`; only the exact `SCAN_DIR` string allowlists. |
| E8 | NUL byte, invalid UTF-8, symlink to file, symlink to directory; a token (built at run time) in each | Grep rules fire on NUL and invalid-UTF-8 files; the known-format rule is skipped for the NUL file only; symlinks absent from the report. |
| E9 | Stub scancode: HIGH vulnerability, same allowlisted, exit 3 | FAIL / FAIL with `summary.fail` 0 and no finding / PASS with no `L6_licence`. |
| E10 | Stub semgrep: 2 of 4 rule files staged; none; all 4 with no result; all 4 with a WARNING result; with an ERROR result whose message ends in `\|` (E10b) | abort with exit 1 and no report (also with no findings); `skipped:no semgrep rulesets…`; `ran`; `LOW_SEV(…)` WARN; 5 FAIL records (4 rulesets + per-file JS) with the YAML path in the brackets; `file_results` message lost its trailing `\|`. |
| E11 | Stub yara (rules present, hit), clamscan (exit 0 / 1, no DB), detect-secrets (hits), trivy (no DB; DB staged) | `L1_ioc_yara` absent; `skipped:no ClamAV signatures available` while running; `trivy database not staged` with "no known CVEs" on stdout; `ran` with DB. |
| E12 | Stub gitleaks exit 0, stub detect-secrets with hits, allowlist `detect-secrets` for `SCAN_DIR` | `file_results[SCAN_DIR]` = status `PASS`, message `[WARN] ALLOWED:detect-secrets:2_high_entropy_string(s) (reason: known)`. |
| E13 | Names with ESC, CR, a literal `\033`, newline, U+009B, U+202E; HTML report of the same | No control byte on stdout/stderr outside the engine's colours; `\033` printed literally; U+009B replaced; U+202E passed through; HTML holds a raw ESC and BEL. E13b: 8 names with `$()`, backticks, quotes, `;`, leading `-`, `*`: all 8 scanned, no side effect. |
| E14 | `.transitignore` containing `*` with a vulnerable file | PASS, `file_results` = `__global__` only, L5 `ran`. |
| E15 | `MIN_SEVERITY` = high, critical, bogus, low on the `vulnerable` fixture; the threshold expression for 7 spellings | FAIL, PASS, FAIL, FAIL; `bogus`, `HIGH`, ` high` → 3, `Critical` → 4. |
| E16 | The 362-file `tests/fixtures/rules` corpus with `TMPDIR` and `WORK_DIR` private | verdict FAIL, exit 1, 365 `file_results` entries (253 FAIL, 78 WARN, 34 PASS), `summary` pass 58 / warn 217 / fail 323 = 323 findings; 75.8 s wall time on a loaded host; `TMPDIR` empty afterwards. |
| E17 | `.diff_files` variants (absolute match, last entry without colon, relative `SCAN_DIR`, trailing slash, missing file, empty file, no `SINCE_COMMIT`); the live refactored script on the clean fixture; `build_pdf_filetypes.py --check` | as section 8.6; the live script's report validated by `check_schema.py`; `deck matches classify_file: 109 extensions, 7 basename patterns, 34 scanner slides`. |
| E18 | `scan_pipeline.sh --min-severity medium dir`; stubs semgrep and detect-secrets that print garbage and exit 7, clamscan exit 7 | `Directory not found: medium`; L2 and L1_secrets_entropy `ran` with no finding; `clamav:malware_detected`. |
| E19 | An independent Python implementation of the `source.sha256` recipe on the three fixtures | equal to the golden value for all three. |
| E20 | A script that extracts every `record_fail`/`record_warn` literal and every `fail_map`/`warn_map` entry | the prefix lists of section 5.2 (40 `CWE-…` ids, 4 `OWASP-…`, 1 `CVE-…`, 17 tool, 21 scanner prefixes). |
| E21 | A symlink used as the scanned directory and another as the report directory; an allowlisted Semgrep `INFO` finding | exit 0, report written through the link; the message is `ALLOWED:…`, not `LOW_SEV(…)`. |
| E22 | 2026-11-13, hardened engine: a repository with a link to `/etc/passwd`, a link `sub/up_link` to `../../../x`, a link to a file inside it and a link to a directory; `zip -r` and `zip -ry` of a directory holding a link to `/etc/hostname` | the first two are the FAIL `symlink:target_outside_the_scanned_directory`, the other two the WARN `symlink:not_followed_…` (tool `symlink`, rule id from the message, severity HIGH); `zip -r` stores the content of the target, `zip -ry` the link. |
| E23 | `.transitignore` of `[!.]*`, a vulnerable `src/db.py`, `.transit-allow.json` with entries for rule `engine` and rule `nothing_scanned` on `__global__`, `MIN_SEVERITY=critical` | FAIL: `[FAIL] engine:nothing_scanned` on `__global__`, not allowlisted, not lowered; `.transitignore` and `.transit-allow.json` are PASS entries; L4 and L5 `skipped:nothing scanned (every file excluded)`; `summary` pass 2 / warn 6 / fail 1. |
| E24 | a `find` that exits 1 after printing its listing, on a repository with one vulnerable file | the file is scanned and FAILs, plus the FAIL `engine:file_listing_failed` on `__global__`; L4 and L5 `skipped:file listing failed (find exit 1)`; `coverage_complete` false. |
| E25 | a stub `scancode` that writes `not json at all` to its report and exits 0, `RUN_SCANCODE=true` | `L6_licence` = `skipped:scancode report could not be read`, WARN `scancode:report_could_not_be_read`, verdict PASS (it used to end the run with a traceback). |
| E26 | `.diff_files` written NUL-separated (`a.py\0`) and as a colon list of absolute paths, each run with the relative scan directory `repo` | NUL format: only `repo/a.py` scanned and FAIL. Colon list: nothing scanned, PASS, L4 `ran` (A19). |
| E27 | `.transitignore` of `docs/`, `/h.py`, `!keep`, then of `docs`; then 30,000 long patterns | the first excludes nothing; `docs` excludes `docs/d.py` and `sub/docs/s.py`; 30,000 patterns: `find` exit 126, FAIL `engine:file_listing_failed`, exit 1 in 3 s. |
| E28 | a tree of 102 directories of 50 characters (a path of 5,202 bytes) holding a vulnerable file | exit 0, PASS, `file_results` = `__global__` only, L4 `ran`: the file is listed and silently skipped (A26). |
| D-F14..16 | `docs/python_engine_design.md` section 2, F14 to F16 (2026-11-12) | the PATH_MAX tree, the nested `.manifest_sha256.txt`, the 5.3 MB XML and the colon / quoted diff names, reproduced on scratch repositories before the hardening (A25 to A28). |

After the hardening (2026-11-13) `python3 tests/conformance/conformance.py check --engine bash` prints `ok` for all 26
cases and `Layer J` (D-003 to D-042) and `Layer K` (F1 to F7) of `tests/run_tests.sh` pass; E22 to E28 above cover what
neither pins (F8 to F13: the control files, the symlinks, the listing status, the unreadable ScanCode report, the manifest
and the traps). The Python engine is checked against the same goldens with
`python3 tests/conformance/conformance.py check --engine python`.

`python3 -I tests/conformance/check_schema.py` runs the self-test (48 deliberate mutations and 4 unsupported
keywords, each rejected for the intended reason), then the engine on `clean`, `vulnerable` and `allowlisted` and an
invalid scanning name, and validates every report; it passed on the bash engine. Feeding it reports damaged by a
wrapper engine (verdict `WARN`, a missing `summary`, `summary.pass` as a string, a bad coverage state, an extra key,
a wrong `coverage_complete`) made it exit 1 with a readable message each time, and removing the `enum` from the
schema's `verdict` made its own self-test report the two mutations that were no longer rejected.
