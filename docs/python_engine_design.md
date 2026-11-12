# Python engine design: skeleton, shared machinery and the first vertical slice

Phase 2 of `PYTHON_PORT_PLAN.md`. Written 2026-11-12 by the architect of Phase 2. Audience: the engineers who will implement
work packages WP-01 to WP-12 (section 14) and, later, the scanner and tool packages of Phase 3 and Phase 4, **in parallel, without
having read the bash code**.

What is in the repository next to this file: the stubs listed in section 3.1 (importable on Python 3.10 to 3.13, no side effect at
import, every behaviour is `raise NotImplementedError`) and `tests/engine/__init__.py`. The signatures in the stubs and in Appendix A are
**final**; this document says how they fit together and what each must do.

Precedence when two statements disagree: `docs/engine_contract.md` (what both engines must do) > the docstring of the function in
the stub (what that function does) > this document (how the pieces fit). A disagreement with the contract is a defect to be reported, not
resolved locally (section 1.3).

## 1. Scope, decisions, change control

### 1.1 Decisions that frame everything

| # | Decision | Source |
|---|----------|--------|
| 1 | One Python engine, standard library only, Python 3.10+; bash kept as the oracle until cut-over; feature freeze on new scanners | plan decisions 1 to 3 (accepted) |
| 2 | The engine is **single-threaded and runs on the main thread**. `rx` caches are not thread-safe and `rx.time_limit` needs SIGALRM on the main thread | `rx.py` docstring |
| 3 | Paths and text from the repository are `str` decoded with `surrogateescape` (what `os.scandir` gives); file **contents** are `bytes` and matched as bytes, like `grep` in the C locale | plan 5.3 |
| 4 | A rule is **data** (a `RuleSpec` row) and is compiled **only** by `rx.ere_to_py`, registered with `rx.rule` | plan 5.1, 5.2 |
| 5 | Scanner modules are found by discovery, not listed in a shared file; the 37 scanner ids are fixed in `transit/scanners/__init__.py` | section 7 |
| 6 | A scanner or tool that is installed but not written yet is **reported, never skipped**: coverage `skipped:python engine has not ported <tool> yet` (or `partial:` for a per-file tool), a WARN, and `coverage_complete` false | task rule 6, S9 |
| 7 | Helper files of the bash engine are **programs**: four are run as programs, three are re-implemented as pure functions and kept as test oracles. None is imported | section 3.3 |
| 8 | Every `proposed` divergence entry means "copy bash": a named switch in `config.KNOWN_FIXES`, off by default. Exceptions are the contract MUSTs listed in section 12 | register rule, contract 9 |
| 9 | D-028 is implemented as proposed (a FAIL verdict and sidecar on an internal error, never a PASS) | plan section 10 |
| 10 | Engine-generated messages use a new prefix `engine:`; they are never allowlisted and never downgraded by `--min-severity` | section 8 |

### 1.2 What this phase does and does not deliver

Delivered now: this design, the stubs, and the interface freeze. Not delivered: any behaviour. The first vertical slice (WP-01 to WP-11)
must reproduce `tests/conformance/golden/clean.json` exactly after the conformance normaliser (walk-through in section 16). Everything
else (31 scanner ids and 16 tool wrappers) is Phase 3 and Phase 4; until each exists the engine reports it as not ported (section 7.4).

### 1.3 Change control of the interface

The signatures, constants and tables in the stubs are frozen from the moment this document is merged. A package may add private helpers
(names starting `_`) and may fill in constants documented as "filled by the implementation". Any other change (a signature, a new public
name, a new scanner id, a new coverage state, a new message prefix) needs an **amendment**: a pull request that changes the stub, this
document and the affected tests together, reviewed by the architect. A package that finds a contract/design disagreement files it as
an amendment request and carries on with the stub's behaviour.


### 1.4 Fail-open review

The judging question is "does anything fail open?". Every place where the bash engine reads an unexamined input as clean, and what the design does about it. "Residual" means the Python engine still behaves like bash by default, for a reason
given, and the entry is in section 12 or 17 with the recommended fix.

| Place | Bash | Python engine | Section |
|-------|------|---------------|---------|
| a tool that is installed but not written yet | n/a | coverage `skipped:`/`partial:` + WARN; `coverage_complete` false; cut-over gated | 7.4 |
| a scanner not written yet | n/a | WARN per file + `partial`; a sniffed RTF is not read as text | 7.4 |
| a scanner raises | `set -e` abort or silent | non-downgradable FAIL for that file; run continues | 7.5 |
| a scanner returns without recording | n/a | FAIL `engine:scanner_error:<id>:no_outcome` | 7.5 |
| a file cannot be read | `grep ... 2>/dev/null` reads it as clean | FAIL `engine:file_unreadable:<reason>` | 5.1, 8.3 |
| a directory cannot be listed | `find ... 2>/dev/null` loses it | WARN + `partial` on L4 and L5 | 8.3 |
| a wrapper raises, or returns no state | n/a | FAIL `engine:tool_error` + `skipped:<tool> wrapper failed`; never `ran` | 10.1 |
| a tool crashes or prints garbage | `ran`, zero findings (A15); ClamAV: malware | not `ran`; a WARN; ClamAV exit other than 0/1 is not malware | 10.3 |
| a hostile line (ReDoS) | `grep` is linear | linear matcher for any buffer with a line over 8 KiB; no per-line cap; measured | 9.2 |
| per-file time budget reached | n/a | WARN + `partial` (residual: a file built to burn 120 s gets a WARN, not a FAIL; the same posture as `jar:inspection_incomplete`; gate on `coverage_complete`) | 9.3 |
| a pattern that is invalid | silently inert forever | exception at import, reported as a load error and a not-ported scanner | 9.1 |
| an internal error | abort, no report, no sidecar | FAIL verdict, FAIL sidecar, report if possible, `PASS` unreachable | 6 |
| engine errors in the allowlist | n/a | `engine:` messages are never allowlisted and never below the threshold | 8.3 |
| hostile `.transit-allow.json` / `.transitignore` | followed through symlinks, any size | regular non-symlink file of at most 1 MiB, else absent (can only remove exceptions) | 5.1, D-036 |
| relative scan directory in diff mode | scans nothing and passes (A19) | compared by absolute path | D-019 |
| `.transitignore` of `*` | passes with nothing scanned and no trace (A4) | residual by default (copy); switch D-004 adds the WARN | 12.1, 17 |
| a NUL byte in a file | `excl` rules silent (D-029), credential formats silent (D-014) | residual by default (copy); switches | 12, 17 |
| shebang with arguments | no shell analysis (D-031) | residual by default (copy); switch | 12, 17 |
| gitleaks reading the repository's own config | possible unless forced | S8 in the wrapper | 10.3 |
| a missing or empty verdict | callers treat as FAIL | the same; `PASS` is printed once, last, after both sidecars | 6 |

## 2. Evidence that shaped the design

Everything below was run on this host (bash 5.2, GNU grep 3.11, Python 3.10.20 / 3.11.17 / 3.12.3 / 3.13.16, running as root).

| # | Finding | How it was measured | What it forces |
|---|---------|--------------------|-----------------|
| F1 | **None of the bash engine's helper files can be imported safely.** `transit.containers.pdf` raises `SystemExit(0)` at import (a silent exit with status 0, which reads as PASS); `jar`, `office`, `scanners.manifests`, `tools.scancode` and `report_json` raise `IndexError`; `tools.gitleaks` imports only because it swallows the exception and would read `sys.argv[1]` and write to stdout. Their headers say "also importable by the Python engine"; that is wrong | `python3 -I -c "import transit.<module>"` with `sys.argv == ['x']` for each of the 12 existing modules | section 3.3: no import; four are run as programs, three are ported; a lint forbids importing them |
| F2 | `rx`'s `budget=` is only as good as the regex engine's signal polling. One hostile line (`curl x ` repeated) against `curl[^\|]*http://`: 10 KB 0.03 s, 30 KB 0.24 s, 70 KB 0.78 s, 150 KB 1.8 s, 300 KB 4.0 s, 600 KB **8.9 s**, 5 MB **74 s**, all with `budget=0.25`. The linear matcher (`rx.dfa_search`) needs 0.001, 0.001, 0.002, 0.005, 0.008, 0.020 s on the same lines | timing script over `rx.search_lines(..., budget=0.25)` and `rx.dfa_search` | section 9.2: a buffer with a line longer than `long_line_bytes` skips `re` and uses the linear matcher |
| F3 | `rx.time_limit` **cannot be nested**: leaving the inner block cancels the outer timer (`getitimer` returns 0.0 afterwards) | nested `with rx.time_limit(5): with rx.time_limit(0.05):` | section 9.3: no engine-level SIGALRM; the per-file budget is a deadline checked between rules |
| F4 | The linear matcher is fast on ordinary text: 1.8 MB of short lines in 0.08 s (about 45 ns per byte) against 0.002 s for `re`. every one of the 285 patterns of the inventory that translate has a linear matcher; `KNOWN_CRED_EXCL`, a shell variable that is not in the inventory, contains a back-reference and has none, so it is applied only to short matched strings | `rx.dfa_available` over `tests/conformance/patterns.json` | `re` stays the default for short-line buffers; the exclusion is never run on a whole line (section 9.4) |
| F5 | A glob emulation that tests every visited entry with the pattern `D` against the whole relative path and against each suffix that starts after a `/`, pruning matched directories, gives **exactly** the files that `find <root> -path` with bash's prune expression lists, on 24 pattern sets (`docs`, `a/b`, `*.log`, `docs/`, `/h.py`, `!keep`, `*`, `sub/*`, `?.py`, `[ab].py`, `*/docs`, `weird dir`, ...) over a 16-file tree with spaces, dots and hidden files | `find` with the exact expression of `scan_pipeline.sh` against a Python walker | `Exclusions.excludes` (section 5, `files.py`); the 3rd and 4th `-path` forms of bash (`D/*`) are redundant once ancestors are pruned |
| F6 | `transit/rx.py` has an invalid escape sequence in the `_DFA` docstring (`\B`, `\<`, `\>`). Python 3.12 and 3.13 print a `SyntaxWarning` the first time the file is compiled (cold `__pycache__`); `python -W error` turns it into a `SyntaxError` | `python3.12 -W error` compile of every file under `transit/` | open question 1: a one-character fix (`r"""`) in a file this task may not edit |
| F7 | The routing tables extracted from `classify_file` (109 extensions, 7 basename arms), the 34 family keys of `build_pdf_filetypes.FAMILIES`, the 14 excluded directories, the `standards` lists, the 18 provider names and the 9 missing-tool texts are all equal to the reference sources | scripted comparison of `dispatch.py`, `scanners/__init__.py`, `config.py`, `layers.py` and `credentials.py` with `build_pdf_filetypes.routed_patterns()`, `FAMILIES`, `report_json.py` and `scan_pipeline.sh` | those tables are real data in the stubs and are not re-derived by anyone |
| F8 | In bash a shebang line with arguments is **not** routed: `#!/bin/bash -e` matches none of `#!*/bash`, `#!*/sh`, ... (the glob must end in `/bash`) and the file falls to the MIME check, so an extensionless script with `#!/bin/bash -e` gets no shell analysis | `case` statement run in bash 5.2 against 7 shebang lines; `fnmatch.fnmatchcase` agrees | D-031 (section 12): copied by default, switch available |
| F9 | The known-credential rules, the private-key rule (`rx.after_context` then a fold then `rx.search_lines`) and `binary="skip"` work as the design needs: a real PEM body is found, a file-type signature, prose and a placeholder body are not; a token is found in text, hidden by a NUL in the first 32 KiB with `binary="skip"`, found with `binary="text"` | small script over `transit/rx.py` | the algorithms in `universal.py` / `credentials.py` docstrings are implementable as written |
| F10 | All 21 stub modules import with no output, no SIGALRM change, no file created, on Python 3.10, 3.11, 3.12, 3.13; the import graph between them is acyclic | `check_stubs.py`, an AST import-graph walk | section 3.2 |

## 3. Module map

### 3.1 Every file

"New" files are the stubs delivered with this design. "Existing" files are not touched by this phase.

| File | Status | Responsibility |
|------|--------|----------------|
| `scan_pipeline.py` | new | The entry point. Refuses Python older than 3.10 with a readable message, puts its own directory first on `sys.path` (the launcher runs it with `-I`, which does not), and calls `transit.pipeline.main(sys.argv[1:], os.environ)`. Nothing else; exits with the returned status. |
| `transit/__init__.py` | existing | Package docstring. |
| `transit/config.py` | new | Contract 2. Parses the environment once into an immutable `Config` (work directory, verbosity, `MIN_SEVERITY` word and number, `RUN_SCA`/`RUN_SCANCODE`, staged-data directories, `REPO_INPUT`, `TMPDIR`, the local timestamp) plus the engine's own `Limits`, the divergence switches and the notices to print. Also owns the constant tables every module shares: the 14 excluded directories, the nine coverage layer ids (seven required, two optional), the `standards` lists, the exit codes. A leaf: imports nothing from the engine. |
| `transit/console.py` | new | Contract 3.1, S1, S2, D-017. The only module that writes to stdout or stderr. `sanitise` replaces C0, DEL, C1, bidi controls and undecodable bytes by `?`; `Console` prints `[INFO]`/`[OK]` on stdout (quiet suppresses), `[WARN]`/`[FAIL]` on stderr (never suppressed), the verdict line, the progress line, and a sanitised traceback. Swallows a closed pipe. A leaf. |
| `transit/cli.py` | new | Contract 1. Strips `--*` words, takes the first three positionals, runs the four refusal checks in order (usage, directory, report directory, scanning name), removes trailing slashes, and returns `Args`. Creates nothing. A leaf. |
| `transit/findings.py` | new | Pure functions of a finding message: the one severity classifier (6.3), the structured record builder (5.3), the allowlist parser and token matching (6.2, A10, S15), `json_safe` (S4, D-023), `neutralise_detail` (S7), and the path helpers `relative_to_scan_dir` and `join_scan_path`. No regular expressions, no I/O. A leaf. |
| `transit/verdict.py` | new | The run state that bash keeps in globals (section 4): verdict, per-file status and messages, event counters, the findings stream, the coverage block and its "incomplete" notes. `record_pass`/`record_warn`/`record_fail` implement 6.1 and 6.2 exactly; `snapshot()` freezes the state for the report; `abort()` implements the D-028 end. The only object that is mutated during a run. |
| `transit/files.py` | new | The file system side: `prepare_work_dirs`, `Exclusions` (built-in names and `.transitignore`, 8.2 to 8.4, with a hand-written `glob_match`), `DiffSelection` (8.6), `files_for_scan` (8.5), `FileView` (one file read once, with `first_line`, `has_long_line`, `flat`, `target`), `TempArea` (3.5, S16) and `compute_hashes` (`source.sha256`, `repo_hash`). No regex is compiled here: `.transitignore` is repository text. |
| `transit/rx.py` | existing, finished | The ERE-to-`re` translator and the grep helpers (`search_lines`, `matching_lines`, `search_excl`, `search_flat`, `only_matching`, `after_context`), the linear matcher, the rule registry and `time_limit`. The only place a rule regex is compiled. Imported as is. |
| `transit/rules/__init__.py` | new | The rule-table machinery: `Match`/`AllOf`/`AnyOf` conditions, `RuleSpec` rows, `RuleSet` (compiles through `rx`, registers with `rx.rule`), `SearchPolicy`, `Target`, and the two evaluation functions `evaluate` and `run_ruleset` that implement the search policy of section 9.2 and the deadline of 9.3. Never records anything. |
| `transit/tools/__init__.py` | new (replaces the one-line docstring) | Everything about running external programs safely: `ToolLocator` (`command -v`), `run_process` (argument list, no shell, new session, enforced timeout, bounded capture), `run_helper_script`, `child_env` (offline variables), the wrapper protocol (`ToolWrapper`, `ToolRequest`, `ToolOutcome`, `Record`) and `load_wrappers`. Defines the policy for an installed tool without a wrapper. |
| `transit/tools/gitleaks.py` | existing | **Program** (reads `sys.argv`). Not run and not imported by the Python engine; test oracle for the gitleaks wrapper's pure parser. |
| `transit/tools/scancode.py` | existing | **Program**. Same: oracle for the ScanCode wrapper's parser. |
| `transit/containers/__init__.py` | existing | Package docstring (safe to import). |
| `transit/containers/office.py` | existing | **Program** (1,766 lines): reads a document, writes a text view, prints `FACT` lines. Run by the office scanner via `tools.run_helper_script("office", ...)`. |
| `transit/containers/jar.py` | existing | **Program**. Run by the jar scanner via `run_helper_script("jar", ...)`. |
| `transit/containers/pdf.py` | existing | **Program** (raises `SystemExit(0)` at import). Run by the PDF scanner via `run_helper_script("pdf", ...)`. |
| `transit/scanners/__init__.py` | new (replaces the one-line docstring) | The registry (`KNOWN_SCANNERS`, `ScannerSpec`, `load_registry`, `Registry.unported`), the `ScanContext` every scanner receives, and the guard (`invoke`, `guard`) that turns a scanner's failure into a recorded FAIL. |
| `transit/scanners/manifests.py` | existing | **Program**. Run by the `package.json`/`composer.json` scanner via `run_helper_script("manifests", ...)`. `load_registry` never imports it (`SCRIPT_MODULES`). |
| `transit/scanners/universal.py` | new | Layer 4: the universal rules that run on every file before its own scanner (CWE-798, CWE-321 with its header-then-body test, the known formats, the certificate note, three CWE-22 rules, five WARN rules). Not registered; called by `layers`. |
| `transit/scanners/credentials.py` | new | The 18 known-credential-format rules and the JWT warning as a library function shared by the universal layer, the jar scanner and the office scanner. Owns the `grep -I` semantics and the placeholder exclusion. |
| `transit/scanners/python_lang.py` | new | Scanner `python`: Bandit (via `ctx.file_tool`) plus six pattern rules. |
| `transit/scanners/shell.py` | new | Scanner `shell`: ShellCheck plus five pattern rules. |
| `transit/scanners/doc.py` | new | Scanners `docs` (`.md .txt .rst`) and `json` (`.json`): one inline credential rule each. |
| `transit/scanners/requirements.py` | new | Scanner `manifest.requirements`: five rules on `requirements*.txt` and `constraints*.txt`. |
| `transit/scanners/unknown.py` | new | The pseudo scanner `unknown`: shebang routing by delegation, then the MIME check (`file(1)`), else PASS. |
| `transit/dispatch.py` | new | `classify_file` (8.8 rules 2 to 5) over the route tables `BASENAME_ROUTES`, `EXT_ROUTES`, `SHEBANG_ROUTES`, the RTF and Flat-OPC probes, `lower_ext`, `routed_patterns`. Calls scanners through a callback; imports no scanner. |
| `transit/layers.py` | new | Layer orchestration: `ToolSlot` tables (the exact missing-tool texts of 5.1 and 7), `run_slot` (the generic whole-directory tool driver, S9), layers 1, 2, 3, 6, the per-file loop for layers 4 and 5 (`run_file_layers`), the layer-3 offline notes, `finalise`, `run_all`. Generic: a Phase 4 package adds a wrapper file and edits nothing here. |
| `transit/report.py` | new | Contract 3.3, 3.4, 4: `report_paths`, `build_report` (the dict of section 4, sorted, JSON-safe), `render_html` and `html_escape` (S3, D-017), `write_atomic` (S5), `write_reports`, `write_sidecars`. A pure-function replacement for `report_json.py`. |
| `transit/report_json.py` | existing | **Program** (needs `REPORT_*` variables). Not used by the Python engine; the oracle `tests/engine/test_report.py` compares `build_report` with. |
| `transit/pipeline.py` | new | `main(argv, environ)`: the 14 steps of section 6, the D-028 handler, signals, the exit status. Nothing imports it except `scan_pipeline.py`. |
| `tests/engine/__init__.py` | new | Documents the test layout and puts the repository root on `sys.path`. |

### 3.2 Layering

```
leaves (stdlib only):   config   console   cli   findings                       rx (existing)
                          │         │              │                              │
                          │         └─────┬────────┘                              │
                          │             verdict (console, findings)               rules (rx)
                          │                                                       │
                          ├────────────── files (config, rules) ◄─────────────────┤
                          ├────────────── tools (config)                          │
                          │                                                       │
                          └──► scanners/__init__ (config console files rules tools verdict)
                                   ▲                  ▲
                scanners/{universal,credentials,python_lang,shell,doc,requirements,unknown}  (scanners, rules)
                                   │
                dispatch (files) ──┤
                                   ▼
                              layers (cli config console dispatch files scanners tools verdict)
                                   │                     report (cli config files verdict, findings)
                                   └──────────┬──────────┘
                                           pipeline  ◄── scan_pipeline.py
```

Rules (a lint in `tests/engine/test_lints.py` enforces each): no import cycle; nothing under `transit/scanners/` or `transit/rules/` imports
`transit.verdict`, `transit.console`, `transit.layers`, `transit.pipeline` or `transit.report`; nothing imports `transit.layers` or
`transit.pipeline` except `pipeline`/`scan_pipeline.py`; `import re` appears only in `transit/rx.py` and in the existing helper programs;
`print(` and writes to `sys.stdout`/`sys.stderr` appear only in `transit/console.py` and `scan_pipeline.py`; no module-level mutable state
in a scanner module (the bash `PS_FAILED` global must become a local); `subprocess` is imported only by `transit/tools/__init__.py`.
Importing a package (`transit.scanners`, `transit.tools`, `transit.rules`) has no side effect: discovery runs in `load_registry` and
`load_wrappers`, never at import.

### 3.3 The existing helper files: programs, not modules (evidence F1)

| File | Import probe (`sys.argv == ['x']`) | What it does when run | Decision |
|------|------------------------------------|-----------------------|----------|
| `transit/rx.py` | imports, no side effect | a library | **imported** |
| `transit/containers/office.py` | `IndexError` | argv `<document> <view file> <ext>`; arms `SIGALRM`; writes the view; prints `FACT` lines | **run as a program** by the office scanner: `run_helper_script("office", [doc, view, ext], cfg=...)`; 1,766 lines of logic that both engines must share byte for byte until the bash engine is retired |
| `transit/containers/jar.py` | `IndexError` | argv `<archive> <view file>`; arms `SIGALRM`; prints `FACT` lines | **run as a program** (jar scanner) |
| `transit/containers/pdf.py` | **`SystemExit(0)`** | argv `<pdf> <names out> <searchable out>` | **run as a program** (PDF scanner). Importing it would end the engine with status 0 |
| `transit/scanners/manifests.py` | `IndexError` | argv `<manifest>`; prints `FACT` lines | **run as a program** (package manifest scanner) |
| `transit/tools/gitleaks.py` | imports only because it swallows the error | reads a gitleaks JSON report, prints `file \x01 line \x01 rule \x00` | **not run**: the gitleaks wrapper ports the 6 lines as a pure function; the script is the oracle in its test |
| `transit/tools/scancode.py` | `IndexError` | prints `LEVEL\|path\|message` lines | **not run**: the ScanCode wrapper ports it; the `\|` line protocol cannot carry a file name that contains `\|` or a newline (a mis-attributed finding), so a pure function returning records is both safer and simpler |
| `transit/report_json.py` | `IndexError` (and `KeyError` on `REPORT_VERDICT`) | needs seven NUL-delimited stream files and 13 environment variables | **not run**: `report.build_report` is the pure function; the script is the oracle in `test_report.py` |

How a helper program is run: `tools.run_helper_script(name, args, cfg=cfg, timeout_s=...)` starts `[sys.executable, "-I", <path>, *args]` with the
environment of `tools.child_env` (so the `JAR_*` and `OFFICE_*` limits of contract 2 reach it), no shell, a timeout of at least the helper's
own budget plus its 10 s alarm margin, stdout captured and parsed by the scanner, and the view file in the run's `TempArea`. The helpers
print `FACT` lines; the scanner owns the `fail_map`/`warn_map` vocabulary of contract 5.1. The zipapp of plan decision 5 (`.pyz`) needs the four
programs as real files: `HELPER_SCRIPTS` paths are resolved by one function, so Phase 6 extracts them to a private directory at start-up
without touching a scanner.

## 4. Shared state and who may mutate it

Bash keeps the run in globals and associative arrays. The Python engine has **one** mutable object, `verdict.Verdict`, and a handful of immutable
values. Every row below was checked against `scan_pipeline.sh`.

| Bash | Python | Mutated by |
|------|--------|-----------|
| `GLOBAL_VERDICT` | `Verdict.verdict` (property; starts `PASS`, flips to `FAIL` once, never back) | `Verdict.record_fail` (a surviving FAIL), `Verdict.abort` |
| `FILE_STATUS[path]` | `Verdict` private map, read through `status_of` and `Snapshot.file_status` | `record_pass` / `record_warn` (only if the file has no status) / `record_fail` (always FAIL). Switch D-012: worst-of |
| `FILE_MSG[path]` | `Snapshot.file_message` (the `"[WARN] a \| [FAIL] b \| "` accumulation) | `record_warn`, `record_fail` |
| `FINDINGS[path]` | `Snapshot.fail_messages` (`"msg \| msg \| "`) | `record_fail` |
| `PASS_COUNT`, `WARN_COUNT`, `FAIL_COUNT` | `Snapshot.counters` (`pass_`, `warn`, `fail`): event counters, 6.1 | `record_*` |
| the findings stream `$FINDINGS_JL` | `Snapshot.findings` (`FindingRecord`s, in memory, no temp file) | `record_fail` |
| `ALLOW_MAP` | `findings.Allowlist` (immutable), held by `Verdict` | built once by `pipeline` step 6 |
| `MIN_SEVERITY`, `SEV_THRESHOLD` | `Config.min_severity`, `Config.sev_threshold`, passed to `Verdict(...)` | `config.load_config` only |
| `LAYER_COVERAGE[...]` | `Verdict` base states + "incomplete" notes, folded by `snapshot()` | `record_layer`, `note_incomplete`, `abort` |
| `DIFF_FILES_ONLY`, `DIFF_FILES_SET` | `files.DiffSelection` (immutable) | `files.load_diff_selection` |
| `EXTRA_EXCLUDE_DIRS`, `FIND_PRUNE_ARGS`, `SEMGREP_EXCLUDES`, `CLAMSCAN_EXCLUDES` | `files.Exclusions` (immutable) | `files.load_exclusions` |
| `WORK_DIR`, `OFFLINE*`, `RUN_SCA`, `RUN_SCANCODE`, `VERBOSITY`, `TIMESTAMP`, `REPO_INPUT` | `Config` (frozen) | `config.load_config` only |
| `SCAN_DIR`, `REPORT_DIR`, `SCANNING_NAME` | `cli.Args` (frozen) | `cli.parse_args` only |
| `PS_FAILED` (a module-level flag the PowerShell rules set) | a local variable or a return value inside `powershell.py` | forbidden as module state: the lint rejects module-level mutable state in scanner modules |
| `KNOWN_CRED_NAMES/PATS/ALL/EXCL` | constants of `credentials.py` | none |
| `DEFAULT_EXCLUDE_DIRS` | `config.DEFAULT_EXCLUDE_DIRS` | none |
| temporary files and directories | `files.TempArea` | `pipeline` creates and cleans it; scanners ask `ctx.temp.new_file(...)` |
| progress line state | inside `Console` | `Console.progress`, `clear_progress` |
| the cache of `has_cmd` | `tools.ToolLocator` | `ToolLocator.find` (cache only) |

Who may call what:

| Caller | May call |
|--------|----------|
| `pipeline` | constructs everything; the only caller of `Verdict.snapshot`, `Verdict.abort`, `report.*` and `files.compute_hashes` |
| `layers` | every `Verdict` method except `snapshot`/`abort`; builds `ScanContext`s |
| a scanner | only `ScanContext` (`record_pass/warn/fail`, `run_rules`, `search`, `file_tool`, `delegate`, `note_incomplete`, `finish`, `temp`, `view`). It never receives a `Verdict`, `Console`, `Config` setter or `Registry`. A scanner's `ctx.cfg` is read-only |
| a tool wrapper | nothing in the engine: it receives a `ToolRequest` and returns a `ToolOutcome`; `layers`/`ScanContext` record on its behalf |
| `report` | `Snapshot` (immutable) only |

The ordering rule that makes per-file results reproducible: `layers.run_file_layers` runs the universal layer, then the family scanner, for one file at a
time, in the byte order of `rel`. A file's status is decided by the first event that sets one (6.1, A12); the universal layer therefore decides
PASS-versus-WARN for a file with a WARN from both. The order of events inside a scanner is the bash order (the messages of one file appear in the report
in that order); it is not contract, but it keeps `diff` output readable.

## 5. Public API: what each module promises

The exact signatures are in the stubs; Appendix A prints them (generated from the stubs, so it cannot drift). This section collects the cross-cutting
promises: what is sanitised, where, and what is raised.

### 5.1 The trust boundary

"Repository text" is a file name, an archive or part name, file contents, a tool's output, an exception message, `.transit-allow.json`,
`.transitignore`, `.diff_files`. It is hostile. Where it is made safe:

| Repository text reaches | Made safe by | Test |
|-------------------------|--------------|------|
| the console (stdout/stderr) | `console.sanitise` inside every `Console` method; callers pass text as it is | S1: names with ESC, CR, TAB, DEL, U+009B, U+202E, a literal `\033`; every byte of both streams is printable or LF |
| the JSON report | `findings.json_safe` on every string in `build_report`; `json.dumps` writes strict UTF-8; control characters are JSON-escaped | S4: golden `hostile_non_utf8_name`, `hostile_escape_name`; a strict parser reads the file |
| the HTML report | `report.html_escape` on every interpolated value | S3: golden `hostile_html_name`; no `<img` / `<script` from a name |
| a message used for severity | `classify_severity` reads only the fixed position of a `semgrep[` message; `neutralise_detail` for archive/part names; a producer may pass `severity=` explicitly | S7: a jar entry `a:LOW:b` still FAILs |
| a shell | never: `tools.run_process` takes an argument list, `shell=False`; a path given to a tool is absolute or follows `--` | S6: the 8 hostile names of E13b; a lint forbids `shell=True`, `os.system`, `os.popen`, `eval`, `exec` in `transit/` |
| a path that is opened | the engine opens only: paths produced by its own walker (`os.scandir`), `<scan_dir>/.transit-allow.json` and `<scan_dir>/.transitignore` via `files.read_repo_config_file` (regular file, not a symlink, at most 1 MiB), `<WORK_DIR>/.diff_files`, and files it created in `TempArea`. A path reported by a tool is mapped with `files.contained_path` and used as a dictionary key, never opened | S14, S15 |
| a regular expression | a rule pattern is compiled by `rx` from engine data; `.transitignore` globs are matched by `files.glob_match` (no regex); `findings` uses no regex at all | S12: fuzz gate; the lint on `import re` |
| a file size | `FileView.data()` reads at most `Limits.max_file_bytes` (a larger file is FAIL `engine:file_unreadable:too_large`) | S12 |

### 5.2 What is raised

| Module | Raises | Never raises |
|--------|--------|--------------|
| `cli.parse_args` | `UsageError` | anything else |
| `config.load_config` | `ValueError` for an unknown `TRANSIT_FIXES` id | on a bad number (defaults) |
| `findings.*` | nothing (total functions); `parse_allowlist` swallows its own failures | |
| `verdict.Verdict` | `ValueError` for an unknown layer id or a malformed coverage state (a programming error) | for any message text |
| `files.*` | `OSError` from `prepare_work_dirs`; `FileReadError` from `FileView.data`; `ValueError` for a bad `name` | for a hostile `.transitignore` (S15) |
| `rules.*` | `ValueError`/`rx.EREError` at `RuleSet` construction; `ScanBudgetExceeded` from `evaluate`; `rx.RegexTimeout` only for a pattern with no linear matcher | at `run_ruleset` (it returns `skipped`/`timed_out`) |
| `tools.*` | `ValueError` for an empty argv, `KeyError` for an unknown helper | `run_process` never raises for a failing child |
| `scanners.invoke` / `guard` | nothing except `BaseException` (signals) | it turns every `Exception` into a recorded FAIL (section 7.5) |
| `report.*` | `OSError` from the writers; `ValueError` for a bad verdict | |
| `pipeline.main` | nothing | it converts everything into an exit status (section 6, D-028) |

## 6. Control flow of a run

`pipeline.main` performs these steps in order. The right-hand column is the contract section the step satisfies; the owning module is in brackets.

| # | Step | Contract |
|---|------|----------|
| 0 | `scan_pipeline.py`: Python >= 3.10 or exit 1 with a message; `sys.path.insert(0, <its directory>)`; `sys.exit(main(sys.argv[1:], os.environ))` | 3.2 (exit status) |
| 1 | `main` installs handlers: SIGTERM/SIGHUP/SIGINT raise `SystemExit(128+n)` in the main thread (so `finally` runs), SIGPIPE is ignored, **SIGALRM is left alone** (section 9.3). A provisional `Console("normal")` serves steps 2 and 3 | 3.2 (killed by a signal: no verdict, 128+n) |
| 2 | `cli.parse_args(argv)` [cli]: strip `--*`, positional 1..3, checks in order: usage, directory, report directory, scanning name; trailing slashes off. On `UsageError`: `Console.error(message)`, **return 1**, nothing written, `WORK_DIR` not created | 1.1 to 1.5, 3.2 row "argument refused" |
| 3 | `config.load_config(environ)` [config]. `ValueError` (bad `TRANSIT_FIXES`) is a refusal like step 2. Then `Console(cfg.verbosity)`; print `cfg.notices` (OFFLINE ignored, rejected `MIN_SEVERITY`/`VERBOSITY`) | 2, D-020, D-025 |
| 4 | `report.report_paths(args, cfg)` [report]; `files.prepare_work_dirs(cfg.work_dir)` [files] creates `reports/`, `quarantine/` (0700), `approved/`. `OSError` here: print `FAIL`, **return 1** (nothing can be written) | 2, 3.3, 3.4, D-027, D-028 |
| 5 | `temp = files.TempArea(cfg.tmpdir)` [files]; cleanup is registered three ways: the `finally` of `main`, `atexit`, the signal path | 3.5, S16 |
| 6 | Allowlist: `files.read_repo_config_file(scan_dir, ".transit-allow.json")` then `findings.parse_allowlist(raw, strict=cfg.fix("D-010"))` [files, findings]; notes to stderr; info line `Allowlist: n exception(s) loaded` | 6.2, A10, S15 |
| 7 | `files.load_exclusions` and `files.load_diff_selection(cfg.work_dir, cfg.since_commit, scan_dir)` [files]. A stale `.diff_files` without `SINCE_COMMIT` is a stderr WARN only. With switch D-004 the exclusion WARN is recorded in step 8 | 8.2 to 8.6, S15 |
| 8 | `verdict.Verdict(scan_dir, allowlist, threshold=..., min_severity=..., console=...)` [verdict]; build `layers.RunEnv` with `tools.ToolLocator`, `tools.load_wrappers()`, `scanners.load_registry()`; print the info lines `Starting scan`, `Standards` | 6, 7 |
| 9 | `files.files_for_scan(scan_dir, exclusions, diff)` [files] | 8.5, 8.6 |
| 10 | `layers.run_all(env, scan)` [layers]: layer 1 (4 slots), layer 2, layer 3 (or `skipped:disabled (RUN_SCA is not true)`), layers 4 and 5 over the file list with `universal.scan` then `dispatch.classify_file` per file, layer 6 (or `skipped:disabled (RUN_SCANCODE is not true)`), `finalise` | 7, 8.1, 8.8, S9 |
| 11 | `files.compute_hashes(scan_dir)` [files] | 4 (`source.sha256`, `repo_hash`) |
| 12 | `snapshot = verdict.snapshot()`; `report.build_report(...)` [report]; `report.write_reports(...)`: JSON then HTML, each `write_atomic` | 3.4, 4, S3, S4, S5 |
| 13 | `report.write_sidecars(paths, verdict)`: `.scan_verdict` then `.scan_report_json`, in `WORK_DIR` | 3.3 |
| 14 | `Console.info("JSON report : ...")` lines, then `Console.verdict("PASS"/"FAIL")` as the **last** stdout write; `main` returns 0 for PASS, 1 for FAIL | 3.2 |
| * | `finally`: `temp.cleanup()`; flush streams | 3.5, S16 |

D-028, the internal-error path (steps 5 to 13). `except Exception` in `main` calls, each inside its own `try` so one failure cannot stop the next:
`Console.exception("internal error", exc)` (sanitised, stderr); `Verdict.abort(type(exc).__name__)` (the FAIL `engine:internal_error:<class>` on `__global__`
and `skipped:engine aborted (<class>)` for every required layer without a state); then steps 11 to 13 with the hash replaced by 64 zeros if it cannot be
computed; and finally `Console.verdict("FAIL")`, **return 1**. If everything fails, `FAIL` is still printed and 1 returned. `PASS` is printed only by step 14 of a
run that reached it, and `Console.verdict` is called exactly once (a test asserts the verdict line appears once, last). A scanner's exception never gets here:
section 7.5 contains it to its file.

Ordering guarantees a test pins: nothing is written before step 2 succeeds; the reports exist before the sidecars; the verdict line comes after both sidecars;
a refused argument leaves `WORK_DIR` uncreated; the report directory is never created.

Exit status: 0 only for a completed PASS. The status never distinguishes WARN from PASS (3.2).

## 7. Scanners: declaration, registry, dispatch

### 7.1 Declaring a scanner

A scanner is a function `fn(ctx: ScanContext) -> bool` plus a `ScannerSpec` in a module-level tuple named `SCANNERS`. The registry finds the module; nothing else
lists it. A rule table is a module-level `RuleSet`. Complete example (the shape every Phase 3 scanner follows):

```python
# transit/scanners/python_lang.py
from transit.rules import Match, RuleSet, RuleSpec
from transit.scanners import ScanContext, ScannerSpec

RULES = RuleSet("python", (
    RuleSpec(id="python/01-os-command-injection", outcome="fail", message="CWE-78:OS_command_injection_risk",
             cond=Match(r"\b(os\.system|subprocess\.call|subprocess\.Popen|commands\.getoutput)\s*\("), source="scan_python"),
    RuleSpec(id="python/05-open-redirect", outcome="warn", message="CWE-601:potential_open_redirect",
             cond=Match(r"(redirect|HttpResponseRedirect)\s*\(\s*request\."), source="scan_python"),
    # ... one row per record_fail / record_warn of scan_python, in bash order
))

def scan(ctx: ScanContext) -> bool:
    fired = False
    run = ctx.file_tool("bandit")                       # bash: has_cmd bandit ... record_warn "$f" "bandit missing"
    if run.status == "missing":
        ctx.record_warn("bandit missing")
    for rec in run.records:                             # empty unless status == "ok"
        if rec.kind == "fail":
            ctx.record_fail(rec.message, severity=rec.severity)
            fired = True
    fired = ctx.run_rules(RULES).fired or fired         # bash: the grep_check calls, in order
    ctx.finish(fired)                                   # bash: $failed || record_pass "$f"
    return True

SCANNERS = (ScannerSpec(id="python", family="python", fn=scan, bash_function="scan_python", tools=("bandit",), ported=True),)
```

Rules for a scanner module: (1) its name is not in `SCRIPT_MODULES` and does not start with `_`; (2) importing it compiles its tables and does nothing else
(no I/O, no signal, no output); (3) no module-level mutable state; (4) it never imports `verdict`, `console`, `layers` or `pipeline`; (5) it records at least
one event per file; (6) it flips `ported=True` only when complete; (7) the messages are the bash messages, character for character.

### 7.2 What a scanner receives: `ScanContext`

| Member | Meaning |
|--------|---------|
| `path`, `rel`, `basename`, `ext`, `sniffed`, `cfg`, `view`, `temp` | identity and read-only environment. `path` is the key in `file_results` (`scan_dir/rel`) |
| `record_pass()`, `record_warn(msg, file=None)`, `record_fail(msg, file=None, severity=None, downgradable=True) -> Outcome` | forward to `Verdict` for this file (or `file=` for a whole-directory finding such as the archive path a jar view belongs to) |
| `run_rules(ruleset, data=None) -> RuleOutcome` | evaluate a table (optionally against derived bytes), record each hit in table order, return `fired` (any `fail` rule matched, even if downgraded) |
| `search(cond, data=None) -> bool`, `target(data=None)` | for logic that is not one table row |
| `finish(fired)` | `record_pass` unless `fired` (bash `$failed \|\| record_pass`) |
| `file_tool(name) -> FileToolRun` | run a per-file external tool or learn why not (7.4) |
| `delegate(scanner_id, sniffed=False) -> bool` | run another scanner on the same file under the guard |
| `note_incomplete(reason, layer=...)`, `check_deadline()` | say part of the work was not done; raise `ScanBudgetExceeded` if the per-file deadline passed |

It returns `True` ("handled; at least one event recorded") or `False` ("not mine", legal only when `ctx.sniffed`).

### 7.3 The table: 34 families, 37 scanner ids

`build_pdf_filetypes.FAMILIES` has 34 keys; `scanners.KNOWN_SCANNERS` maps the 37 ids onto them (two families have two ids; `unknown` is a pseudo family). The routes are
`dispatch.BASENAME_ROUTES`, `EXT_ROUTES` and `SHEBANG_ROUTES` (verified equal to `classify_file`, F7). "Wave" is the work package that implements it (section 14).

| Family | Scanner id(s) | Bash function | Routed by | Per-file tool / helper | Module | Wave |
|--------|--------------|---------------|-----------|------------------------|--------|------|
| python | `python` | `scan_python` | `.py`, `#!*python*` | bandit | `python_lang.py` | 1 (WP-09) |
| setuppy | `setuppy` | `scan_setup_py` | `setup.py`, `conanfile.py` | | `setup_py.py` | 2-D |
| js | `js` | `scan_javascript` | `.js .ts .jsx .tsx .mjs .cjs`, `#!*node*` | semgrep (JS) | `javascript.py` | 2-A (+3-F) |
| java | `java` | `scan_java` | `.java` | | `java.py` | 2-A |
| php | `php` | `scan_php` | `.php`, `#!*php*` | | `php.py` | 2-A |
| ruby | `ruby` | `scan_ruby` | `.rb`, `#!*ruby*` | | `ruby.py` | 2-A |
| go | `go` | `scan_go` | `.go` | | `go.py` | 2-A |
| c | `c` | `scan_c_cpp` | `.c .cpp .cc .h .hpp` | cppcheck | `c_cpp.py` | 2-B (+3-F) |
| rust | `rust` | `scan_rust` | `.rs` | | `rust.py` | 2-B |
| kotlin | `kotlin` | `scan_kotlin` | `.kt .kts` | | `kotlin.py` | 2-B |
| csharp | `csharp` | `scan_csharp` | `.cs` | | `csharp.py` | 2-B |
| shell | `shell` | `scan_shell` | `.sh .bash .zsh .ksh`, shebangs | shellcheck | `shell.py` | 1 (WP-09) |
| powershell | `powershell.text`, `powershell.xml` | `scan_powershell`, `scan_powershell_xml` (+`_ps_rules`) | 8 extensions, `#!*pwsh*` | | `powershell.py` | 2-F |
| batch | `batch` | `scan_bat` | `.bat .cmd` | | `bat.py` | 2-F |
| makefile | `makefile` | `scan_makefile` | `.mk .mak .make`, `Makefile*` | | `makefile.py` | 2-D |
| cmake | `cmake` | `scan_cmake` | `.cmake`, `CMakeLists*.txt` | | `cmake.py` | 2-D |
| gradle | `gradle` | `scan_gradle` | `*.gradle`, `*.gradle.kts`, `gradle*.properties` | | `gradle.py` | 2-D |
| manifest | `manifest.package_json`, `manifest.requirements` | `scan_package_json`, `scan_requirements` | `package.json`, `composer.json`; `requirements*.txt`, `constraints*.txt` | helper `manifests.py` | `package_manifests.py` (2-E); `requirements.py` (1, WP-10) | 1 + 2-E |
| xml | `xml` | `scan_xml` | `.xml .pom` (+ Flat-OPC probe) | | `xml_scan.py` | 2-E |
| yaml | `yaml` | `scan_yaml` | `.yml .yaml` | | `yaml_scan.py` | 2-C |
| terraform | `terraform` | `scan_terraform` | `.tf .tfvars .hcl` | checkov | `terraform.py` | 2-C (+3-F) |
| docker | `docker` | `scan_docker` | `Dockerfile*` | hadolint | `docker.py` | 2-C (+3-F) |
| html | `html` | `scan_html` | `.html .htm .xhtml` | | `html_scan.py` | 2-E |
| pdf | `pdf` | `scan_pdf` | `.pdf` | helper `pdf.py` | `pdf_scan.py` | 3-A |
| ooxml | `ooxml` | `scan_office` | 17 extensions; Flat-OPC probe | helper `office.py` | `office_scan.py` | 3-C |
| legacy_office | `legacy_office` | `scan_office` | 9 extensions | helper `office.py` | `office_scan.py` | 3-C |
| odf | `odf` | `scan_office` | 12 extensions | helper `office.py` | `office_scan.py` | 3-C |
| rtf | `rtf` | `scan_office` | `.rtf`; RTF head of `.md/.txt/.rst`/unknown | helper `office.py` | `office_scan.py` | 3-C |
| sql | `sql` | `scan_sql` | `.sql` | | `sql.py` | 2-B |
| json | `json` | `classify_file` (inline) | `.json` | | `doc.py` | 1 (WP-10) |
| docs | `docs` | `classify_file` (inline) | `.md .txt .rst` | | `doc.py` | 1 (WP-10) |
| binary | `binary` | `scan_binary` | `.so .dll .dylib .exe .elf .bin` | strings | `binary.py` | 2-G (+3-F) |
| archive | `archive` | `scan_archive` | `.zip .tar .gz .tgz .bz2 .xz` | unzip | `archive.py` | 2-G (+3-F) |
| jar | `jar` | `scan_jar` | `.jar .war .ear .aar` | helper `jar.py` | `jar_scan.py` | 3-B |
| *(pseudo)* | `unknown` | `scan_unknown` | everything else | file(1) | `unknown.py` | 1 (WP-10) |

The four office-family ids share one function (`office_scan.scan`), registered four times, because bash's `scan_office` is one function behind four `case` arms.

### 7.4 What happens to something that is not written yet (never silently skipped)

| Case | Detected by | Recorded |
|------|-------------|----------|
| a routed scanner id has no spec, or `ported=False` | `scanners.invoke` | WARN `engine:scanner_not_ported:<id>` on the file; `note_incomplete("L5_per_language_sast", "python engine has not ported scanner <id> yet")`; `invoke` returns `True` so a sniffed RTF is never read as plain text |
| a whole-directory tool (gitleaks, detect-secrets, clamscan, yara, semgrep, trivy, scancode) is installed, no wrapper | `layers.run_slot` | coverage `skipped:python engine has not ported <tool> yet` and WARN `engine:tool_not_ported:<tool>` on `__global__` |
| a per-file tool (bandit, shellcheck, cppcheck, hadolint, checkov, semgrep for JS, file(1), strings, unzip) is installed, no wrapper | `ScanContext.file_tool` | `FileToolRun("not_ported")`; once per run the same WARN; `note_incomplete("L5_per_language_sast", "python engine has not ported <tool> yet")`, which makes the L5 state `partial:...` |
| the tool is not installed | `layers.run_slot` / `file_tool` | the exact bash WARN and state of contract 5.1 / 7 (`gitleaks missing — secret scan skipped`, `skipped:gitleaks not installed`, per file `bandit missing`) |

Why `partial:` for L5 and `skipped:` for the others: layer 5 did run (every file got its pattern rules); one of its tools did not. Both start with something other than `ran`,
so both keep `coverage_complete` false and put the layer in `coverage_gaps` (contract 7). The gate for cut-over (Phase 6) is `Registry.unported() == ()` and no tool without a wrapper;
`tests/engine/test_cutover.py` (WP-V) fails while either is non-empty; it does not exist in Wave 1, so nothing is red before Wave 3 is merged.

### 7.5 Errors inside a scanner (contract 11, D-028, S9)

`scanners.invoke` (and `guard` for the universal layer) wraps every scanner call. What it records, all non-downgradable (`engine:` messages are never allowlisted and never
below the threshold, 8.3):

| What happened | Recorded | Coverage note |
|---------------|----------|---------------|
| per-file deadline passed (`ScanBudgetExceeded`) | WARN `engine:scan_incomplete:<id>:time_budget` | `partial:per-file time budget reached` on L5 |
| `FileReadError(reason)` | FAIL `engine:file_unreadable:<reason>` | |
| `rx.RegexTimeout` (a pattern with no linear matcher) | FAIL `engine:regex_timeout:<id>` | |
| any other `Exception`, `NotImplementedError` and `MemoryError` included | FAIL `engine:scanner_error:<id>:<ExceptionClass>`; the sanitised traceback goes to stderr only | |
| the scanner returned `True` and recorded nothing | FAIL `engine:scanner_error:<id>:no_outcome` | |
| the scanner returned `False` and the context was not sniffed | FAIL `engine:scanner_error:<id>:returned_not_mine` | |
| `BaseException` (SIGTERM, Ctrl-C) | propagates to `main` | |

Why FAIL and not WARN: a crashing scanner means a file was not examined; a hostile repository must not be able to craft a file that crashes a parser and gets only a WARN. The
exception **text** is never put in the report (it can contain a file name); only the class name is.

## 8. Reports, finding records, coverage and engine messages

### 8.1 Where each coverage state comes from

| Layer id | State and text | Written by |
|----------|----------------|-----------|
| `L1_secrets_gitleaks` | `ran` / `skipped:gitleaks failed (exit <rc>)` | `gitleaks_wrapper` (Wave 3-D) via its `ToolOutcome.layer_state` |
| | `skipped:gitleaks not installed` | `layers.run_slot` from `LAYER1_SLOTS` |
| | `skipped:python engine has not ported gitleaks yet` | `layers.run_slot` |
| `L1_secrets_entropy`, `L1_malware`, `L1_ioc_yara`, `L2_owasp_cwe`, `L3_dependency_cve`, `L6_licence` | the table of contract 7: `ran`, `skipped:<tool> not installed`, `skipped:no ClamAV signatures available`, `skipped:yara or rules directory missing`, `skipped:no semgrep rulesets staged for offline use`, `skipped:trivy database not staged for offline use`, ... | the tool's wrapper for the states that depend on the tool's data or result; `layers.run_slot` for "not installed" and "not ported"; `layers.run_layer3` / `run_layer6` for `skipped:disabled (RUN_SCA is not true)` and `skipped:disabled (RUN_SCANCODE is not true)` |
| | `partial:rulesets missing (<names>)` | `semgrep_wrapper` (D-005: the run continues; S9) |
| `L4_patterns`, `L5_per_language_sast` | `ran` after the loop, even with zero files; `partial:<reasons>` when `note_incomplete` was called | `layers.run_file_layers`; reasons from `Verdict.note_incomplete` |
| any required layer without a state after an internal error | `skipped:engine aborted (<class>)` | `Verdict.abort` |

`coverage_gaps` is the sorted list of ids whose final state does not start with `ran`; `coverage_complete` is its emptiness (`report.build_report`). The set of ids is closed (nine);
`Verdict.record_layer` rejects any other. `L1_ioc_yara` and `L6_licence` follow bash (absent in the cases A6 and A8) **except** where S9 requires a state: a ScanCode that failed is
`skipped:scancode failed (exit <rc>)` (D-006).

### 8.2 Finding records

`findings.build_record` is `_emit_finding` (contract 5.3), `findings.classify_severity` is `_classify_severity` (6.3). Both are pure and are called by `Verdict.record_fail`:
the severity that decides the `--min-severity` downgrade and the severity written in the record are the same value, computed once (a unit test asserts it for every message in the
golden files). A producer that carries a severity as a field passes `severity=` (a Semgrep result, a ScanCode vulnerability); it is used for both. Rule tables leave `severity=None`
(bash behaviour) and a unit test asserts that an explicit `RuleSpec.severity` equals `classify_severity(message)`. The records known to be wrong in bash (A16, D-016: bandit's `rule_id` is
` HIGH:B602`, `CVE-2021-44228:...` has tool `unknown`) are **copied** until D-016 is decided; the conformance normaliser then needs no alias.

### 8.3 Engine messages (new prefix `engine:`)

Contract 5.2 requires a new prefix to be added to its list; `engine` is added by this design (amendment of the contract, recorded as D-032/D-033 in section 12). Grammar `engine:<kind>[:<detail>]`;
`<detail>` is engine-generated (a scanner id, a rule id, an exception class name, a reason word), never repository text.

| Message | Kind | File | Raised by |
|---------|------|------|-----------|
| `engine:tool_not_ported:<tool>` | WARN | `__global__` | `layers.run_slot`, `ScanContext.file_tool` |
| `engine:scanner_not_ported:<id>` | WARN | the file | `scanners.invoke` |
| `engine:scan_incomplete:<id or ruleset>:time_budget` | WARN | the file | `invoke`, `ScanContext.run_rules` |
| `engine:unreadable_directories(<n>)` | WARN | `__global__` | `layers.run_file_layers` |
| `engine:scanner_load_error:<module>`, `engine:wrapper_load_error:<module>` | WARN | `__global__` | `layers.finalise` |
| `engine:file_unreadable:<reason>` | FAIL | the file | `layers.run_file_layers`, `invoke` |
| `engine:regex_timeout:<id>` | FAIL | the file | `ScanContext.run_rules`, `invoke` |
| `engine:scanner_error:<id>:<class>` (`no_outcome`, `returned_not_mine` as class) | FAIL | the file | `invoke`, `guard` |
| `engine:tool_error:<tool>:<class>` | FAIL | `scan_dir` | `layers.run_slot` |
| `engine:internal_error:<class>` | FAIL | `__global__` | `Verdict.abort` (D-028) |

Properties: a message starting `engine:` is never matched by the allowlist and never turned into `LOW_SEV(...)` (`Verdict.record_fail`, `Allowlist.lookup`), so a repository cannot configure
an internal error away; its structured record has tool `engine`, category `security`, rule id the second segment.

### 8.4 Where each report key comes from

| Key | Source |
|-----|--------|
| `verdict`, `decision`, `status_color`, `status_background` | `Snapshot.verdict`, derived in `build_report` |
| `scan_name` | `ReportPaths.scan_name` (argument 3 or `Config.timestamp`) |
| `source.directory`, `directory` | `Args.scan_dir`; `source.sha256`, `repo_hash`: `files.compute_hashes` |
| `coverage`, `coverage_complete`, `coverage_gaps` | `Snapshot.coverage` |
| `timestamp` | the UTC time `pipeline` passes as `now_utc` (second resolution) |
| `repo_input` | `Config.repo_input` |
| `standards` | `report.standards(run_sca, run_scancode)` |
| `summary` | `Snapshot.counters` (`pass_` is written as `pass`) |
| `findings` | `Snapshot.findings`, sorted by (file, rule_id, line or 0, message) |
| `findings_by_file` | `Snapshot.fail_messages` with one trailing `" \| "` removed |
| `file_results` | `Snapshot.file_status` and `file_message` (D-009 strip) |

The report validates against `docs/report.schema.json` and passes every invariant of `tests/conformance/check_schema.py`; `tests/engine/test_report.py` runs that checker on reports built
from a `Verdict` driven through the scenarios of the golden files.

## 9. Rule tables, regular expressions and time

### 9.1 The shape of a rule table and how it maps to bash

One `RuleSpec` is one `record_fail`/`record_warn` guarded by one `grep` condition. Fields: `id` (`<scanner id>/<NN>-<slug>`, unique across the engine), `outcome` (`fail`|`warn`), `message` (the
bash string, exact), `cond` (a `Match`, or `AllOf`/`AnyOf` of them), `severity` (normally `None`), `applies_to` (basenames and extensions inside a scanner that branches on the name), `source`.

| Bash call | `Match(...)` | `rx.rule` label | `binary` |
|-----------|-------------|-----------------|----------|
| `grep_check P F` | `Match(P)` | `line` | `text` (no `-I`: a NUL byte or invalid UTF-8 changes nothing, E8) |
| `grep_check_i P F` | `Match(P, ci=True)` | `line_i` | `text` |
| `grep_check_excl P X F` | `Match(P, excl=X)` | `excl` | `grep` (bash's NUL blindness, D-029; `text` with the switch) |
| `grep_flat P F` | `Match(P, mode="flat")` | `flat` | `text` |
| `_pdf_has F P` | `Match(P)` (or code calling `rx.rule(..., mode="line_a")`) | `line_a` | `text` |
| `{ grep_check_i A F && grep_check_i B F; }` | `AllOf((Match(A, ci=True), Match(B, ci=True)))` | each leaf as above | |
| `A \|\| B` | `AnyOf((...))` | | |
| `grep -qIE`, `grep -ohIE` (known credentials) | code in `credentials.py` | `line` | `skip` |
| `grep -E -A5 \| tr \| grep -E` (private key) | code in `universal.private_key_present` | | |

The pattern text is taken from `tests/conformance/patterns.json` (the record whose `enclosing_function` and `pattern` match); it is the text bash hands to `grep` after quote resolution. `tests/engine`
asserts (a) every `Match.pattern` and `Match.excl` of every table occurs in `patterns.json`, and (b) after Wave 2, that every `patterns.json` entry of mode `line|line_i|excl|flat` occurs in some table or
in a waiver list. Compilation goes through `rx.ere_to_py`; `RuleSet` registers each leaf with `rx.rule(<id>, pattern, mode=<label>, excl=...)`, so `python3 tests/conformance/pattern_fuzz.py` and
`rx.registered()` see every engine rule. An invalid pattern is an exception when the module is imported, which the registry reports as a load error (in bash it is a rule that never fires and never
complains).

About the three modes the task statement lists (`line | flat | file`): `line` and `flat` are `Match.mode`; bash has no mode that lets one pattern span a line break except `flat`, so "file" is `AllOf`, a conjunction of line searches each taken over the whole file (the PowerShell
`fetch` and `execute` halves on different lines). The case-insensitive flag is `Match.ci` (forced for `flat` and `excl`, as `grep -iE` is in bash), the exclusion is `Match.excl`.

Semantics: a `fail` rule that matches sets `fired` whatever `record_fail` did with it. Rules run in table order; a time-skipped rule is reported (9.3).

### 9.2 The search policy (measured, F2 to F4)

`rules.evaluate(Match)` chooses the matcher per buffer, not per rule:

```
line mode:   if target.has_long_line and rx.dfa_available(c):  rx.dfa_search(c, data, binary=b)            # linear
             else:                                             rx.search_lines(c, data, binary=b, budget=policy.rule_budget_s)
flat mode:   v = target.flat()   (b"" over 5 MB: no match)
             if len(v) > policy.long_line_bytes and rx.dfa_available(c): rx.dfa_search(c, v)
             else: rx.search_lines(c, v, budget=policy.rule_budget_s)
excl mode:   if target.has_long_line and DFA for both: candidates = rx.dfa_matching_lines(pat, data);
                                                       hit if some candidate line has no match of excl (rx.dfa_search on the slice)
             else: rx.search_excl(pat, excl, data, binary=b, budget=policy.rule_budget_s)   # binary="grep" when policy.excl_nul_blind
```

`long_line_bytes` is 8192. At that line length the worst measured `re` search costs about 0.05 s even when the alarm is late, so a file of any size made of lines under 8 KiB costs
`0.25 s + one line` per rule at worst, after which `rx` finishes the buffer with the linear matcher. A longer line never meets `re`. **No per-line cap exists anywhere**: padding a payload
past a cap would hide it (PYTHON_PORT_PLAN status block); a line of any length is searched, linearly.

`FileView.has_long_line()` is computed once per file with `rx.lines_over(data, long_line_bytes)` (O(1) for a file smaller than the limit).

### 9.3 SIGALRM, deadlines and who may arm what

| Timer | Armed by | Scope |
|-------|----------|-------|
| `rx.time_limit(budget)` | `rx.search_*` when `budget=` is passed | one search, main thread only; **not nestable** (F3) |
| `SIGALRM` in `jar.py` / `office.py` | the helper program, in its own process | the helper's own budget plus 10 s |
| `subprocess` timeouts | `tools.run_process` | the child and its process group; no signal is used in the parent |
| per-file deadline | `layers.run_file_layers`: `time.monotonic() + Limits.file_budget_s` (120 s) at the start of the file, shared by the universal layer and the family scanner | checked **between** rules (`run_ruleset`, `ScanContext.check_deadline`); never by an alarm |
| the engine itself | nobody | there is **no** engine-level SIGALRM: arming one would be cancelled by the first `rx` search |

Consequences: a search is never wrapped in a second `time_limit`; the main thread is the only thread; `rules.evaluate` raises `RuntimeError` if called off the main thread. When the deadline passes, the
remaining rules of that file are returned as `skipped` and recorded as the WARN `engine:scan_incomplete:...:time_budget` plus a `partial` note (it is a resource limit, reported, like `jar:inspection_incomplete`).
The worst case for one file is therefore `file_budget_s` plus one rule's linear pass (about 45 ns per byte).

### 9.4 `rx.only_matching`, the flat view and memory

* `rx.only_matching` has no `budget=` and leftmost-first semantics. `credentials.py` calls it **only** on a line that `rx.matching_lines` (budgeted) already reported and that is not longer than
  `long_line_bytes`. For a longer matching line the provider is reported **without** the placeholder-exclusion test (fail closed; D-030). `KNOWN_CRED_EXCL` has a back-reference and so no linear matcher (F4); it
  is applied to the short matched text only, never to a line.
* `FileView.flat()` is built once per file and only if a `flat` rule asks (at most 5 MB, `rx.FLAT_CAP`).
* One `FileView` exists at a time and is released after its file. A file larger than `Limits.max_file_bytes` (1 GiB) is the FAIL `engine:file_unreadable:too_large`. There is no `mmap`: `rx` takes `bytes`.

## 10. External tools

### 10.1 The protocol

A tool wrapper is a module `transit/tools/<tool>_wrapper.py` (the suffix is what `load_wrappers` looks for; the two old programs `gitleaks.py` and `scancode.py` are never imported)
exposing `WRAPPERS: tuple[ToolWrapper, ...]`. A `ToolWrapper` subclass sets `name` (the executable), `layer` (the coverage id, or `L5_per_language_sast`), `scope`
(`directory`|`file`), `missing_message` / `missing_state` and implements `run(request: ToolRequest) -> ToolOutcome`.

How it reports back:

| Question | Answer in the protocol |
|----------|------------------------|
| found / not found | `ToolLocator.find(name)`; decided by `layers.run_slot` / `ScanContext.file_tool` *before* the wrapper runs, so the wrapper only runs when the tool exists |
| exit status | `ProcessResult.returncode` (and `status` `ok`/`timeout`/`signal`/`not_found`/`error`); the wrapper maps it |
| parsed result | `ToolOutcome.records` (the verdict calls, bash order) and, for a directory tool, `layer_state` |
| timeout | `ProcessResult.status == "timeout"` (the process group was killed); the wrapper returns `layer_state="skipped:<tool> timed out"` and a WARN record (S9) |
| "I could not understand the output" | `layer_state="skipped:<tool> output not parseable"` and a WARN; never `ran` with zero findings |
| what is shown to a human | `ToolOutcome.notes`, sanitised excerpts for the console (S10) |

`layers.run_slot` applies the outcome: `pass` -> `record_pass(file)`, `warn` -> `record_warn(file, message)`, `fail` -> `record_fail(file, message, severity=...)` (so the allowlist and the
threshold apply to a tool's findings exactly as to a rule's), then `record_layer(slot.layer_id, outcome.layer_state)`. A per-file wrapper returns `layer_state=None`; `ScanContext.file_tool` hands its
records to the scanner. The wrapper never records, never prints, never reads the verdict.

### 10.2 Process rules (S6, S9, S10)

Every external program is started by `tools.run_process`: an argument list, no shell, `stdin` closed, a new session (the process group is killed on timeout), stdout and stderr captured (bounded, `MAX_CAPTURE_BYTES`; `output_file` for big
JSON), the environment of `tools.child_env` (the four offline variables; `GITLEAKS_CONFIG*` removed for gitleaks). A path derived from the repository is absolute or follows `--`. A wrapper treats an exit status it does not document as a
failure of the tool, not as "no findings". `subprocess` is imported nowhere else (lint).

### 10.3 Facts each wrapper author needs (taken from the reference script, `git show 4b2746b:scan_pipeline.sh`)

| Tool | Layer, scope | Invocation in bash | Records and states |
|------|--------------|--------------------|--------------------|
| gitleaks | `L1_secrets_gitleaks`, directory | `detect --no-git --source <scan_dir> --config <generated [extend] useDefault = true> --report-format json --report-path <private file>`, plus `--no-banner --redact --log-level error --gitleaks-ignore-path <empty dir> --ignore-gitleaks-allow` only where `gitleaks detect --help` lists them; stdout/stderr discarded; `GITLEAKS_CONFIG*` removed | per leak FAIL `gitleaks:<RuleID, ":" -> "_">:line<N>` (file made absolute under `scan_dir`), at most 200, then FAIL `gitleaks:more_leaks_not_listed_<n-200>` on `scan_dir`; exit 0: `record_pass(scan_dir)`, `ran`; exit 1 with no readable report: FAIL `gitleaks:secrets_detected`, `ran`; exit >= 2: FAIL `gitleaks:scan_error_exit_<rc>`, `skipped:gitleaks failed (exit <rc>)`; WARN `gitleaks:inline_allow_comments_not_disabled (...)` when the flag is missing; WARN `gitleaks:repository_allowlist_ignored (...)` on `scan_dir` when `.gitleaks.toml`/`.gitleaksignore` exist. S8 a to h |
| detect-secrets | `L1_secrets_entropy`, directory | `detect-secrets scan <scan_dir>`, sum the lengths of `results` | hits > 0: FAIL `detect-secrets:<n>_high_entropy_string(s)` on `scan_dir`, else `record_pass(scan_dir)`; `ran` only if the exit status and the JSON were understood (bash: always `ran`, A15) |
| clamscan | `L1_malware`, directory | `clamscan -r --quiet [--database=<CLAMAV_DB_DIR>] --exclude-dir=<name> ... <scan_dir>`; the database is `CLAMAV_DB_DIR/*.cvd\|*.cld`, else `/var/lib/clamav/*.cvd\|*.cld`, else the WARN `OFFLINE:ClamAV signature database is empty ...` | exit 0 `record_pass(scan_dir)`; exit 1 FAIL `clamav:malware_detected`; any other exit `skipped:clamav failed (exit <rc>)` + WARN (D-015, S9); no signatures: `skipped:no ClamAV signatures available` |
| yara | `L1_ioc_yara`, directory | `yara -r <rule> <scan_dir>` for each `WORK_DIR/yara-rules/*.yar`; present only if the directory exists | any output: FAIL `yara:ioc_match:<rule basename>`; `ran` after a run (D-008); `skipped:yara rules directory has no .yar files` |
| semgrep | `L2_owasp_cwe`, directory | for each staged `SEMGREP_RULES_DIR/{owasp-top-ten,cwe-top-25,security-audit,secrets}.yaml`: `semgrep --config=<yaml> --quiet --json --no-autofix --metrics=off --exclude-dir <name> ... <scan_dir>` | per result FAIL `semgrep[<ruleset>]:<check_id>:line<N>:<SEV>:<message cut to 120>` (severity passed as a field); rule sets missing: WARN `OFFLINE:semgrep rulesets not staged (...)` and `partial:rulesets missing (<names>)` (the run goes on, D-005); none: `skipped:no semgrep rulesets staged for offline use`; `<ruleset>` stays the YAML path until D-018 is decided |
| trivy | `L3_dependency_cve`, directory | `trivy fs --quiet --exit-code 0 --format json --skip-db-update --skip-java-db-update --offline-scan --cache-dir <TRIVY_CACHE_DIR> <scan_dir>`, only if `TRIVY_CACHE_DIR/db/*` exists | else WARN `OFFLINE:trivy database not staged in ...` and `skipped:trivy database not staged for offline use` (no "no known CVEs" claim, D-015); count > 0: FAIL `trivy:<n>_vulnerable_dependencies`, else `record_pass(scan_dir)` |
| scancode | `L6_licence`, directory | `scancode --license --copyright --package --json-pp <WORK_DIR/reports/scancode_<ts>.json> --quiet --timeout 120 <scan_dir>`; first the WARN `OFFLINE:scancode CVE lookup disabled ...` | parse = pure port of `tools/scancode.py` returning records: WARN `licence:<spdx>` (risky and score >= 70), `scancode_vuln:<id>[<SEV>] in <pkg>==<ver>` FAIL for CRITICAL/HIGH else WARN; failure: `skipped:scancode failed (exit <rc>)` / `skipped:scancode produced no report` (D-006); the verdict changes only through `record_fail` (D-007) |
| bandit | `L5`, file | `bandit -q -l -i <file>` | output has `Severity: (MEDIUM\|HIGH)`: FAIL `bandit:Severity: <LEVEL>:<B id>` |
| shellcheck | `L5`, file | `shellcheck -S warning <file>` | non-zero: FAIL `shellcheck:warnings` |
| cppcheck | `L5`, file | `cppcheck --enable=all --quiet <file>` (stderr merged) | first `error:`/`warning:` text: FAIL `cppcheck:<text>` |
| hadolint | `L5`, file | `hadolint <file>` | non-zero: FAIL `hadolint:dockerfile_issue` |
| checkov | `L5`, file | `checkov -f <file> --quiet [--skip-download]` | count > 0: FAIL `checkov:<n>_CIS_IaC_findings` |
| semgrep (JS) | `L5`, file | bash: `semgrep --config=p/javascript --quiet --json --no-autofix <file>` | FAIL `semgrep:js:<n>_findings`. **This is a registry config: it needs the network, so in the forced-offline engine bash gets no result and still says `ran` (D-037).** The wrapper must not contact the registry; with no staged `javascript.yaml` it returns `failed` and the L5 note `semgrep javascript ruleset not staged for offline use` |
| file(1) | `L5`, file | `file --mime-type -b <file>` | `application/x-executable`, `x-sharedlib`, `x-dosexec` prefixes: FAIL `binary:unexpected_executable_mime:<mime>` |
| strings | `L5`, file | `strings <file>` piped through `grep -iE '(http://\|https://\|/etc/passwd\|/bin/sh\|exec\|shell\|reverse\|c2server)'` | FAIL `binary:IOC_strings_detected` (the filter runs in Python on the captured output) |
| unzip | `L5`, file | `unzip -l <file>` for `*.zip`; any line containing `..` | FAIL `CWE-22:zip_slip_path_traversal_in_archive` |

pip-audit, safety and npm audit are not ported (D-026: unreachable while offline is forced); only the two `OFFLINE:` notes of layer 3 remain (`layers.run_layer3`).

### 10.4 Policy for an installed tool without a wrapper

Section 7.4. In one sentence: the layer is `skipped:python engine has not ported <tool> yet` (or, for a per-file tool, L5 is `partial:`), a WARN says so, `coverage_complete` stays false, and
`Registry.unported()`/the wrapper table must be empty before cut-over. A wrapper that exists but raises is a different case: FAIL `engine:tool_error:<tool>:<class>` (section 7.5).

## 11. Test strategy

All engine tests are plain `unittest`, standard library only, one file per module under `tests/engine/`, runnable as `python3 -I -m unittest discover -s tests/engine`
(each module starts with the three `sys.path` lines of `tests/engine/__init__.py`; `-I` removes the current directory). Fixtures live in `tests/fixtures/`; a token-shaped string is **never** written
contiguously in a test or a document (build it from two halves at run time, as `tests/run_tests.sh` does).

Rules for every package: (1) **red before green** - run the new test file against the stub first (every test fails with `NotImplementedError`) and keep the evidence in the pull request;
(2) a **mutation check** - for each branch that implements a contract rule, break it on purpose and confirm the matching assertion goes red (the package lists the mutations it ran); (3) an oracle where one
exists: real `grep` (as `tests/conformance/test_rx.py`), real `find`, `sha256sum`, the old `report_json.py`, the old `tools/*.py`.

| Test file | Module | Must assert (beyond the obvious) |
|-----------|--------|----------------------------------|
| `test_config.py` | `config` | defaults and overrides of every variable of contract 2; `MIN_SEVERITY` `bogus`, `HIGH`, ` high`, `Critical`, empty, unset -> 3,3,3,4,3,3 (E15); the `OFFLINE=false` notice text; `RUN_SCA` true only for exactly `true`; an unknown `TRANSIT_FIXES` id raises; `TRANSIT_*` limits ignore `0` and `abc`; `timestamp` format; `Config` is frozen |
| `test_console.py` | `console` | S1 with the six hostile names (bytes of both streams printable or LF), S2 (`\033` literal kept), D-017 characters, quiet silences info/ok only, `verdict` accepts only PASS/FAIL, a `BrokenPipeError` is swallowed, progress only on a tty |
| `test_cli.py` | `cli` | the 19 argument variants of E4 with their exit-1 reasons, `--` words anywhere, trailing slashes (`/` kept), empty positional 2 honours 3, a symlinked directory, a file as directory, 150/151 characters, nothing created on refusal |
| `test_findings.py` | `findings` | `classify_severity` on the 23 messages of E6; `build_record` on the 26 messages of E6 including `engine:`; the 14 allowlist variants of E3 in both modes; `json_safe`; `neutralise_detail` (`a:LOW:b`); `join_scan_path`/`relative_to_scan_dir` for `/`; no `re` import |
| `test_verdict.py` | `verdict` | 6.1 first-writer table (E12) and the D-012 switch; counters (the clean scenario gives pass 4, warn 7); 6.2 order (allowlist before threshold, E21); the `ALLOWED:` and `LOW_SEV(` texts; `engine:` never downgraded; `Outcome` values; coverage validation; `note_incomplete` folding; `abort`; `snapshot` idempotent and immutable |
| `test_files.py` | `files` | F5: the 24 pattern sets against real `find`; `glob_match` against `find -path` on brackets, escapes, `*`; E2 variants; D-001/D-002; symlinks not listed; E17 diff variants and D-019; `compute_hashes` equals the `sha256sum` recipe and the three E19 values; `FileView`; `TempArea` modes and cleanup; `read_repo_config_file` refusals; unreadable directory in `ScanList.errors` |
| `test_rules.py` | `rules` | construction errors; `rx.registered()` contains every leaf; each mode against real `grep`; **a 600 KB hostile line finishes in under 1 s for each of the 28 table patterns of the slice** (the linear matcher measured 0.03 s at worst); deadline gives `skipped`; `RuntimeError` off the main thread; `AppliesTo`; `AllOf`/`AnyOf`; `binary` modes |
| `test_scanners.py` | `scanners/__init__` | discovery (skips `manifests`, `_x`, a module without `SCANNERS`), load errors (unknown id, family mismatch, duplicate, import failure), `unported()`, the eight outcomes of `invoke`, `ScanContext` recording and `finish`, `delegate` depth, the four `file_tool` statuses with fake wrappers; uses `tests/engine/support.py` |
| `test_dispatch.py` | `dispatch` | `routed_patterns()` equals `build_pdf_filetypes.routed_patterns()`; the 34 family keys; per-family extension sets equal `FAMILIES`; `UPPER.PY`; basename arm order; the 7 shebang lines of F8; every flow of `classify_file` with a fake `run` (xml chain, docs with RTF, unknown with RTF, unported returns True) |
| `test_layers.py` | `layers` | slot texts equal bash (F7); `run_slot` for not installed / not ported / ok / raising wrapper / no state; layers 3 and 6 disabled; the offline notes; `run_file_layers` with zero files, a vanished file, an unreadable directory, a per-file deadline, the universal layer guarded |
| `test_tools.py` | `tools` | `ToolLocator` cache and `PATH`; `run_process` timeout kills the group, output bounded, never a shell (`$(touch X)` stays an argument), `not_found`; `child_env`; `run_helper_script` against the four real helpers on a tiny input; `load_wrappers` ignores the old scripts; the not-ported WARN once per run |
| `test_report.py` | `report` | `build_report` equals the old `report_json.py` output on the same inputs; schema + invariants through `check_schema.py`; sorted output; `html_escape` (S3, D-017) and `render_html` on the two hostile names; `write_atomic` leaves no partial file when the replace fails and applies the umask; sidecar order; `report_paths` (relative report dir stays relative) |
| `test_universal.py`, `test_credentials.py` | L4 | one positive and one near-miss fixture per rule (`tests/fixtures/rules`), tokens built at run time; the CWE-321 cases of F9; a NUL file (grep rules fire, formats do not); a 600 KB line; `fired`/`downgrade` semantics |
| `test_python_lang.py`, `test_shell.py`, `test_doc.py`, `test_requirements.py`, `test_unknown.py` | scanners | each rule row (fail and near-miss); `fired` when the allowlist downgrades; the three bandit/shellcheck statuses; the shebang table; the RTF hand-off; the clean-fixture per-file results |
| `test_pipeline.py` | `pipeline` | in-process run of the clean fixture (last stdout line, exit 0, sidecars, no temporary file left); refusals leave `WORK_DIR` uncreated; D-028 (a `layers.run_all` that raises gives `FAIL`, a FAIL sidecar and a valid report); SIGTERM gives 143 and no temporary file; `Console.verdict` called once and last; nothing about the cut-over gate (that is `test_cutover.py`) |
| `test_entrypoint.py` | `scan_pipeline.py` | runs under `python3 -I` from another directory; the version message under `python3.9` when present |
| `test_cutover.py` | the repository (Wave 4) | `Registry.unported() == ()`; every key of `tools.DIRECTORY_TOOLS` and `tools.FILE_TOOLS` has a wrapper; no `engine:*_not_ported` message on the real-file corpora |
| `test_lints.py` | the repository | the import rules of 3.2; no `shell=True`/`os.system`/`eval`; no import of the seven helper programs; `compile()` of every file under `transit/` with warnings as errors (F6); no contiguous token in `tests/engine`; every message string in a rule table occurs in `scan_pipeline.sh` |

Conformance (run by CI for each package that touches the output): `python3 tests/conformance/conformance.py check --engine python --case clean` (Wave 1), then the cases whose scanners exist,
and `diff` for bash against Python; `python3 tests/conformance/check_schema.py` on a Python report; `python3 tests/conformance/pattern_fuzz.py --quick` filtered to the rules the package registered.

## 12. Divergences

### 12.1 Handling of the register's entries

`proposed` means copy bash; a switch is a name in `config.KNOWN_FIXES`, off by default. Four rows are not copied because the contract says MUST (S1, S9) or because copying bash would pass a repository with nothing examined (hard rule 6).

| Id | Phase 2 handling | Owner module |
|----|------------------|--------------|
| D-001, D-002 | closed in bash; implemented (directories only, relative to the root) | `files` |
| D-003 | copy (last line without newline dropped, CR kept); switch `D-003` | `files.load_exclusions` |
| D-004 | copy (no trace); switch `D-004` records `transitignore:exclusions_applied(<n> pattern(s))` on `__global__` | `files` (text), `pipeline` (records it, step 8) |
| D-005, D-006, D-007, D-008, D-015 | **Python behaviour** (S9 is a MUST: a layer that did not run is never `ran`, a crashing ClamAV is not malware, the verdict changes only through `record_fail`) | Wave 3 wrappers |
| D-009 | copy (`rstrip(" \| ")`); switch `D-009` | `report` |
| D-010 | copy (an odd entry drops the rest); switch `D-010` = `parse_allowlist(strict=True)` | `findings` |
| D-011 | copy; switch `D-011` = `Verdict(dot_matches_directory=True)` | `verdict` |
| D-012 | copy (first writer); switch `D-012` = `Verdict(first_writer=False)` | `verdict` |
| D-013 | copy (event counters) | `verdict` |
| D-014 | copy (`binary="skip"`); switch `D-014` reads files with NUL, bounded | `credentials` |
| D-016 | copy (records identical to bash, A16) until decided | `findings` |
| D-017 | **implemented** (contract S1/S3 MUST): bidi controls replaced, HTML control bytes escaped | `console`, `report` |
| D-018 | copy (YAML path as ruleset label) until decided | semgrep wrapper |
| D-019 | **implemented** (hard rule 6): diff-mode keys are `os.path.abspath` of both sides | `files` |
| D-020 | copy plus a console notice | `config` |
| D-021 | copy (overwrite) | `report` |
| D-022 | copy (`file(1)`); D-034 adds visibility | `unknown`, file wrapper |
| D-023 | copy (U+FFFD per invalid byte) | `findings.json_safe` |
| D-024 | implemented (sorted) | `report` |
| D-025 | copy (stderr notice only) | `config` |
| D-026 | drop (only the two `OFFLINE:` notes) | `layers` |
| D-027 | copy (`quarantine/` 0700 and `approved/` created) | `files` |
| D-028 | **implemented as proposed** | `pipeline`, `verdict` |

### 12.2 New entries this design proposes (to be appended to `docs/engine_divergences.md` by WP-12; status `proposed`)

| Id | Area | Bash behaviour | Python behaviour | Decision |
|----|------|----------------|------------------|----------|
| D-029 | grep rules, NUL | `grep_check_excl` on a file with a NUL byte can never match (the first `grep` prints a notice, the second reads nothing): one NUL silences `pip:vcs_requirement_not_pinned_to_a_commit` and every future `excl` rule (E8, rx docstring) | default copies (`SearchPolicy.excl_nul_blind`); switch `D-029` searches as text | needs-decision, recommend fix-in-python |
| D-030 | credential formats | `grep -o` has no line-length problem | a matching line longer than `long_line_bytes` is reported without the placeholder-exclusion test (`rx.only_matching` has no budget) | fix-in-python, fail closed, no switch |
| D-031 | shebang routing | `#!/bin/bash -e` (a shebang with arguments) matches no `case` pattern, so an extensionless script gets no shell analysis (F8) | default copies; switch `D-031` matches the interpreter word | needs-decision, recommend fix |
| D-032 | not-ported tools and scanners | n/a | coverage `skipped:python engine has not ported <tool> yet` / `partial:...`, WARNs `engine:tool_not_ported:<tool>`, `engine:scanner_not_ported:<id>`; disappears when nothing is unported | interim, implemented |
| D-033 | scanner and engine errors | a crashing scanner reads as "ran, found nothing" (D-015) or aborts the run | non-downgradable FAILs `engine:scanner_error`, `engine:file_unreadable`, `engine:regex_timeout`, `engine:tool_error`, `engine:internal_error`; `engine:` is never allowlisted | fix-in-python |
| D-034 | `file(1)` missing | unknown-extension files pass with no MIME check and no message (A22) | L5 `partial:file(1) is not installed: ...` when such a file was met | needs sign-off (changes a coverage state) |
| D-035 | resource limits | none | per-file budget (WARN + `partial`), unreadable directories (WARN + `partial`), file larger than 1 GiB (FAIL) | implemented |
| D-036 | repository configuration | `.transit-allow.json` and `.transitignore` are read through symlinks, any size | regular file, not a symlink, at most 1 MiB, else treated as absent with a console note (fewer exceptions, never more) | fix-in-python |
| D-037 | per-file Semgrep for JS | `--config=p/javascript` needs the registry; offline it returns nothing and L5 is `ran` | the wrapper never contacts the registry; no staged ruleset gives `failed` and a `partial` note | fix-in-python (Wave 3-F) |

## 13. Who owns each behaviour of the contract

Every behaviour of sections 1 to 9 has exactly one owning module (the one whose code makes the decision). "Helpers" are mechanisms the owner calls; they do not own the behaviour. A row whose owner is a Wave 2/3 module is
owned by a module that does not exist yet; the stub fixes its name and the registry reports it as not ported.

| Contract | Behaviour | Owner | Helpers |
|----------|-----------|-------|---------|
| 1.1 | options do not exist (`--*` words dropped) | `cli` | |
| 1.2 | the four refusals, in order, before any write | `cli` | |
| 1.3 | trailing slashes removed, nothing else done to the directory | `cli` | |
| 1.4, 1.5 | `scanning_name` rules; empty strings | `cli` | |
| 2 | every environment variable, defaults, `MIN_SEVERITY`, `VERBOSITY`, forced `OFFLINE`, `RUN_SCA`, `RUN_SCANCODE`, `REPO_INPUT`, `TMPDIR` | `config` | |
| 2 | the offline child environment; `JAR_*`/`OFFICE_*` reach the helpers | `tools` (`child_env`) | the helper programs parse the numbers themselves |
| 2, 3.3 | `WORK_DIR/{reports,quarantine,approved}` | `files` (`prepare_work_dirs`) | |
| 3.1 | console channels, quiet | `console` | |
| 3.2 | last stdout line, exit status | `pipeline` | `Console.verdict` prints |
| 3.3 | sidecar files and order | `report` | |
| 3.4 | report paths, atomic write, HTML content | `report` | |
| 3.5 | temporary files | `files` (`TempArea`) | `pipeline` calls `cleanup` |
| 3.6 | what `ai_transit.sh` and `generate_excel_report.py` read | `report` (keys and invariants) | |
| 4 | report keys | `report` | `verdict.Snapshot` |
| 4 | `findings[]` record fields | `findings` | |
| 4 | `source.sha256`, `repo_hash` | `files` (`compute_hashes`) | |
| 5.1 | message grammar of each producer | the producing module: a rule table, a wrapper, a container scanner | `findings` for the shared prefixes |
| 5.2 | prefix list (plus `engine:`, section 8.3) | `findings` (`build_record`) | |
| 5.3 | record derived from the message | `findings` | |
| 6.1 | the three states, first writer, counters | `verdict` | |
| 6.2 | `record_fail` steps; allowlist matching | `verdict` | `findings.Allowlist.lookup`, `allowlist_tokens` |
| 6.2 | `.transit-allow.json` parsing | `findings` (`parse_allowlist`) | `files.read_repo_config_file` reads the bytes |
| 6.3 | one severity classification | `findings` | |
| 7 | every coverage state | `layers` (writes them) | `verdict` stores and validates; wrappers return their own states |
| 8.1 | whole-directory tools versus per-file layers | `layers` | |
| 8.2, 8.3, 8.4 | built-in exclusions, how a name is applied, `.transitignore` | `files` | `config.DEFAULT_EXCLUDE_DIRS` is the data |
| 8.5 | what `find` lists | `files` (`files_for_scan`) | |
| 8.6 | diff mode | `files` (`load_diff_selection`) | |
| 8.7 | grep flags: `-I` versus not | `rules` (`Match.binary`) | `credentials` uses `skip` |
| 8.7 | binary and archive by extension | `binary`, `archive` (Wave 2-G) | |
| 8.7 | unknown extension: shebang then MIME | `unknown` | `dispatch.shebang_scanner` |
| 8.7 | RTF and Flat-OPC sniffing | `dispatch` | |
| 8.8 rule 1 | universal layer first | `layers` | `universal.scan` |
| 8.8 rules 2 to 4 | basename arms, lower-cased extension, inline rules | `dispatch` (arms), `doc` (inline rules) | |
| 8.8 rule 5 | every scanner records an outcome | `scanners` (`invoke` enforces, `ScanContext.finish`) | each scanner |
| S1, S2 | console is control-free; backslash text is data | `console` | |
| S3 | HTML escaped | `report` | |
| S4 | JSON always valid | `report` | `findings.json_safe` |
| S5 | report whole or not at all | `report` (`write_atomic`) | |
| S6 | no repository text reaches a shell | `tools` (`run_process`) | lint |
| S7 | severity never read from repository text | `findings` | `neutralise_detail` |
| S8 | gitleaks on our terms | `gitleaks_wrapper` (Wave 3-D) | |
| S9 | fail closed and say so | `layers` (`run_slot`, `finalise`), `scanners` (`invoke`) | every wrapper |
| S10 | tool output never echoed | `tools` | |
| S11 | containers never extracted, limits reported | `jar_scan`, `office_scan` (Wave 3-B/C) | the helper programs |
| S12 | hostile input costs bounded time | `rules` | `files.FileView.has_long_line`, `ScanContext` deadline |
| S13 | an allowlist can only lower, visibly | `verdict` | |
| S14 | the scanned directory is read-only | no module writes there; `ScanContext` has no write API | lint |
| S15 | hostile `.transit-allow.json` / `.transitignore` | `findings` (allowlist), `files` (`.transitignore`) | `files.read_repo_config_file` |
| S16 | temporary files private and removed | `files` (`TempArea`) | |
| 11 | A1 to A24 | section 12 | |

## 14. Work packages

Disjoint file ownership was checked by script: **27 packages, 139 files, no file owned twice**, every scanner id has exactly one module and every module one owner. Packages that say "all" can be built by
different engineers at the same time: they code against the frozen stubs, and only the *merge order* is constrained (column "Merges after"). A package may not edit a file it does not own; a needed
change is an amendment (1.3).

Shared test support: `tests/engine/support.py` (a fake `ScanContext`, a fake `Verdict` sink, a stub-tool directory builder, a temp-repository builder) is owned by WP-05 and lands first; every scanner package imports it.

### 14.1 Wave 1: Phase 2 completion (12 packages, all parallel; first vertical slice)

| Id | Owns exclusively | Implements | Consumes (frozen interfaces) | Acceptance tests | Merges after |
|----|------------------|------------|------------------------------|------------------|--------------|
| WP-01 | `transit/config.py`, `console.py`, `cli.py`, `tests/engine/test_config.py`, `test_console.py`, `test_cli.py` | `load_config`, `env_number`, `Config.fix`; `sanitise`, `Console`; `positional_words`, `scanning_name_error`, `parse_args` | nothing | section 11 rows for the three files; the byte-level S1 test; the 19 E4 variants. Mutations: drop the C1 range; drop the bidi range; accept 151 characters; do not lower-case `MIN_SEVERITY`; strip only the first `--` word | none |
| WP-02 | `transit/findings.py`, `verdict.py`, `tests/engine/test_findings.py`, `test_verdict.py` | everything in the two modules | `console.Console` (a fake with the same methods in tests) | section 11 rows; E6 (23 + 26 messages), E3 (14 variants), E12, E21; the clean scenario gives `pass 4, warn 7`. Mutations: threshold before allowlist; `record_warn` overwriting FAIL; per-file instead of per-event counters; drop the `engine:` exemption; `snapshot` returning live dictionaries | none |
| WP-03 | `transit/files.py`, `tests/engine/test_files.py` | the whole module | `config.Config/Limits`, `rules.Target`, `rx` | F5 against real `find` (24 sets), E2, E17, D-001/D-002, D-019, E19 hashes, `read_repo_config_file`, `TempArea` modes. Mutations: test the scan root against the exclusions; match files against built-in names; unsorted output; follow symlinks | none |
| WP-04 | `transit/rules/__init__.py`, `tests/engine/test_rules.py` | `Match`/`AllOf`/`AnyOf` validation, `RuleSet`, `evaluate`, `run_ruleset` | `rx` | section 11 row; the 600 KB hostile line under 1 s for each of the 28 table patterns of the slice (measured worst case of the linear matcher: 0.03 s); each mode against real `grep`. Mutations: always use `re`; skip the long-line test; nest `time_limit`; ignore the deadline | none |
| WP-05 | `transit/scanners/__init__.py`, `transit/dispatch.py`, `tests/engine/support.py`, `test_scanners.py`, `test_dispatch.py` | registry, `ScanContext`, `invoke`, `guard`; route tables' functions | `verdict.Verdict` (real once WP-02 is merged, fake before), `files.FileView`, `rules`, `tools` types | section 11 rows; `routed_patterns()` equals `build_pdf_filetypes.routed_patterns()`; the eight `invoke` outcomes. Mutations: let an exception escape; accept `no_outcome`; import `manifests` | WP-02, WP-04 |
| WP-06 | `transit/tools/__init__.py`, `transit/layers.py`, `tests/engine/test_tools.py`, `test_layers.py` | `ToolLocator`, `run_process`, `run_helper_script`, `child_env`, `load_wrappers`; `run_slot`, layers 1, 2, 3, 6, `run_file_layers`, `finalise`, `run_all` | `scanners.invoke`, `verdict`, `files`, `dispatch.classify_file` | section 11 rows; the four helper programs run on tiny inputs; `$(touch X)` stays an argument; timeout kills the group; the nine slot texts equal bash. Mutations: run a shell; record `ran` after a wrapper exception; swallow a missing layer | WP-02, WP-05 |
| WP-07 | `transit/report.py`, `tests/engine/test_report.py` | the whole module | `verdict.Snapshot`, `findings`, `files.SourceHashes`, `cli.Args`, `config` | `build_report` equals the old `report_json.py`; schema + invariants; S3 on both hostile names; atomic write failure leaves no file. Mutations: no escaping; non-atomic write; verdict before sidecars | WP-02 |
| WP-08 | `transit/scanners/universal.py`, `credentials.py`, `tests/engine/test_universal.py`, `test_credentials.py` | the 17 universal rows, `private_key_present`, `check_known_credentials` | `ScanContext`, `rules`, `rx` | one positive and one near-miss per rule; F9; NUL; a 600 KB line; D-030. Mutations: drop the body requirement; run the formats on a NUL file; apply the exclusion to a long line | WP-04, WP-05 |
| WP-09 | `transit/scanners/python_lang.py`, `shell.py`, `tests/engine/test_python_lang.py`, `test_shell.py` | both scanners and their tables | `ScanContext`, `rules` | every row (fail and near-miss); `fired` stays true after an allowlist downgrade; the clean fixture's `bandit missing` / `shellcheck missing`. Mutations: `finish` always passes; wrong order of bandit and rules | WP-04, WP-05 |
| WP-10 | `transit/scanners/doc.py`, `requirements.py`, `unknown.py`, `tests/engine/test_doc.py`, `test_requirements.py`, `test_unknown.py` | the five scanners | `ScanContext`, `rules`, `dispatch.shebang_scanner` | every row; the RTF hand-off; the shebang table of F8; `file(1)` missing note. Mutations: skip the RTF hand-off; route `#!/bin/bash -e` | WP-04, WP-05 |
| WP-11 | `transit/pipeline.py`, `scan_pipeline.py`, `tests/engine/test_pipeline.py`, `test_entrypoint.py`, and **one hunk** of `scan_pipeline.sh` (section 15) | `main` and the signal handlers | every module | `python3 tests/conformance/conformance.py check --engine python --case clean` prints `ok clean`; `check_schema.py` accepts the report; `TRANSIT_ENGINE=python bash scan_pipeline.sh` gives the same report; D-028 test; SIGTERM test; `tests/run_tests.sh` still passes | WP-01 to WP-10 (codes in parallel) |
| WP-12 | `tests/engine/test_lints.py`, `tests/conformance/family_diff.py`, `Dockerfile` (COPY line), `prepare_offline_install.sh` (file loop), `.github/workflows/ci.yml` (engine jobs), `docs/engine_divergences.md` (D-029 to D-037) | the lints of 3.2, `family_diff.py` (runs both engines on a directory holding only the fixtures routed to given scanner ids and prints per-file status and rule-id differences), CI job `python3 -I -m unittest discover -s tests/engine` and `conformance.py check --engine python`, `scan_pipeline.py` in the image and the offline bundle (`selfcheck.py` needs no change: it globs `*.py` and `transit/**/*.py`) | the stubs | `test_lints.py` fails on each forbidden construct (mutation per lint) and passes on the stubs, except the `-W error` lint, which needs open question 1 | none |

Wave 1 exit criterion (the first vertical slice): all of the above merged; `python3 -I -m unittest discover -s tests/engine` green; the clean fixture reproduces `golden/clean.json`; `Registry.unported()` lists exactly the 31 ids of Waves 2 and 3.

### 14.2 Wave 2: Phase 3 pattern scanners (7 packages, parallel with each other and with Wave 3)

They start the day this design is merged (they need only the stubs) and merge after WP-04 and WP-05. Each owns `transit/scanners/<module>.py` and `tests/engine/test_<module>.py` for its modules.
Shared acceptance for every one: (1) a rule-row test with a positive and a near-miss fixture per row, tokens built at run time; (2) `python3 tests/conformance/family_diff.py <ids>` reports no difference in per-file status
and rule ids against bash on `tests/fixtures/rules`; (3) the real-file corpus counts written in CLAUDE.md for the family are reproduced when the corpus exists (run by WP-V); (4) every message string occurs in `scan_pipeline.sh`;
(5) every pattern occurs in `patterns.json`; (6) the registry reports the ids as ported.

| Id | Modules (scanner ids) | Specific points |
|----|-----------------------|-----------------|
| WP-2A | `javascript` (`js`), `java`, `php`, `ruby`, `go` | `js` asks `ctx.file_tool("semgrep-js")` |
| WP-2B | `c_cpp` (`c`), `rust`, `kotlin`, `csharp`, `sql` | `c` asks `ctx.file_tool("cppcheck")`; `.kts` that is not `*.gradle.kts` stays here |
| WP-2C | `yaml_scan` (`yaml`), `terraform`, `docker` | `terraform` asks `checkov`, `docker` asks `hadolint`; the bracket-class credential rule of CLAUDE.md |
| WP-2D | `makefile`, `cmake`, `gradle`, `setup_py` (`setuppy`) | corpora: 88 Makefiles (zero findings), 1,116 CMake (1 FAIL), 6,413 Gradle, 36 `setup.py` (0 FAIL, 3 WARN) |
| WP-2E | `html_scan` (`html`), `xml_scan` (`xml`), `package_manifests` (`manifest.package_json`) | `xml` uses `flat` and comment-stripped views (`ScanContext.search` on derived bytes); `package_manifests` runs `manifests.py` with `run_helper_script` and parses `FACT` lines; corpora 388 HTML, 3,362 XML (0 FAIL), 1,193 `package.json` |
| WP-2F | `bat` (`batch`), `powershell` (`powershell.text`, `powershell.xml`) | the CR-stripped, comment-dropped, continuation-joined views are derived bytes; `PS_FAILED` becomes a local; one `_ps_rules` function shared by both ids; corpora 116 batch, 69 PowerShell (0 FAIL, 8 WARN) |
| WP-2G | `binary`, `archive` | by-extension FAIL; `strings` and `unzip` through `file_tool("strings")` / `("unzip")` |

### 14.3 Wave 3: Phase 4 containers and tool wrappers (7 packages, parallel with each other and with Wave 2)

| Id | Owns | Specific points | Consumes |
|----|------|-----------------|----------|
| WP-3A | `pdf_scan.py`, `test_pdf_scan.py` | runs `pdf.py` with `run_helper_script("pdf", ...)`; two views; the five project PDFs must PASS with no finding | `ScanContext`, `rules` (`line_a`), `tools` |
| WP-3B | `jar_scan.py`, `test_jar_scan.py` | runs `jar.py`; the `fail_map`/`warn_map` vocabulary; S7 neutralising; the 52 fixtures of `make_jar_fixtures.py`; the credential formats on the view through `credentials.check_known_credentials` with `report_file=` the archive | `credentials`, `tools`, `findings.neutralise_detail` |
| WP-3C | `office_scan.py`, `test_office_scan.py` | runs `office.py`; registered under four ids; the sniffed hand-offs from `docs`/`unknown`/`xml`; the office fixtures | same |
| WP-3D | `tools/gitleaks_wrapper.py`, `test_gitleaks_wrapper.py` | S8 a to h; the pure port of `tools/gitleaks.py` (oracle test); the 200 cap; stub gitleaks recording arguments and environment (golden `gitleaks_stub_leak`) | `tools` |
| WP-3E | `tools/detect_secrets_wrapper.py`, `clamscan_wrapper.py`, `yara_wrapper.py` + tests | D-015, D-008; the ClamAV database check | `tools` |
| WP-3F | `tools/semgrep_wrapper.py`, `trivy_wrapper.py`, `scancode_wrapper.py` + tests | D-005, D-006, D-007, D-015, D-018 (label stays the YAML path); the pure port of `tools/scancode.py` (oracle test) | `tools` |
| WP-3G | `tools/bandit_wrapper.py`, `shellcheck_wrapper.py`, `cppcheck_wrapper.py`, `hadolint_wrapper.py`, `checkov_wrapper.py`, `semgrep_js_wrapper.py`, `file_wrapper.py`, `strings_wrapper.py`, `unzip_wrapper.py` + tests | per-file protocol (`layer_state=None`); D-037 | `tools` |

Wave 3 acceptance for a wrapper: tested only against stub executables on a private `PATH` (the host has none of the real tools); every documented exit status and one undocumented one (must not be `ran`); a timeout; unparseable output;
the exact messages of section 10.3; `Registry`/`WrapperSet` report it as present.

### 14.4 Wave 4: verification and cut-over gate (after Waves 2 and 3)

| Id | Owns | Does |
|----|------|------|
| WP-V | `tests/conformance/run_corpora.py`, `tests/engine/test_cutover.py`, `tests/conformance/engine_perf.py` | rebuilds the real-file corpora named in CLAUDE.md as a script and compares both engines; runs `tests/run_tests.sh` with `TRANSIT_ENGINE=bash` and `python`; the fuzz gate over `rx.registered()` including every engine rule; the performance report (not slower than bash on the 362-file corpus); the cut-over gate `Registry.unported() == ()` and no tool without a wrapper |

Dependencies are acyclic (checked). Critical path to the first vertical slice: WP-04 -> WP-05 -> {WP-06, WP-08, WP-09, WP-10} -> WP-11. Everything else is off the critical path.

## 15. The `TRANSIT_ENGINE` switch (owned by WP-11; the only edit to `scan_pipeline.sh` in this phase)

`ai_transit.sh` calls `bash scan_pipeline.sh <dir>` with the caller's environment plus a few assignments, so `TRANSIT_ENGINE` set by a caller reaches the script. The hunk goes immediately after `set -euo pipefail` and **before** the bash-4 check
(the Python engine does not need bash 4):

```bash
# --- engine switch (PYTHON_PORT_PLAN.md, phase 2): bash is the default until cut-over -------------
case "${TRANSIT_ENGINE:-bash}" in
    bash)   ;;
    python) exec python3 -I "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scan_pipeline.py" "$@" ;;
    *)      echo "[ERROR] TRANSIT_ENGINE must be 'bash' or 'python' (got: ${TRANSIT_ENGINE})" >&2; exit 1 ;;
esac
```

Properties: an unknown value refuses (exit 1), it does not fall back to bash silently; `exec` keeps the exit status and signals; `-I` keeps `PYTHON*` environment variables and the user site out of the engine (the entry point adds its own directory to
`sys.path`); a missing `python3` gives the shell's "not found" and status 127, which every caller reads as FAIL (no sidecar). Phase 6 flips the default and keeps `bash` behind the same variable for one release.

## 16. Walk-through: the clean fixture

`tests/fixtures/clean` holds `README.md`, `requirements.txt`, `src/app.py`, `src/setup.sh`. On a host with only `npm`, `file`, `strings`, `unzip` (the golden's `tools_present`):

| Step | Events | Result |
|------|--------|--------|
| layer 1 | gitleaks, detect-secrets, clamscan, yara not found | WARNs `gitleaks missing — secret scan skipped`, `detect-secrets missing`, `clamscan missing`, `yara or rules directory missing` on `__global__`; states `skipped:gitleaks not installed`, `skipped:detect-secrets not installed`, `skipped:clamav not installed`, `skipped:yara or rules directory missing` |
| layer 2 | semgrep not found | WARN `semgrep missing — OWASP/CWE layer skipped (pip install semgrep)`; `skipped:semgrep not installed` |
| layer 3 | `RUN_SCA` not `true` | `skipped:disabled (RUN_SCA is not true)` (no event) |
| layers 4/5 | `files_for_scan`: `README.md`, `requirements.txt`, `src/app.py`, `src/setup.sh` | the 57 rule-by-file evaluations of the slice (28 distinct table patterns) against these four files give no hit, and neither do the private-key header and the 18 formats (verified with `rx` and `patterns.json`) |
| `README.md` | universal: nothing; `docs` (RTF head no): rule no | `record_pass` -> PASS, pass 1 |
| `requirements.txt` | universal: nothing; basename arm `requirements*.txt` -> `manifest.requirements`: no rule | `record_pass` -> PASS, pass 2 |
| `src/app.py` | universal: nothing; `python`: `file_tool("bandit")` = `missing` -> WARN `bandit missing` (status WARN, warn +1); no rule; `finish(False)` -> `record_pass` (pass 3, status stays WARN: first writer) | WARN |
| `src/setup.sh` | likewise with `shellcheck missing` | WARN, pass 4 |
| layer 6 | `RUN_SCANCODE` not `true` | `skipped:disabled (RUN_SCANCODE is not true)` |
| end | `L4_patterns` and `L5_per_language_sast` `ran` | `coverage_gaps` = the seven other ids; `summary` pass 4, warn 7 (5 global + 2); no finding; `source.sha256` = `065a8e52...06be` by the E19 recipe; verdict PASS, decision APPROVED; last stdout line `PASS`, exit 0 |

This is `tests/conformance/golden/clean.json`. On a host that also has bandit or shellcheck the Python engine reports `partial:python engine has not ported bandit yet` for L5 until WP-3G is merged; the golden was captured without them.

## 17. OPEN QUESTIONS

None of these blocks implementation: each has a default that the packages implement and that is reversed by a one-line switch or a later edit.

1. **`transit/rx.py` has an invalid escape in the `_DFA` docstring** (`\B`, `\<`, `\>` inside a non-raw `"""`; line 1001 of the current file). Python 3.12 and 3.13 print a `SyntaxWarning` whenever the file is compiled without a cached `.pyc`
   (a read-only install, a fresh container, a zipapp), and `python -W error` fails; a future Python may make it an error. The fix is one character (`r"""`), but the task forbids editing `rx.py`. Request: permission to make that edit
   (WP-12's `-W error` lint needs it; until then the lint skips `rx.py` with a recorded exception).
2. **Report-content changes that need the owner's sign-off** (divergence register rule 6) and that this design implements by default: D-032 (new coverage states and `engine:` WARNs for not-ported tools and scanners; temporary), D-033 (`engine:` FAILs),
   D-034 (`partial` when `file(1)` is missing and an unknown-extension file was met), D-035 (resource limits), D-036 (repository configuration must be a regular, non-symlink file of at most 1 MiB). Defaults are the safe direction in every case.
3. **Switches whose default copies a bash blind spot** and which the owner should decide: D-029 (`excl` rules go blind on a file with a NUL byte), D-031 (`#!/bin/bash -e` is not routed to the shell scanner), D-014 (the credential formats skip a file with a NUL), and the largest of the
   silent paths, D-004 (a `.transitignore` of `*` passes a repository with nothing scanned and no trace in the report) with D-003. Recommendation for all: fix in Python and in bash.
4. **Per-file Semgrep for JavaScript (D-037)**: `prepare_offline_cache.sh` stages four rule sets but not `javascript`. Until the owner stages one (or decides the call is dropped), the wrapper reports `failed` and L5 is `partial`.
5. **Amending contract 5.2 with the `engine:` prefix** (section 8.3). Needed so that `findings.build_record` and `generate_excel_report.py` (which reads the `[FAIL]`/`[WARN]` tags only) treat it as a documented producer.

## Appendix A. Public API (generated from the stubs)

Generated by walking each stub with `ast`; the stubs are authoritative and carry the full docstrings (preconditions, errors, what is sanitised). Regenerate with the script in Appendix B.

### `scan_pipeline.py`

AI Transit Pipeline - Python engine entry point.

```text
script: checks Python >= 3.10, puts its own directory first on sys.path, calls transit.pipeline.main(sys.argv[1:], os.environ)
```

### `transit/config.py`

Run configuration: every environment variable the engine reads (contract section 2), parsed once.

```text
constants: `ENGINE_NAME`, `ENGINE_VERSION`, `MIN_PYTHON`, `DEFAULT_WORK_DIR`, `DEFAULT_EXCLUDE_DIRS`, `SEVERITY_THRESHOLDS`, `COVERAGE_REQUIRED`, `COVERAGE_OPTIONAL`, `COVERAGE_LAYERS`, `STANDARDS_HEAD`, `STANDARDS_TAIL`, `KNOWN_FIXES`, `EXIT_PASS`, `EXIT_FAIL`
class `Limits()` (frozen dataclass) - The engine's own resource limits.
    fields: rule_budget_s: float; file_budget_s: float; long_line_bytes: int; max_file_bytes: int; tool_timeout_s: float; helper_timeout_s: float
class `Notice()` (frozen dataclass) - A message found while parsing the environment, printed by the pipeline once the console exists.
    fields: level: str; text: str
class `Config()` (frozen dataclass) - Immutable view of the run's configuration.
    fields: environ: Mapping[str, str]; work_dir: str; verbosity: str; min_severity: str; sev_threshold: int; since_commit: str; run_sca: bool; run_scancode: bool; offline_cache: str; semgrep_rules_dir: str; trivy_cache_dir: str; clamav_db_dir: str; repo_input: str; tmpdir: str; timestamp: str; limits: Limits; fixes: frozenset[str]; notices: tuple[Notice, ...]
    def fix(self, fix_id: str) -> bool
def load_config(environ: Mapping[str, str], *, now: _dt.datetime | None=None) -> Config  - Parse environ into a Config (contract 2).
def env_number(environ: Mapping[str, str], name: str, default: float) -> float  - The JAR_*/OFFICE_* knob rule (contract 2): parse as float; not a number or not above 0 means default.
```

### `transit/console.py`

Console output: the only module that writes to stdout or stderr.

```text
constants: `COLOUR_INFO`, `COLOUR_WARN`, `COLOUR_OK`, `COLOUR_FAIL`, `COLOUR_RESET`
class `Console()` - Sanitised, channel-correct output (contract 3.1).
    def __init__(self, verbosity: str='normal', *, out: 'BinaryIO | None'=None, err: 'BinaryIO | None'=None, err_is_tty: 'bool | None'=None) -> None
    def info(self, text: str) -> None
    def ok(self, text: str) -> None
    def warn(self, text: str) -> None
    def fail_line(self, text: str) -> None
    def error(self, text: str) -> None
    def verdict(self, value: str) -> None
    def progress(self, current: int, total: int, rel_path: str) -> None
    def clear_progress(self) -> None
    def exception(self, where: str, exc: BaseException) -> None
def sanitise(text: 'str | bytes') -> str  - Return text with every character listed in the module docstring replaced by ?.
```

### `transit/cli.py`

Command line: scan_pipeline.py <directory_to_scan> [directory_for_report] [scanning_name] (contract 1).

```text
constants: `SCANNING_NAME_MAX_CHARS`
class `UsageError(Exception)` - A refused command line.
    def __init__(self, message: str) -> None
class `Args()` (frozen dataclass) - The parsed command line.
    fields: scan_dir: str; report_dir: 'str | None'; scanning_name: 'str | None'
def positional_words(argv: Sequence[str]) -> list[str]  - Contract 1.1: drop every word that begins with -- (including a lone --), keep the order, keep positionals beyond the third (they are ignored later).
def scanning_name_error(name: str) -> 'str | None'  - Contract 1.4.
def parse_args(argv: Sequence[str], *, prog: str='scan_pipeline.py') -> Args  - Parse argv (WITHOUT the program name) and run the four checks of contract 1.2 in order: (1) no positional -> usage; (2) positional 1 is not an existing directory (os.path.isdir: a symlink to a directory counts, a file...
```

### `transit/findings.py`

Messages, severity, the structured finding record and the allowlist: everything that is a pure function of a finding message (contract 5, 6.2 step 2, 6.3).

```text
constants: `SEVERITY_NUMBER`, `CATEGORIES`, `ENGINE_PREFIX`
class `Severity()` (frozen dataclass) - A severity as the classifier returns it: name is one of SEVERITY_NUMBER, number its value.
    fields: name: str; number: int
class `FindingRecord()` (frozen dataclass) - One element of the report's findings array: all ten fields of contract section 4, always present.
    fields: tool: str; category: str; severity: str; rule_id: str; rule_name: str; file: str; line: 'int | None'; column: 'int | None'; message: str; references: tuple[str, ...]
    def to_json(self) -> dict
class `Allowlist()` (frozen dataclass) - .transit-allow.json after parsing: (rule, path) -> reason.
    fields: entries: Mapping[tuple[str, str], str]
    def __len__(self) -> int
    def lookup(self, message: str, rel_path: str) -> 'str | None'
def classify_severity(message: str) -> Severity  - The one classifier (contract 6.3).
def relative_to_scan_dir(file: str, scan_dir: str) -> str  - Bash ${file#"$SCAN_DIR/"}: file with a leading scan_dir + "/" removed, otherwise unchanged.
def join_scan_path(scan_dir: str, rel: str) -> str  - The path string under which a file is recorded: scan_dir + "/" + rel, except that for scan_dir == "/" it is "/" + rel (what find / prints).
def allowlist_tokens(message: str) -> tuple[str, str]  - The two rule tokens tried, in order, for the allowlist (contract 6.2 step 2): the text before the first : and the text between the first and the second :.
def build_record(file: str, message: str, scan_dir: str, *, severity: 'str | None'=None) -> FindingRecord  - Derive the structured record from a FAIL message (contract 5.3), first matching row wins: semgrep[ -> tool semgrep/sast, rule id between ]: and the next :; detect-secrets:; clamav:; gitleaks:; yara:; bandit: (rule id...
def parse_allowlist(raw: bytes, *, strict: bool=False) -> tuple[Allowlist, tuple[str, ...]]  - Parse the bytes of .transit-allow.json (contract 6.2, A10, S15).
def json_safe(text: str) -> str  - Make text encodable as strict UTF-8: each undecodable byte (a lone surrogate from os.fsdecode) becomes U+FFFD, exactly as os.fsencode(text).decode("utf-8", "replace") (golden hostile_non_utf8_name, D-023).
def neutralise_detail(detail: str, *, max_chars: int) -> str  - S7, for container scanners that put an archive entry name or part name in a message: non-printable characters and | become ?; a colon that closes a word in {info, low, warning, medium, error, high, critical} (case-ins...
```

### `transit/verdict.py`

The run state: the verdict, per-file status and messages, counters, the findings stream, the allowlist and threshold, and the coverage block.

```text
constants: `GLOBAL_FILE`
class `Outcome(enum.Enum)` - What record_fail actually did.
class `Counters()` (frozen dataclass) - Event counters (contract 6.1, A13/D-013): not file counts.
    fields: pass_: int; warn: int; fail: int
class `Snapshot()` (frozen dataclass) - Immutable end state handed to report.
    fields: verdict: str; counters: Counters; file_status: Mapping[str, str]; file_message: Mapping[str, str]; fail_messages: Mapping[str, str]; findings: tuple[FindingRecord, ...]; coverage: Mapping[str, str]
class `Verdict()` - The one mutable run-state object.
    def __init__(self, scan_dir: str, allowlist: Allowlist, *, threshold: int, min_severity: str, console: Console, first_writer: bool=True, dot_matches_directory: bool=False) -> None
    @property def verdict(self) -> str
    @property def counters(self) -> Counters
    @property def events(self) -> int
    def status_of(self, file: str) -> 'str | None'
    def coverage_state(self, layer_id: str) -> 'str | None'
    def record_pass(self, file: 'str | None'=None) -> None
    def record_warn(self, file: 'str | None', message: str) -> None
    def record_fail(self, file: str, message: str, *, severity: 'str | None'=None, downgradable: bool=True) -> Outcome
    def record_layer(self, layer_id: str, state: str, *, overwrite: bool=True) -> None
    def note_incomplete(self, layer_id: str, reason: str) -> None
    def abort(self, reason: str) -> None
    def snapshot(self) -> Snapshot
```

### `transit/files.py`

The file system side of a run: which files are scanned, how one file is read, temporary files, and the content hashes.

```text
constants: `MANIFEST_SKIP_NAME`
class `FileReadError(Exception)` - A file that was listed could not be read.
    def __init__(self, reason: str) -> None
class `FileEntry()` (frozen dataclass) - One regular file chosen for the per-file layers.
    fields: path: str; rel: str; size: int
class `FileView()` - One file, read at most once.
    def __init__(self, path: str, rel: str, limits: Limits) -> None
    @property def path(self) -> str
    @property def rel(self) -> str
    @property def basename(self) -> str
    @property def ext(self) -> str
    def data(self) -> bytes
    def head(self, n: int=8192) -> bytes
    def first_line(self) -> bytes
    def has_long_line(self) -> bool
    def flat(self) -> bytes
    def target(self, data: 'bytes | None'=None) -> Target
    def release(self) -> None
class `TempArea()` - Contract 3.5 and S16.
    def __init__(self, tmpdir: str) -> None
    @property def path(self) -> str
    def new_file(self, suffix: str='') -> str
    def new_dir(self) -> str
    def cleanup(self) -> None
class `Exclusions()` (frozen dataclass) - Contract 8.2 to 8.4 (D-001/D-002 closed).
    fields: dir_names: tuple[str, ...]; patterns: tuple[str, ...]
    def excludes(self, rel: str, *, is_dir: bool) -> bool
    def semgrep_dirs(self) -> tuple[str, ...]
class `DiffSelection()` (frozen dataclass) - Contract 8.6.
    fields: active: bool; keys: frozenset[str]; stale_ignored: bool
class `ScanList()` (frozen dataclass) - The files of the per-file layers, sorted by the bytes of rel, plus the directories that could not be listed (errors holds rel paths; layers.run_file_layers records ONE WARN engine:unreadable_directories(<n>) and note_...
    fields: entries: tuple[FileEntry, ...]; errors: tuple[str, ...]
class `SourceHashes()` (frozen dataclass) - sha256: contract 4 source.sha256; repo_hash: contract 4 repo_hash.
    fields: sha256: str; repo_hash: str
def prepare_work_dirs(work_dir: str) -> None  - Create WORK_DIR/reports, WORK_DIR/quarantine (mode 0700) and WORK_DIR/approved with parents (mkdir -p; D-027: created although unused).
def read_repo_config_file(scan_dir: str, name: str, *, max_bytes: int=1 << 20) -> 'tuple[bytes | None, str | None]'  - Read scan_dir/name (.transit-allow.json or .transitignore; name has no separator, else ValueError) as repository configuration, S15 / D-036: it must be a REGULAR file that is NOT a symlink (lstat) and at most max_bytes.
def contained_path(scan_dir: str, path: str) -> 'str | None'  - For a wrapper that must map a path reported by a tool (absolute, or relative to scan_dir) to the recorded path: the os.path.abspath-normalised path if it lies at or below os.path.abspath(scan_dir), else None.
def glob_match(pattern: str, text: str) -> bool  - fnmatch(3) without FNM_PATHNAME, as find -path applies it: * matches any string INCLUDING /; ? any one character; [...] a set with ! or ^ negation and ranges; \x the character x.
def load_exclusions(scan_dir: str, *, cfg: Config) -> 'tuple[Exclusions, tuple[str, ...]]'  - Read scan_dir/.transitignore through read_repo_config_file and return the exclusions plus the console notes.
def load_diff_selection(work_dir: str, since_commit: str, scan_dir: str) -> DiffSelection  - Parse WORK_DIR/.diff_files: entries are terminated by :; the text after the last : (including a trailing newline) is dropped; an entry is kept only if it names an existing regular file.
def files_for_scan(scan_dir: str, exclusions: Exclusions, diff: DiffSelection) -> ScanList  - Contract 8.5: regular files only (lstat; symlinks to files and to directories are neither listed nor followed), hidden files included, pruned by exclusions, restricted to diff.keys when diff.active, .manifest_sha256.t...
def compute_hashes(scan_dir: str) -> SourceHashes  - source.sha256 = SHA-256 of the lines <hex> ./<rel> (two spaces, LF) of EVERY regular file under scan_dir (no exclusion applies; symlinks excluded), sorted by the BYTES of the whole ./<rel> string (LC_ALL=C sort -z, so...
```

### `transit/rules/__init__.py`

Declarative rule tables and the only way a rule is evaluated.

```text
constants: `MODES`, `BINARY_MODES`
class `ScanBudgetExceeded(Exception)` - The per-file deadline passed between two rules.
class `SearchPolicy()` (frozen dataclass) - How a search is run.
    fields: rule_budget_s: float; long_line_bytes: int; excl_nul_blind: bool
class `Target()` (frozen dataclass) - What a rule is evaluated against: bytes plus the facts a rule can depend on.
    fields: data: bytes; basename: str; ext: str; has_long_line: bool; flat: Callable[[], bytes]
class `Match()` (frozen dataclass) - One grep call.
    fields: pattern: str; mode: str; ci: bool; excl: 'str | None'; binary: str
class `AllOf()` (frozen dataclass) - Whole-file conjunction: true when every member is (each over the WHOLE file, not necessarily the same line).
    fields: members: 'tuple[Cond, ...]'
class `AnyOf()` (frozen dataclass) - True when any member is (bash A || B).
    fields: members: 'tuple[Cond, ...]'
class `AppliesTo()` (frozen dataclass) - Restricts a rule to some files of the scanner that owns it.
    fields: basenames: 'tuple[str, ...] | None'; exts: 'tuple[str, ...] | None'
class `RuleSpec()` (frozen dataclass) - One row of a rule table = one record_fail / record_warn of the bash scanner.
    fields: id: str; outcome: str; message: str; cond: Cond; severity: 'str | None'; applies_to: 'AppliesTo | None'; source: str
class `RuleSet()` - An ordered, compiled table.
    def __init__(self, name: str, rules: Sequence[RuleSpec]) -> None
    @property def name(self) -> str
    @property def rules(self) -> tuple[RuleSpec, ...]
class `RuleRun()` (frozen dataclass) - Result of run_ruleset.
    fields: hits: tuple[RuleSpec, ...]; skipped: tuple[str, ...]; timed_out: tuple[str, ...]
def evaluate(cond: Cond, target: Target, policy: SearchPolicy) -> bool  - Evaluate one condition tree.
def run_ruleset(ruleset: RuleSet, target: Target, policy: SearchPolicy, deadline: 'float | None'=None) -> RuleRun  - Evaluate every applicable rule (AppliesTo checked against target.basename / target.ext) in table order.
```

### `transit/tools/__init__.py`

External tools: finding them, running them safely, and the protocol a tool wrapper implements.

```text
constants: `OFFLINE_CHILD_ENV`, `HELPER_SCRIPTS`, `DIRECTORY_TOOLS`, `FILE_TOOLS`, `MAX_CAPTURE_BYTES`
class `ToolInfo()` (frozen dataclass) - A tool that was found on PATH: name as asked, path absolute.
    fields: name: str; path: str
class `ToolLocator()` - command -v with a cache.
    def __init__(self, cfg: Config) -> None
    def find(self, name: str) -> 'ToolInfo | None'
class `ProcessResult()` (frozen dataclass) - What a child process did.
    fields: status: str; returncode: 'int | None'; stdout: bytes; stderr: bytes; truncated: bool; elapsed_s: float
class `Record()` (frozen dataclass) - One verdict call a wrapper asks for.
    fields: kind: str; file: str; message: str; severity: 'str | None'
class `ToolRequest()` (frozen dataclass) - Input of ToolWrapper.run.
    fields: cfg: Config; scan_dir: str; target: 'str | None'; temp: object; exclude_dirs: tuple[str, ...]; info: ToolInfo
class `ToolOutcome()` (frozen dataclass) - What a wrapper reports back.
    fields: layer_state: 'str | None'; records: tuple[Record, ...]; notes: tuple[str, ...]; exit_code: 'int | None'; timed_out: bool
class `ToolWrapper(abc.ABC)` - One external tool.
    @abc.abstractmethod def run(self, request: ToolRequest) -> ToolOutcome
class `WrapperSet()` (frozen dataclass) - The wrappers that could be loaded, keyed by tool name, and the import failures (class name and module only, never a message that could carry repository text).
    fields: wrappers: Mapping[str, ToolWrapper]; load_errors: tuple[str, ...]
    def get(self, name: str) -> 'ToolWrapper | None'
def child_env(cfg: Config, *, remove: Sequence[str]=(), extra: 'Mapping[str, str] | None'=None) -> dict[str, str]  - cfg.environ + OFFLINE_CHILD_ENV + extra, minus the names in remove (gitleaks removes GITLEAKS_CONFIG and GITLEAKS_CONFIG_TOML, S8d).
def run_process(argv: Sequence[str], *, env: Mapping[str, str], timeout_s: float, cwd: 'str | None'=None, stdin: 'bytes | None'=None, output_file: 'str | None'=None) -> ProcessResult  - Run argv WITHOUT a shell (S6): subprocess with an argument list, shell=False, stdin closed unless given, a new session so that on timeout the whole process group is killed, and the timeout enforced for sure (kill, the...
def run_helper_script(name: str, args: Sequence[str], *, cfg: Config, timeout_s: 'float | None'=None, env_extra: 'Mapping[str, str] | None'=None) -> ProcessResult  - Run one of HELPER_SCRIPTS as a program: [sys.executable, "-I", <path>, *args] with the environment of child_env (the JAR_* and OFFICE_* knobs reach the helper through it).
def load_wrappers() -> WrapperSet  - Import every module of this package whose name ends in _wrapper and collect its module-level WRAPPERS tuple, keyed by ToolWrapper.name (which must be a key of DIRECTORY_TOOLS or FILE_TOOLS, else ValueError).
```

### `transit/scanners/__init__.py`

Scanner registry, the ScanContext every scanner receives, and the guard that turns a scanner's failure into a recorded one.

```text
constants: `KNOWN_SCANNERS`, `PSEUDO_FAMILIES`, `SCRIPT_MODULES`
class `ScannerSpec()` (frozen dataclass) - A registered scanner.
    fields: id: str; family: str; fn: ScannerFn; bash_function: str; tools: tuple[str, ...]; ported: bool
class `Registry()` (frozen dataclass) - All specs found, and the load errors (module name + exception class name only).
    fields: specs: Mapping[str, ScannerSpec]; load_errors: tuple[str, ...]
    def get(self, scanner_id: str) -> 'ScannerSpec | None'
    def unported(self) -> tuple[str, ...]
class `RuleOutcome()` (frozen dataclass) - Result of ScanContext.run_rules.
    fields: fired: bool; outcomes: tuple[tuple[str, Outcome], ...]; incomplete: bool
class `FileToolRun()` (frozen dataclass) - Answer of ScanContext.file_tool.
    fields: status: str; records: tuple[Record, ...]
class `ScanContext()` - Everything one scanner may touch for one file.
    def __init__(self, *, view: FileView, verdict: Verdict, cfg: Config, console: Console, tools: ToolLocator, wrappers: WrapperSet, registry: Registry, policy: SearchPolicy, temp: TempArea, scan_dir: str, deadline: float, sniffed: bool=False, depth: int=0) -> None
    @property def path(self) -> str
    @property def rel(self) -> str
    @property def basename(self) -> str
    @property def ext(self) -> str
    @property def sniffed(self) -> bool
    @property def view(self) -> FileView
    @property def cfg(self) -> Config
    @property def temp(self) -> TempArea
    def record_pass(self) -> None
    def record_warn(self, message: str, *, file: 'str | None'=None) -> None
    def record_fail(self, message: str, *, file: 'str | None'=None, severity: 'str | None'=None, downgradable: bool=True) -> Outcome
    def note_incomplete(self, reason: str, *, layer: str='L5_per_language_sast') -> None
    def finish(self, fired: bool) -> None
    def run_rules(self, ruleset: RuleSet, *, data: 'bytes | None'=None) -> RuleOutcome
    def search(self, cond: Cond, *, data: 'bytes | None'=None) -> bool
    def target(self, data: 'bytes | None'=None) -> Target
    def check_deadline(self) -> None
    def file_tool(self, name: str) -> FileToolRun
    def delegate(self, scanner_id: str, *, sniffed: bool=False) -> bool
def load_registry(module_names: 'Sequence[str] | None'=None) -> Registry  - Discover the scanner modules (pkgutil.iter_modules over this package, minus SCRIPT_MODULES and _*; or exactly module_names for tests), import each and collect SCANNERS.
def invoke(registry: Registry, scanner_id: str, ctx: ScanContext) -> bool  - Run one scanner under the guard (contract 11 / D-028 for a single file).
def guard(label: str, fn: ScannerFn, ctx: ScanContext, *, requires_outcome: bool=True) -> bool  - invoke for a function that is not in the registry (the universal layer, label universal).
```

### `transit/dispatch.py`

File dispatch: which scanner a file goes to (bash classify_file, contract 8.8).

```text
constants: `BASENAME_ROUTES`, `EXT_ROUTES`, `RTF_SNIFFED_EXTS`, `SHEBANG_ROUTES`
def lower_ext(path: str) -> str  - ${f##*.} lower-cased, with the dot: the text after the last .
def rtf_head(view: FileView) -> bool  - Bash _rtf_head: the first 16 bytes, leading whitespace removed, start with {\rtf.
def flat_office_head(view: FileView) -> bool  - Bash _flat_office_head: the first 8192 bytes contain schemas.microsoft.com/office/2006/xmlPackage, schemas.microsoft.com/office/word/2003/wordml or urn:schemas-microsoft-com:office:spreadsheet.
def shebang_scanner(first_line: bytes, *, first_word_only: bool=False) -> 'str | None'  - The scanner id for a first line (FileView.first_line) by SHEBANG_ROUTES (decoded as latin-1), or None.
def classify_file(view: FileView, run: RunScanner, *, fix_d031: bool=False) -> None  - Contract 8.8 rules 2 to 5 for one file (the universal layer has already run).
def routed_patterns() -> 'tuple[set[str], set[str]]'  - (extension set, basename-arm set) in the shape of build_pdf_filetypes.routed_patterns(): extensions with their dot, and each basename arm as its patterns joined by | ('Makefile*|makefile*|GNUmakefile*').
```

### `transit/layers.py`

Layer orchestration: L1 to L6, the per-file loop for L4 and L5, and the coverage block.

```text
constants: `LAYER1_SLOTS`, `LAYER2_SLOTS`, `LAYER3_SLOTS`, `LAYER6_SLOTS`, `LAYER3_DISABLED`, `LAYER6_DISABLED`
class `ToolSlot()` (frozen dataclass) - A whole-directory tool of layers 1, 2, 3 or 6.
    fields: tool: str; layer_id: str; missing_message: str; missing_state: str; requires_dir: 'str | None'; missing_file: str
class `RunEnv()` (dataclass) - Everything a layer needs, built by pipeline.main after the arguments, configuration, allowlist, exclusions and diff selection are loaded.
    fields: cfg: Config; args: Args; scan_dir: str; console: Console; verdict: Verdict; tools: ToolLocator; wrappers: WrapperSet; registry: Registry; temp: TempArea; exclusions: Exclusions; diff: DiffSelection
class `FileLayerSummary()` (frozen dataclass) - Result of the per-file loop: files seen, files skipped because they vanished, files that could not be read.
    fields: scanned: int; vanished: int; unreadable: int
def run_slot(env: RunEnv, slot: ToolSlot) -> None  - One whole-directory tool.
def run_layer1(env: RunEnv) -> None  - Layer 1 in bash order (gitleaks, detect-secrets, clamscan, yara): run_slot for each of LAYER1_SLOTS.
def run_layer2(env: RunEnv) -> None  - Layer 2: run_slot for LAYER2_SLOTS.
def run_layer3(env: RunEnv) -> None  - Layer 3.
def run_layer6(env: RunEnv) -> None  - Layer 6: RUN_SCANCODE not exactly true -> record_layer("L6_licence", LAYER6_DISABLED); otherwise run_slot for LAYER6_SLOTS (the wrapper adds the OFFLINE:scancode CVE lookup disabled ...
def run_file_layers(env: RunEnv, scan: ScanList, *, universal: Callable[..., object], dispatch_file: Callable[..., None]) -> FileLayerSummary  - Layers 4 and 5 (bash scan_by_type).
def finalise(env: RunEnv) -> None  - After the last layer: one WARN engine:scanner_load_error:<module> per Registry.load_errors entry and one engine:wrapper_load_error:<module> per WrapperSet.load_errors entry, each with note_incomplete on L5_per_languag...
def run_all(env: RunEnv, scan: ScanList) -> FileLayerSummary  - The order of scan_pipeline.sh's main block: layer 1, layer 2, layer 3, layers 4 and 5, layer 6, finalise.
```

### `transit/report.py`

Reports and sidecars: the JSON report, the HTML report, the two sidecar files (contract 3.3, 3.4, 4).

```text
class `ReportPaths()` (frozen dataclass) - Contract 3.4.
    fields: json: str; html: str; scan_name: str; verdict_sidecar: str; report_sidecar: str
def report_paths(args: Args, cfg: Config) -> ReportPaths  - Pure path arithmetic; creates nothing.
def standards(run_sca: bool, run_scancode: bool) -> list[str]  - Contract 4 standards: STANDARDS_HEAD, SCA-CVE if run_sca, ScanCode-Licence-Copyright if run_scancode, then STANDARDS_TAIL.
def message_for_file_results(accumulated: str) -> str  - D-009 (copied): accumulated.rstrip(" | "), a CHARACTER-SET strip of trailing spaces and pipes, as the bash writer does.
def build_report(snapshot: Snapshot, source: SourceHashes, *, args: Args, scan_name: str, repo_input: str, run_sca: bool, run_scancode: bool, now_utc: _dt.datetime, fix_d009: bool=False) -> dict  - The raw report of contract 4 as a dict: verdict; decision (APPROVED iff PASS) with status_color / status_background (#198754/#D1E7DD PASS, #B02A37/#F8D7DA FAIL); scan_name; source {directory, sha256}; coverage (the sn...
def html_escape(text: str) -> str  - S3 / D-017: & first, then <, >, ", ' (as &#39;); then every C0 control (TAB and LF included), DEL and every C1 control is written as &#xNN;; lone surrogates become U+FFFD.
def render_html(report: dict, *, timestamp_local: str) -> str  - The HTML report (contract 3.4): title AI Transit Report - <timestamp_local>, <h1>Verdict: <V></h1>, the escaped directory, the three counters, a coverage table (new, allowed), and one row for EVERY file_results entry...
def write_atomic(path: str, data: bytes, *, mode: int=438) -> None  - S5.
def write_reports(report: dict, paths: ReportPaths, *, timestamp_local: str) -> None  - JSON first (json.dumps(..., ensure_ascii=False, indent=2) + LF, UTF-8, strict), then HTML, each through write_atomic.
def write_sidecars(paths: ReportPaths, verdict: str) -> None  - Contract 3.3, in this order: .scan_verdict = PASS/FAIL + LF, then .scan_report_json = the JSON path as constructed + LF.
```

### `transit/pipeline.py`

The run from argv to the exit status (bash: the top-level code of scan_pipeline.sh).

```text
def main(argv: Sequence[str], environ: 'Mapping[str, str] | None'=None, *, out: 'BinaryIO | None'=None, err: 'BinaryIO | None'=None) -> int  - Run the engine.
```

### `transit/scanners/universal.py`

Layer 4: the universal pattern rules that run on EVERY file before its own scanner (bash scan_universal_patterns).

```text
constants: `RULES`, `PRIVATE_KEY_HEADER`, `PRIVATE_KEY_WITH_BODY`
def private_key_present(ctx: ScanContext, data: 'bytes | None'=None) -> bool  - CWE-321 test: rx.after_context(header, data, 5); fold CR, LF and TAB to spaces; the folded text matches PRIVATE_KEY_WITH_BODY.
def scan(ctx: ScanContext) -> bool  - Run steps 1 to 6 on ctx's file.
```

### `transit/scanners/credentials.py`

Known credential formats (bash _known_cred_check and the KNOWN_CRED_* tables).

```text
constants: `PROVIDER_NAMES`, `PROVIDER_PATTERNS`, `EXCLUSION`, `JWT_PATTERN`, `JWT_MESSAGE`
class `CredentialResult()` (frozen dataclass) - failed: at least one provider FAIL was recorded (bash returns 0 only then, for triggered).
    fields: failed: bool; providers: tuple[str, ...]; jwt: bool
def check_known_credentials(ctx: ScanContext, *, data: 'bytes | None'=None, report_file: 'str | None'=None) -> CredentialResult  - Run steps 1 to 3 above on data (default: the file's own bytes) and record through ctx: one record_fail per provider that fired (CWE-798:known_credential_format_<name>), then the JWT record_warn.
```

### `transit/scanners/python_lang.py`

Python source files (bash scan_python): family python, scanner id python.

```text
constants: `RULES`, `SCANNERS`
def scan(ctx: ScanContext) -> bool  - Scan one Python file.
```

### `transit/scanners/shell.py`

Shell scripts (bash scan_shell): family shell, scanner id shell.

```text
constants: `RULES`, `SCANNERS`
def scan(ctx: ScanContext) -> bool  - Scan one shell script.
```

### `transit/scanners/doc.py`

The two families that classify_file handles with ONE inline rule each: docs (.md .txt .rst) and json (.json).

```text
constants: `DOC_RULES`, `JSON_RULES`, `SCANNERS`
def scan_docs(ctx: ScanContext) -> bool  - Scan a documentation or text file.
def scan_json(ctx: ScanContext) -> bool  - Scan a .json file that is not a package manifest.
```

### `transit/scanners/requirements.py`

pip requirement files (bash scan_requirements): family manifest, scanner id manifest.requirements.

```text
constants: `RULES`, `SCANNERS`
def scan(ctx: ScanContext) -> bool  - Scan one requirements file.
```

### `transit/scanners/unknown.py`

Files with no recognised extension or name (bash scan_unknown): pseudo scanner id unknown (not one of the 34 families).

```text
constants: `SCANNERS`
def scan(ctx: ScanContext) -> bool  - Scan one file of unknown type.
```

## Appendix B. Verification log and the generator

Run on this host while the design was written (the scripts were throw-away files in the session scratchpad; the key ones are reproduced below so a reviewer can repeat them).

| What | Command (abridged) | Result |
|------|--------------------|--------|
| F1 import probes | for each of 12 existing modules: `python3 -I -c "import sys; sys.path.insert(0,'.'); sys.argv=['x']; import <m>"` | safe: `transit`, `rx`, `tools`, `scanners`, `containers`, `tools.gitleaks` (by accident); `IndexError`: `report_json`, `tools.scancode`, `scanners.manifests`, `containers.jar`, `containers.office`; **`SystemExit(0)`**: `containers.pdf` |
| F2 budget latency | `rx.search_lines(rx.ere_to_py("curl[^\|]*http://"), b"curl x " * k, budget=0.25)` against `rx.dfa_search` | 10 KB 0.03 s, 30 KB 0.24, 70 KB 0.78, 150 KB 1.83, 300 KB 4.04, 600 KB 8.88; `dfa_search` 0.001 to 0.020 s; 5 MB line 74.5 s with `budget=0.25` |
| F3 nesting | `with rx.time_limit(5): with rx.time_limit(0.05): pass` then `signal.getitimer(ITIMER_REAL)` | `(0.0, 0.0)`: the outer timer is gone |
| F4 DFA | `rx.dfa_available` over `patterns.json`; `rx.dfa_search` on 1.8 MB of short lines; 28 slice patterns on four 600 KB lines | 285 of 285 translatable patterns have a DFA (the exclusion pattern with a back-reference does not); 0.08 s for 1.8 MB; worst 0.03 s on 600 KB |
| F5 `find -path` | 24 pattern sets against `find <root> <bash's prune expression> -type f` and a walker using "pattern against the path and every suffix after a `/`" | 0 differences |
| F6 `-W error` | `compile()` of every file with `warnings.simplefilter("error")` on 3.12 and 3.13 | all new files clean; `transit/rx.py` fails (line 1001, `\B`) |
| F7 tables | comparison scripts | 109 extensions, 7 basename arms, 34 families, 14 directories, `standards`, 18 provider names, 9 missing-tool texts and 2 disabled-layer texts equal the reference |
| F8 shebang | bash `case` against `fnmatch.fnmatchcase` | `#!/bin/bash -e`, `#!/usr/bin/env bash -e`, `#!/bin/sh -x` unrouted in both |
| F9 primitives | `rx.after_context` + fold + `rx.search_lines`; `binary="skip"` | real PEM body found; signature, prose, placeholder not; token found, hidden by NUL with `skip`, found with `text` |
| F10 stubs | `python3.10`, `3.11`, `3.12`, `3.13` `-I` import of the 21 modules with stdout/stderr captured, `SIGALRM` and the working directory compared | no output, no signal, no file; none of the seven helper programs imported; AST import graph acyclic |
| clean fixture | the 28 table patterns against the four fixture files, the key header and the 18 formats | 57 rule-by-file evaluations, no hit |
| ownership | script over the 27 packages | 139 files, no overlap, no unknown dependency, no cycle; every one of the 37 scanner ids maps to a module with an owner |

Regenerating Appendix A (run from the repository root; prints Markdown on stdout of the file you pass):

```python
import ast, os, sys
FILES = ["transit/config.py", "transit/console.py", "transit/cli.py", "transit/findings.py", "transit/verdict.py", "transit/files.py",
         "transit/rules/__init__.py", "transit/tools/__init__.py", "transit/scanners/__init__.py", "transit/dispatch.py",
         "transit/layers.py", "transit/report.py", "transit/pipeline.py", "transit/scanners/universal.py",
         "transit/scanners/credentials.py", "transit/scanners/python_lang.py", "transit/scanners/shell.py",
         "transit/scanners/doc.py", "transit/scanners/requirements.py", "transit/scanners/unknown.py"]

def summary(doc):
    para = " ".join((doc or "").strip().split("\n\n")[0].split()).replace("``", "")
    cut = para.find(". ")
    return para if cut < 0 or cut > 220 else para[: cut + 1]

def sig(fn):
    ret = " -> " + ast.unparse(fn.returns) if fn.returns else ""
    return f"def {fn.name}({ast.unparse(fn.args)}){ret}"

for rel in FILES:
    tree = ast.parse(open(rel, encoding="utf-8").read())
    print(f"### `{rel}`\n\n{summary(ast.get_docstring(tree))}\n\n```text")
    for n in tree.body:
        if isinstance(n, ast.ClassDef):
            print(f"class {n.name}({', '.join(map(ast.unparse, n.bases))}) - {summary(ast.get_docstring(n))}")
            for s in n.body:
                if isinstance(s, ast.AnnAssign):
                    print(f"    field {s.target.id}: {ast.unparse(s.annotation)}")
                elif isinstance(s, ast.FunctionDef) and (not s.name.startswith("_") or s.name in ("__init__", "__len__")):
                    print("    " + sig(s))
        elif isinstance(n, ast.FunctionDef) and not n.name.startswith("_"):
            print(sig(n) + " - " + summary(ast.get_docstring(n)))
    print("```\n")
```
