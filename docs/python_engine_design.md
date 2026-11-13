# Python engine design: skeleton, shared machinery and the first vertical slice

> **INTERFACES FROZEN, 2026-11-12.** After two independent reviews (28 defects, all recorded in the *Review log* at the end of this
> document) the signatures, fields, constants, tables and docstrings of the stub modules listed in section 3.1 and printed in Appendix A,
> the message strings of section 8.3, the steps of section 6 and the file ownership of section 14 are **frozen**. **Any change after
> 2026-11-12 needs an entry in the Review log first** (id, severity, what changes and why, with the evidence that justifies it); a pull
> request that changes a stub or this document without one is refused. Private helpers (names starting `_`) and constants documented as
> "filled by the implementation" are not frozen.

Phase 2 of `PYTHON_PORT_PLAN.md`. Written 2026-11-12 by the architect of Phase 2, revised the same day after review. Audience: the engineers who
will implement work packages WP-01 to WP-13 (section 14) and, later, the scanner and tool packages of Phase 3 and Phase 4, **in parallel,
without having read the bash code**.

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

The signatures, constants and tables in the stubs are frozen (see the banner at the top; the date is 2026-11-12). A package may add private helpers
(names starting `_`) and may fill in constants documented as "filled by the implementation". Any other change (a signature, a new public
name, a new scanner id, a new coverage state, a new message prefix, a different step in section 6) needs an **amendment**: first an entry in
the *Review log* (last section), then a pull request that changes the stub, this document and the affected tests together, reviewed by the
architect. A package that finds a contract/design disagreement files it as an amendment request and carries on with the stub's behaviour.


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
| a directory cannot be listed | `find ... 2>/dev/null` loses the whole subtree | non-downgradable FAIL `engine:directory_unreadable:<reason>` (first 200, then a summary) + `partial` on L4 and L5: a subtree is as unexamined as a file | 8.3, D-041 |
| a path longer than PATH_MAX | `find` lists it, bash cannot open it: PASS, the file is absent from the report (F14) | the walk and every open use directory descriptors (`files.open_beneath`), so the length of the path does not matter | 5.1, D-041 |
| a file named `.manifest_sha256.txt` | skipped at **any depth**; `ai_transit.sh` excludes only the root one from the ZIP, so a nested one ships unscanned (F15) | skipped by no name at all; scanned like any file | D-038 |
| a flat-mode rule (XXE) on a file over 5 MiB | matches nothing (F15) | no cap: the folded view is searched by the linear matcher | 9.2, D-039 |
| diff mode, a changed file whose name holds `:` or non-ASCII | dropped silently (F16) | NUL-separated format accepted; the legacy list is rebuilt by joining and C-unquoting; what still cannot be resolved is a WARN + `partial` | 8.3, D-042 |
| a stale sidecar | survives an aborted run, a caller that reads it sees the previous PASS | both sidecars removed right after the report directories exist | 6, D-040 |
| `SystemExit` or another `BaseException` inside a scanner | n/a | FAIL for that file (`engine:scanner_error:<id>:SystemExit`); in `main`, an internal error, never exit status 0 | 7.5, 6 |
| a wrapper raises, or returns no state | n/a | FAIL `engine:tool_error` + `skipped:<tool> wrapper failed`; never `ran` | 10.1 |
| a tool crashes or prints garbage | `ran`, zero findings (A15); ClamAV: malware | not `ran`; a WARN; ClamAV exit other than 0/1 is not malware | 10.3 |
| a hostile line (ReDoS) | `grep` is linear | linear matcher for any buffer with a line over 8 KiB; no per-line cap (contract S12 is amended, D-043); every pattern the engine runs, report rows and code rules alike, is a registered `Matcher`/`RuleSet` leaf covered by the hostile-line test | 9.1, 9.2 |
| per-file time budget reached | n/a | non-downgradable FAIL `engine:scan_incomplete:<id>:time_budget` + `partial`. The budget is `120 s + 10 s per MiB` of the file, so a legitimate large file completes (a fixed 120 s was reached by the universal layer alone at about 185 MB, F11) | 9.3, D-035 |
| a pattern that is invalid | silently inert forever | exception at import, reported as a load error and a not-ported scanner | 9.1 |
| an internal error | abort, no report, no sidecar | FAIL verdict, FAIL sidecar, report if possible, `PASS` unreachable | 6 |
| engine errors in the allowlist | n/a | `engine:` messages are never allowlisted and never below the threshold | 8.3 |
| hostile `.transit-allow.json` / `.transitignore` | followed through symlinks, any size | regular non-symlink file of at most 1 MiB, else absent (can only remove exceptions) | 5.1, D-036 |
| relative scan directory in diff mode | scans nothing and passes (A19) | compared by absolute path | D-019 |
| `.transitignore` of `*` (or of anything) | passes with nothing scanned and no trace (A4, F15) | WARN `transitignore:exclusions_applied(<n> pattern(s))` whenever the file yields a pattern; FAIL `engine:nothing_scanned:transitignore` when the patterns removed every file; a file with more than 64 globs or a pattern over 256 characters is refused as a whole (it can only make the scan examine more) | 6, 12.1, D-004, D-044 |
| a NUL byte in a file | `excl` rules silent (D-029), credential formats silent (D-014) | residual by default (copy); switches | 12, 17 |
| shebang with arguments | no shell analysis (D-031) | residual by default (copy); switch | 12, 17 |
| gitleaks reading the repository's own config | possible unless forced | S8 in the wrapper | 10.3 |
| a missing or empty verdict | callers treat as FAIL | the same; `PASS` is printed once, last, after both sidecars, and the exit status is 0 only if that line was written | 6 |

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
| F9 | The known-credential rules, the private-key test (header lines, a window of five lines after each, a fold, then the body search; first prototyped with `rx.after_context`, which the review replaced, F13) and `binary="skip"` work as the design needs: a real PEM body is found, a file-type signature, prose and a placeholder body are not; a token is found in text, hidden by a NUL in the first 32 KiB with `binary="skip"`, found with `binary="text"` | small script over `transit/rx.py` | the algorithms in `universal.py` / `credentials.py` docstrings are implementable as written |
| F10 | All 20 stub modules import with no output, no warning from a new file, no SIGALRM change, no file created, on Python 3.10, 3.11, 3.12, 3.13 (re-run after the review); the 22 files (the entry point and `tests/engine/__init__.py` included) parse with `feature_version=(3, 10)` and compile with warnings as errors; the import graph between them is acyclic and satisfies the layering lints of 3.2 as amended | `check_stubs.py`, `check_graph.py` (Appendix B.2) | section 3.2 |
| F11 | The linear matcher costs about 38 ns per byte per rule. The 11 universal table patterns over 10 MB (one 9 KB line, ordinary lines otherwise) took 4.16 s in total (0.31 to 0.48 s each), against 1.07 s for `re` with `budget=0.25`; `re` with a budget on a large buffer ends up on the same linear matcher | `rx.dfa_search`, `rx.search_lines` per pattern of `patterns.json` | the per-file deadline cannot be a fixed 120 s: 17 universal rows alone reach it at about 185 MB (R-02); section 9.3 |
| F12 | `rx.lines_over` and `rx.after_context` split the whole buffer: 28 MB of `ab\n` peaked at 576 MB and 85 MB at 1,705 MB, about 19 times the input; a `bytes.find` loop stayed at the input size | `resource.getrusage` | `has_long_line` is an aligned-block count with O(1) memory; no helper may split a buffer; `max_file_bytes` 512 MiB (R-04) |
| F13 | `rx.after_context` on `-----BEGIN ` + `PRIVATE KEY ` * k + `x` is quadratic and unbudgeted: 46 KB 0.20 s, 93 KB 0.87 s, 281 KB 6.70 s; `rx.matching_lines(budget=0.25)` 0.19, 0.26, 0.31 s; `rx.dfa_search` 0.002, 0.003, 0.010 s | timing script | `private_key_present` walks `ctx.spans` and builds the windows itself (R-18) |
| F14 | A tree 5,202 bytes deep (102 directories of 50 characters): `find` lists the file (5,217-byte path), an `os.scandir`-by-path walk fails at 4,135 bytes with ENAMETOOLONG, bash gives PASS (the file is absent from `file_results`), a walk through directory descriptors lists it | `os.mkdir(dir_fd=)`, three walkers, `scan_pipeline.sh` | `files.open_beneath`, the descriptor walk, D-041 (R-09) |
| F15 | bash: an XML with an external entity is FAIL at 4,000,059 bytes and PASS at 5,300,055 (the `grep_flat` cap, L462); a payload in `.manifest_sha256.txt`, at the root or nested, is never examined, a repository whose only payload is a nested one is PASS, and `zip -r . -x ".manifest_sha256.txt"` still lists `sub/.manifest_sha256.txt`; a `.transitignore` of `*` hides everything (E14, reproduced again) | bash runs on scratch repositories | D-038, D-039, D-004 (R-01, R-03, R-08) |
| F16 | `json.loads('[' * 200000 + ']' * 200000)` raises `RecursionError`, not a `ValueError`, on Python 3.10, 3.11, 3.12 and 3.13; `raise SystemExit(0)` inside `try/except Exception` is not caught (status 0 follows); in diff mode a changed `a:b.py` is dropped (PASS where `plain.py` is FAIL) and `git diff --name-only` prints `é.py` as `"\303\251.py"`; `os.path.abspath('/tmp//repo/a.py')` is `/tmp/repo/a.py` while the recorded key is `/tmp//repo/a.py`; two names `x<0xFE>.py` and `x<0xFF>.py` share one `file_results` key | python3.10 to 3.13 and bash runs | `parse_allowlist` catches `Exception`; `invoke` and `main` handle `SystemExit`; D-042; `contained_path`; the collision merge (R-05, R-06, R-07, R-12, R-13) |

## 3. Module map

### 3.1 Every file

"New" files are the stubs delivered with this design. "Existing" files are not touched by this phase.

| File | Status | Responsibility |
|------|--------|----------------|
| `scan_pipeline.py` | new | The entry point. Refuses Python older than 3.10 with a readable message, puts its own directory first on `sys.path` (the launcher runs it with `-I`, which does not), and calls `transit.pipeline.main(sys.argv[1:], os.environ)`. Nothing else; exits with the returned status. |
| `transit/__init__.py` | existing | Package docstring. |
| `transit/config.py` | new | Contract 2. Parses the environment once into an immutable `Config` (work directory, verbosity, `MIN_SEVERITY` word and number, `RUN_SCA`/`RUN_SCANCODE`, staged-data directories, `REPO_INPUT`, `TMPDIR`, the local timestamp) plus the engine's own `Limits`, the divergence switches and the notices to print. Also owns the constant tables every module shares: the 14 excluded directories, the nine coverage layer ids (seven required, two optional), the `standards` lists, the exit codes. A leaf: imports nothing from the engine. |
| `transit/console.py` | new | Contract 3.1, S1, S2, D-017. The only module that writes to stdout or stderr. `sanitise` replaces C0, DEL, C1, the `BIDI_CONTROLS` and undecodable bytes by `?` (the progress line included: the file name in it is repository text); `Console` prints `[INFO]`/`[OK]` on stdout (quiet suppresses), `[WARN]`/`[FAIL]` on stderr (never suppressed), the verdict line, the progress line, and a sanitised traceback. Swallows a closed pipe. A leaf. |
| `transit/cli.py` | new | Contract 1. Strips `--*` words, takes the first three positionals, runs the four refusal checks in order (usage, directory, report directory, scanning name), removes trailing slashes, and returns `Args`. Creates nothing. A leaf. |
| `transit/findings.py` | new | Pure functions of a finding message: the one severity classifier (6.3), the structured record builder (5.3), the allowlist parser and token matching (6.2, A10, S15), `json_safe` (S4, D-023), `neutralise_detail` (S7), and the path helpers `relative_to_scan_dir` and `join_scan_path`. No regular expressions, no I/O. A leaf. |
| `transit/verdict.py` | new | The run state that bash keeps in globals (section 4): verdict, per-file status and messages, event counters, the findings stream, the coverage block and its "incomplete" notes, and the run-scoped "already warned" keys. `record_pass`/`record_warn`/`record_fail` implement 6.1 and 6.2 exactly; `record_warn_once` is the once-per-run WARN; `set_allowlist` installs the allowlist once, before the first event; `snapshot()` freezes the state for the report; `abort()` implements the D-028 end and works at any moment after construction. The only object that is mutated during a run. |
| `transit/files.py` | new | The file system side: `prepare_work_dirs`, `Exclusions` (built-in names and `.transitignore`, 8.2 to 8.4, with a hand-written `glob_match`, a literal index and caps), `DiffSelection` (8.6, two formats), `files_for_scan` (8.5; a walk through directory descriptors that skips nothing by name), `open_beneath` (the only way a repository file is opened), `FileView` (one file read once, with `first_line`, `has_long_line` in O(1) memory, an uncapped `flat`, `target`), `TempArea` (3.5, S16) and `compute_hashes` (`source.sha256`, `repo_hash`). No regex is compiled here: `.transitignore` is repository text. |
| `transit/rx.py` | existing, finished | The ERE-to-`re` translator and the grep helpers (`search_lines`, `matching_lines`, `search_excl`, `search_flat`, `only_matching`, `after_context`), the linear matcher, the rule registry and `time_limit`. The only place a rule regex is compiled. Imported as is. |
| `transit/rules/__init__.py` | new | The rule-table machinery: `Match`/`AllOf`/`AnyOf`/`Not` conditions, `RuleSpec` rows, `RuleSet` and `Matcher` (both compile through `rx` and register with `rx.rule`; a `Match` that is in neither cannot be evaluated), `SearchPolicy`, `Target`, and the two evaluation functions `evaluate` and `run_ruleset` that implement the search policy of section 9.2 and the deadline of 9.3. Never records anything. |
| `transit/tools/__init__.py` | new (replaces the one-line docstring) | Everything about running external programs safely: `ToolLocator` (`command -v`), `run_process` (argument list, no shell, new session, enforced timeout, bounded capture), `run_helper_script`, `child_env` (offline variables), the wrapper protocol (`ToolWrapper`, `ToolRequest`, `ToolOutcome`, `Record`) and `load_wrappers`. Defines the policy for an installed tool without a wrapper. |
| `transit/tools/gitleaks.py` | existing | **Program** (reads `sys.argv`). Not run and not imported by the Python engine; test oracle for the gitleaks wrapper's pure parser. |
| `transit/tools/scancode.py` | existing | **Program**. Same: oracle for the ScanCode wrapper's parser. |
| `transit/containers/__init__.py` | existing | Package docstring (safe to import). |
| `transit/containers/office.py` | existing | **Program** (1,766 lines): reads a document, writes a text view, prints `FACT` lines. Run by the office scanner via `tools.run_helper_script("office", ...)`. |
| `transit/containers/jar.py` | existing | **Program**. Run by the jar scanner via `run_helper_script("jar", ...)`. |
| `transit/containers/pdf.py` | existing | **Program** (raises `SystemExit(0)` at import). Run by the PDF scanner via `run_helper_script("pdf", ...)`. |
| `transit/scanners/__init__.py` | new (replaces the one-line docstring) | The registry (`KNOWN_SCANNERS`, `ScannerSpec`, `load_registry`, `Registry.unported`), the `ScanContext` every scanner receives (recording, rules, `spans`, `file_tool`, `apply_tool_records`, `delegate`), and the guard (`invoke`, `guard`) that turns a scanner's failure, `SystemExit` included, into a recorded FAIL. The one module under `scanners/` and `rules/` allowed to import `verdict` and `console`. |
| `transit/scanners/manifests.py` | existing | **Program**. Run by the `package.json`/`composer.json` scanner via `run_helper_script("manifests", ...)`. `load_registry` never imports it (`SCRIPT_MODULES`). |
| `transit/scanners/universal.py` | new | Layer 4: the universal rules that run on every file before its own scanner (CWE-798, CWE-321 with its header-window-then-body test built on two `Matcher`s, the known formats, the certificate note, three CWE-22 rules, five WARN rules). Not registered; called by `layers`. |
| `transit/scanners/credentials.py` | new | The 18 known-credential-format rules and the JWT warning as a library function shared by the universal layer, the jar scanner and the office scanner; every pattern is a registered `Matcher`. Owns the `grep -I` semantics and the placeholder exclusion. |
| `transit/scanners/python_lang.py` | new | Scanner `python`: Bandit (via `ctx.file_tool`) plus six pattern rules. |
| `transit/scanners/shell.py` | new | Scanner `shell`: ShellCheck plus five pattern rules. |
| `transit/scanners/doc.py` | new | Scanners `docs` (`.md .txt .rst`) and `json` (`.json`): one inline credential rule each. |
| `transit/scanners/requirements.py` | new | Scanner `manifest.requirements`: five rules on `requirements*.txt` and `constraints*.txt`. |
| `transit/scanners/unknown.py` | new | The pseudo scanner `unknown`: shebang routing by delegation, then the MIME check (`file(1)`), else PASS. |
| `transit/dispatch.py` | new | `classify_file` (8.8 rules 2 to 5) over the route tables `BASENAME_ROUTES`, `EXT_ROUTES`, `SHEBANG_ROUTES`, the RTF and Flat-OPC probes, `lower_ext`, `routed_patterns`. Calls scanners through a callback; imports no scanner. |
| `transit/layers.py` | new | Layer orchestration: `ToolSlot` tables (the exact missing-tool texts of 5.1 and 7), `run_slot` (the generic whole-directory tool driver, S9), layers 1, 2, 3, 6, the per-file loop for layers 4 and 5 (`run_file_layers`, with `search_policy` and the size-scaled `file_deadline`, and the FAILs for unreadable directories and for an exclusion that removed everything), the layer-3 offline notes, `finalise`, `run_all`. Generic: a Phase 4 package adds a wrapper file and edits nothing here. |
| `transit/report.py` | new | Contract 3.3, 3.4, 4: `report_paths`, `build_report` (the dict of section 4, sorted, JSON-safe, colliding keys merged), `render_html` and `html_escape` (S3, D-017, bidi controls too), `write_atomic` (S5), `write_reports`, `clear_sidecars` (D-040), `write_sidecars`. A pure-function replacement for `report_json.py`. |
| `transit/report_json.py` | existing | **Program** (needs `REPORT_*` variables). Not used by the Python engine; the oracle `tests/engine/test_report.py` compares `build_report` with. |
| `transit/pipeline.py` | new | `main(argv, environ)`: the 15 steps of section 6, the D-028 handler, signals, the exit status. Nothing imports it except `scan_pipeline.py`. |
| `tests/engine/__init__.py` | new | Documents the test layout and puts the repository root on `sys.path`. |

### 3.2 Layering

```
leaves (stdlib only):   config   console   cli   findings                       rx (existing)
                          │         │              │                              │
                          │         └─────┬────────┘                              │
                          │             verdict (console, findings)               rules (rx)
                          │                                                       │
                          ├────────────── files (config, findings, rules) ◄───────┤
                          ├────────────── tools (config)                          │
                          │                                                       │
                          └──► scanners/__init__ (config console files rules tools verdict)   ← the one importer of console/verdict
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

Rules (a lint in `tests/engine/test_lints.py` enforces each): no import cycle; **no module under `transit/scanners/` or `transit/rules/` except
`transit/scanners/__init__.py`** imports `transit.verdict` or `transit.console` (the package `__init__` defines `ScanContext`, whose constructor
names both types, and imports no more than that; review log R-11), and **none at all** imports `transit.layers`, `transit.pipeline` or `transit.report`;
none of `transit/files.py`, `transit/rules/`, `transit/scanners/universal.py` or `transit/scanners/credentials.py` calls `rx.after_context` or
`rx.lines_over` or splits a whole buffer with `.split(b"\n")` / `.splitlines(` (memory, F12; a Wave 2 or 3 scanner that builds a derived view is held to the
memory acceptance test of section 14.2 instead); nothing imports `transit.layers` or
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
| the console (stdout/stderr) | `console.sanitise` inside every `Console` method, **`progress` included** (it is cut to 80 characters after sanitising; contract 3.1 says "not needed" and is amended, R-10); callers pass text as it is | S1: names with ESC, CR, TAB, DEL, U+009B, U+202E, a literal `\033`; every byte of both streams is printable or LF, with the progress line drawn (`err_is_tty=True`) |
| the JSON report | `findings.json_safe` on every string in `build_report`; `json.dumps` writes strict UTF-8; control characters are JSON-escaped | S4: golden `hostile_non_utf8_name`, `hostile_escape_name`; a strict parser reads the file |
| the HTML report | `report.html_escape` on every interpolated value (control bytes and `BIDI_CONTROLS` as character references) | S3: golden `hostile_html_name`; no `<img` / `<script` from a name; a U+202E name is written as `&#x202E;` |
| a message used for severity | `classify_severity` reads only the fixed position of a `semgrep[` message; `neutralise_detail` for archive/part names; a producer may pass `severity=` explicitly | S7: a jar entry `a:LOW:b` still FAILs |
| a shell | never: `tools.run_process` takes an argument list, `shell=False`; a path given to a tool is absolute or follows `--` | S6: the 8 hostile names of E13b; a lint forbids `shell=True`, `os.system`, `os.popen`, `eval`, `exec` in `transit/` |
| a path that is opened | the engine opens only: files listed by its own walker, **through `files.open_beneath`** (component by component with `dir_fd=` and `O_NOFOLLOW`, so the length of the path does not matter, F14, and a symlink swapped in during the run is not followed), `<scan_dir>/.transit-allow.json` and `<scan_dir>/.transitignore` via `files.read_repo_config_file` (regular file, not a symlink, at most 1 MiB), `<WORK_DIR>/.diff_files`, and files it created in `TempArea`. A path reported by a tool is mapped with `files.contained_path` and used as a dictionary key, never opened | S14, S15 |
| a regular expression | a rule pattern is compiled by `rx` from engine data and registered (`RuleSet` or `Matcher`; an unregistered `Match` cannot be evaluated); `.transitignore` globs are matched by `files.glob_match` (no regex; at most 64 globs of 256 characters, literals by set lookup); `findings` uses no regex at all | S12: fuzz gate over `rx.registered()`; the lint on `import re` |
| a file size | `FileView.data()` reads at most `Limits.max_file_bytes` (512 MiB; a larger file is FAIL `engine:file_unreadable:too_large`); peak memory is about twice the file | S12; the RSS test of section 11 |

### 5.2 What is raised

| Module | Raises | Never raises |
|--------|--------|--------------|
| `cli.parse_args` | `UsageError` | anything else |
| `config.load_config` | `ValueError` for an unknown `TRANSIT_FIXES` id | on a bad number (defaults) |
| `findings.*` | nothing (total functions); `parse_allowlist` catches `Exception` (a `RecursionError` from a deeply nested file is not a `ValueError`, F16) and returns an empty allowlist with a note | |
| `verdict.Verdict` | `ValueError` for an unknown layer id or a malformed coverage state; `RuntimeError` for `set_allowlist` after the first event (programming errors) | for any message text |
| `files.*` | `OSError` from `prepare_work_dirs` and `TempArea`; `FileReadError` from `FileView.data` and `open_beneath`; `ValueError` for a bad `name` or a bad `rel` | for a hostile `.transitignore`, `.diff_files` or tree (S15); `files_for_scan` reports what it cannot list, it does not raise |
| `rules.*` | `ValueError`/`rx.EREError` at `RuleSet` construction; `ScanBudgetExceeded` from `evaluate`; `rx.RegexTimeout` only for a pattern with no linear matcher | at `run_ruleset` (it returns `skipped`/`timed_out`) |
| `tools.*` | `ValueError` for an empty argv, `KeyError` for an unknown helper | `run_process` never raises for a failing child |
| `scanners.invoke` / `guard` | nothing except a `BaseException` that is not `SystemExit` (the signal exception, Ctrl-C) | it turns every `Exception` and every `SystemExit` into a recorded FAIL (section 7.5) |
| `report.*` | `OSError` from the writers and from `clear_sidecars` when neither sidecar can be removed or overwritten; `ValueError` for a bad verdict | |
| `pipeline.main` | nothing | it converts everything, `SystemExit` and every other `BaseException` included, into an exit status; 0 only after `PASS` was written (section 6, D-028) |

## 6. Control flow of a run

`pipeline.main` performs these steps in order. The right-hand column is the contract section the step satisfies; the owning module is in brackets.
The numbering changed in the review (R-05): the `Verdict` exists from step 5, before anything that can fail with an exception, so the D-028 handler
always has something to `abort`.

| # | Step | Contract |
|---|------|----------|
| 0 | `scan_pipeline.py`: Python >= 3.10 or exit 1 with a message; `sys.path.insert(0, <its directory>)`; `sys.exit(main(sys.argv[1:], os.environ))` | 3.2 (exit status) |
| 1 | `main` installs handlers: SIGTERM/SIGHUP/SIGINT raise the private **`_Terminated(BaseException)`** carrying the signal number, in the main thread (so `finally` runs); SIGPIPE is ignored; **SIGALRM is left alone** (section 9.3). They are restored when `main` returns. A provisional `Console("normal")` serves steps 2 and 3 | 3.2 (killed by a signal: no verdict, 128+n) |
| 2 | `cli.parse_args(argv)` [cli]: strip `--*`, positional 1..3, checks in order: usage, directory, report directory, scanning name; trailing slashes off. On `UsageError`: `Console.error(message)`, **return 1**, nothing written, `WORK_DIR` not created | 1.1 to 1.5, 3.2 row "argument refused" |
| 3 | `config.load_config(environ)` [config]. `ValueError` (bad `TRANSIT_FIXES`) is a refusal like step 2. Then `Console(cfg.verbosity)`; print `cfg.notices` (OFFLINE ignored, rejected `MIN_SEVERITY`/`VERBOSITY`) | 2, D-020, D-025 |
| 4 | `report.report_paths(args, cfg)` [report]; `files.prepare_work_dirs(cfg.work_dir)` [files] creates `reports/`, `quarantine/` (0700), `approved/`. On `OSError`: **one `Console.error` line, return 1, NO verdict line, no report, no sidecar** (nothing can be written; contract 3.2 "Aborted after validation": an `[INFO]`/`[OK]`/`[FAIL]` line, not a verdict) | 2, 3.2, 3.3, 3.4, D-027 |
| 5 | **`report.clear_sidecars(paths)`**: remove `.scan_verdict` and `.scan_report_json`, so that no exit that does not reach step 14 can leave the previous run's PASS for a caller that reads sidecars (an OOM kill, a SIGKILL, a full disk; D-040). If a sidecar cannot be removed it is overwritten (`.scan_verdict` with `FAIL`); if that fails too, `Console.error` and return 1 as in step 4. Then **construct the one `Verdict`** with an empty `Allowlist` and the threshold. **From here on, every `Exception` and every `BaseException` except `_Terminated` is an internal error handled by D-028** | 3.3, 6, D-028 |
| 6 | `temp = files.TempArea(cfg.tmpdir)` [files] (an unwritable `TMPDIR` raises `OSError`, which is an internal error: FAIL report, exit 1); cleanup is registered three ways: the `finally` of `main`, `atexit`, the signal path | 3.5, S16 |
| 7 | Allowlist: `files.read_repo_config_file(scan_dir, ".transit-allow.json")` then `findings.parse_allowlist(raw, strict=cfg.fix("D-010"))` (neither raises: a refused, unreadable or hostile file, `RecursionError` included, is an empty allowlist and a note) and `verdict.set_allowlist(...)` [files, findings, verdict]; notes to stderr; info line `Allowlist: n exception(s) loaded` | 6.2, A10, S15 |
| 8 | `files.load_exclusions` and `files.load_diff_selection(cfg.work_dir, cfg.since_commit, scan_dir)` [files]. A stale `.diff_files` without `SINCE_COMMIT` is a stderr WARN only. Then **record in the report**: `Exclusions.patterns` non-empty -> WARN `transitignore:exclusions_applied(<n> pattern(s))` on `__global__` (D-004, no switch); `DiffSelection.unresolved` > 0 on an active diff -> WARN `engine:diff_entries_unresolved(<n>)` on `__global__` and `note_incomplete` on L4 and L5 (D-042) | 8.2 to 8.6, S15 |
| 9 | Build `layers.RunEnv` with `tools.ToolLocator`, `tools.load_wrappers()`, `scanners.load_registry()`; print the info lines `Starting scan`, `Standards` | 6, 7 |
| 10 | `files.files_for_scan(scan_dir, exclusions, diff)` [files] | 8.5, 8.6 |
| 11 | `layers.run_all(env, scan)` [layers]: layer 1 (4 slots), layer 2, layer 3 (or `skipped:disabled (RUN_SCA is not true)`), layers 4 and 5 over the file list with `universal.scan` then `dispatch.classify_file` per file (and the FAILs for unreadable directories and for an exclusion that removed everything), layer 6 (or `skipped:disabled (RUN_SCANCODE is not true)`), `finalise` | 7, 8.1, 8.8, S9 |
| 12 | `files.compute_hashes(scan_dir)` [files] | 4 (`source.sha256`, `repo_hash`) |
| 13 | `snapshot = verdict.snapshot()`; `report.build_report(...)` [report]; `report.write_reports(...)`: JSON then HTML, each `write_atomic` | 3.4, 4, S3, S4, S5 |
| 14 | `report.write_sidecars(paths, verdict)`: `.scan_verdict` then `.scan_report_json`, in `WORK_DIR` | 3.3 |
| 15 | `Console.info("JSON report : ...")` lines, then `Console.verdict("PASS"/"FAIL")` as the **last** stdout write; `main` returns 0 for PASS, 1 for FAIL | 3.2 |
| * | `finally`: `temp.cleanup()`; restore handlers; flush streams | 3.5, S16 |

D-028, the internal-error path (steps 6 to 14). `except Exception` **and `except BaseException` for everything that is not `_Terminated`** (a `SystemExit(0)` from a library, a
`KeyboardInterrupt` that did not come from the handler, `GeneratorExit`) in `main` calls, each inside its own `try` so one failure cannot stop the next:
`Console.exception("internal error", exc)` (sanitised, stderr); `Verdict.abort(type(exc).__name__)` (the FAIL `engine:internal_error:<class>` on `__global__`
and `skipped:engine aborted (<class>)` for every required layer without a state); then steps 12 to 14 with the hash replaced by 64 zeros if it cannot be
computed; and finally `Console.verdict("FAIL")`, **return 1**. If everything fails, `FAIL` is still printed and 1 returned. `PASS` is printed only by step 15 of a
run that reached it, and `Console.verdict` is called exactly once (a test asserts the verdict line appears once, last). A scanner's exception never gets here:
section 7.5 contains it to its file. **The status is derived from one fact**: `main` returns 0 if and only if it has just written `PASS` in step 15; every other
path returns 1, or 128+n for `_Terminated`. A `SystemExit(0)` raised anywhere (a test injects one into `layers.run_all`) therefore ends as `FAIL` and status 1, never as 0
with no verdict line, which every status-only caller reads as PASS (R-06). `_Terminated` is not an internal error: it ends the run with 128+n, no verdict line and (since step 5)
no sidecar, and `temp.cleanup()` still runs.

Ordering guarantees a test pins: nothing is written before step 2 succeeds; the reports exist before the sidecars; the verdict line comes after both sidecars;
a refused argument leaves `WORK_DIR` uncreated; the report directory is never created; **after step 5 no sidecar from an earlier run exists, whatever happens next**.

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
    run = ctx.file_tool("bandit")                       # bash: has_cmd bandit ... record_warn "$f" "bandit missing"
    if run.status == "missing":
        ctx.record_warn("bandit missing")
    fired = ctx.apply_tool_records(run)                 # every record, in order, WARNs included; True if a FAIL record was applied
    fired = ctx.run_rules(RULES).fired or fired         # bash: the grep_check calls, in order
    ctx.finish(fired)                                   # bash: $failed || record_pass "$f"
    return True

SCANNERS = (ScannerSpec(id="python", family="python", fn=scan, bash_function="scan_python", tools=("bandit",), ported=True),)
```

Rules for a scanner module: (1) its name is not in `SCRIPT_MODULES` and does not start with `_`; (2) importing it compiles its tables and does nothing else
(no I/O, no signal, no output); (3) no module-level mutable state; (4) it never imports `verdict`, `console`, `layers` or `pipeline`; (5) it records at least
one event per file; (6) it flips `ported=True` only when complete; (7) the messages are the bash messages, character for character; (8) **every pattern is
registered at import**: a `RuleSet` row, or a module-level `Matcher` for code that is not a row, and a condition that combines them (`AllOf`, `AnyOf`, `Not`)
is a module-level constant too; a `Match(...)` built inside a function cannot be evaluated (`rules.evaluate` raises `ValueError`), so the hostile-line test and
the fuzz gate see every pattern the scanner can run (R-18, R-21); (9) a tool's result is applied with `ctx.apply_tool_records(run)`, never by a loop of its own,
so the WARN that explains why a tool was unusable is not dropped (R-24).

### 7.2 What a scanner receives: `ScanContext`

| Member | Meaning |
|--------|---------|
| `path`, `rel`, `basename`, `ext`, `sniffed`, `cfg`, `view`, `temp` | identity and read-only environment. `path` is the key in `file_results` (`scan_dir/rel`) |
| `record_pass()`, `record_warn(msg, file=None)`, `record_fail(msg, file=None, severity=None, downgradable=True) -> Outcome` | forward to `Verdict` for this file (or `file=` for a whole-directory finding such as the archive path a jar view belongs to) |
| `run_rules(ruleset, data=None) -> RuleOutcome` | evaluate a table (optionally against derived bytes), record each hit in table order, return `fired` (any `fail` rule matched, even if downgraded) |
| `search(cond, data=None) -> bool`, `spans(matcher, data=None)`, `target(data=None)` | for logic that is not one table row; `cond` and `matcher` are module-level constants built from registered patterns; `spans` yields the offsets of the matching lines lazily and checks the deadline between items |
| `finish(fired)` | `record_pass` unless `fired` (bash `$failed \|\| record_pass`) |
| `file_tool(name) -> FileToolRun`, `apply_tool_records(run) -> bool` | run a per-file external tool or learn why not (7.4); record its records in order and learn whether a FAIL was among them |
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
| a per-file tool (bandit, shellcheck, cppcheck, hadolint, checkov, semgrep for JS, file(1), strings, unzip) is installed, no wrapper | `ScanContext.file_tool` | `FileToolRun("not_ported")`; once per run (`Verdict.record_warn_once("tool_not_ported:<tool>", ...)`, the run's only mutable object holds the memory) the same WARN; `note_incomplete("L5_per_language_sast", "python engine has not ported <tool> yet")`, which makes the L5 state `partial:...` |
| the tool is not installed | `layers.run_slot` / `file_tool` | the exact bash WARN and state of contract 5.1 / 7 (`gitleaks missing — secret scan skipped`, `skipped:gitleaks not installed`, per file `bandit missing`) |

Why `partial:` for L5 and `skipped:` for the others: layer 5 did run (every file got its pattern rules); one of its tools did not. Both start with something other than `ran`,
so both keep `coverage_complete` false and put the layer in `coverage_gaps` (contract 7). The gate for cut-over (Phase 6) is `Registry.unported() == ()` and no tool without a wrapper;
`tests/engine/test_cutover.py` (WP-V) fails while either is non-empty; it does not exist in Wave 1, so nothing is red before Wave 3 is merged.

### 7.5 Errors inside a scanner (contract 11, D-028, S9)

`scanners.invoke` (and `guard` for the universal layer) wraps every scanner call. What it records, all non-downgradable (`engine:` messages are never allowlisted and never
below the threshold, 8.3):

| What happened | Recorded | Coverage note |
|---------------|----------|---------------|
| per-file deadline passed (`ScanBudgetExceeded`) | **FAIL** `engine:scan_incomplete:<id>:time_budget` | `partial:per-file time budget reached` on L5 |
| `FileReadError(reason)` | FAIL `engine:file_unreadable:<reason>` | |
| `rx.RegexTimeout` (a pattern with no linear matcher) | FAIL `engine:regex_timeout:<id>` | |
| any other `Exception`, `NotImplementedError` and `MemoryError` included | FAIL `engine:scanner_error:<id>:<ExceptionClass>`; the sanitised traceback goes to stderr only | |
| **`SystemExit`** (a library or a helper import that exits) | FAIL `engine:scanner_error:<id>:SystemExit`; the run goes on | |
| the scanner returned `True` and recorded nothing | FAIL `engine:scanner_error:<id>:no_outcome` | |
| the scanner returned `False` and the context was not sniffed | FAIL `engine:scanner_error:<id>:returned_not_mine` | |
| any other `BaseException` (the signal exception, Ctrl-C, `GeneratorExit`) | propagates to `main` (section 6: `_Terminated` ends the run with 128+n, anything else is an internal error) | |

Why FAIL and not WARN: a crashing scanner means a file was not examined; a hostile repository must not be able to craft a file that crashes a parser, or that burns the time
budget, and gets only a WARN. The budget row was a WARN in the first draft and the review (R-02, R-17) moved it to FAIL for exactly that reason; it is safe to do so because the budget now
scales with the file (9.3), so a legitimate large file does not reach it on a normal host. The exception **text** is never put in the report (it can contain a file name); only the class name is.

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
| `engine:scan_incomplete:<id or ruleset>:time_budget` | **FAIL** | the file | `invoke`, `ScanContext.run_rules` |
| `engine:scanner_load_error:<module>`, `engine:wrapper_load_error:<module>` | WARN | `__global__` | `layers.finalise` |
| `engine:file_unreadable:<reason>` (`too_large`, `permission`, `io`) | FAIL | the file | `layers.run_file_layers`, `invoke` |
| `engine:directory_unreadable:<reason>` (`permission`, `io`, `too_deep`); `engine:directory_unreadable:more_not_listed_<n>` after the first 200 | FAIL | the directory; `scan_dir` for the summary | `layers.run_file_layers` |
| `engine:nothing_scanned:transitignore` | FAIL | `scan_dir` | `layers.run_file_layers` |
| `engine:diff_entries_unresolved(<n>)` | WARN | `__global__` | `pipeline` step 8 |
| `transitignore:exclusions_applied(<n> pattern(s))` (the D-004 text of the register; not an `engine:` message) | WARN | `__global__` | `pipeline` step 8 |
| `engine:regex_timeout:<id>` | FAIL | the file | `ScanContext.run_rules`, `invoke` |
| `engine:scanner_error:<id>:<class>` (`no_outcome`, `returned_not_mine` as class) | FAIL | the file | `invoke`, `guard` |
| `engine:tool_error:<tool>:<class>` | FAIL | `scan_dir` | `layers.run_slot` |
| `engine:internal_error:<class>` | FAIL | `__global__` | `Verdict.abort` (D-028) |

Properties: a message starting `engine:` is never matched by the allowlist and never turned into `LOW_SEV(...)` (`Verdict.record_fail`, `Allowlist.lookup`), so a repository cannot configure
an internal error away; its structured record has tool `engine`, category `security`, rule id the second segment. A file name never appears in the text of an `engine:` message: it is the `file` argument.

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
| `file_results` | `Snapshot.file_status` and `file_message` (D-009 strip); two paths that collide after `json_safe` are merged: worst status, messages concatenated (D-045) |

The report validates against `docs/report.schema.json` and passes every invariant of `tests/conformance/check_schema.py`; `tests/engine/test_report.py` runs that checker on reports built
from a `Verdict` driven through the scenarios of the golden files.

## 9. Rule tables, regular expressions and time

### 9.1 The shape of a rule table and how it maps to bash

One `RuleSpec` is one `record_fail`/`record_warn` guarded by one `grep` condition. Fields: `id` (`<scanner id>/<NN>-<slug>`, unique across the engine), `outcome` (`fail`|`warn`), `message` (the
bash string, exact), `cond` (a `Match`, or `AllOf`/`AnyOf`/`Not` of them), `severity` (normally `None`), `applies_to` (basenames and extensions inside a scanner that branches on the name), `source`.

| Bash call | `Match(...)` | `rx.rule` label | `binary` |
|-----------|-------------|-----------------|----------|
| `grep_check P F` | `Match(P)` | `line` | `text` (no `-I`: a NUL byte or invalid UTF-8 changes nothing, E8) |
| `grep_check_i P F` | `Match(P, ci=True)` | `line_i` | `text` |
| `grep_check_excl P X F` | `Match(P, excl=X)` | `excl` | `text` in the row; **bash's NUL blindness (D-029) is applied by `SearchPolicy.excl_nul_blind`, the single control point** (`rx` `binary="grep"` when it is True, `text` with the switch) |
| `grep_flat P F` | `Match(P, mode="flat")` | `flat` | `text`; **no size cap** (D-039) |
| `_pdf_has F P` | `Match(P)` (or code calling `rx.rule(..., mode="line_a")`) | `line_a` | `text` |
| `{ grep_check_i A F && grep_check_i B F; }` | `AllOf((Match(A, ci=True), Match(B, ci=True)))` | each leaf as above | |
| `A \|\| B` | `AnyOf((...))` | | |
| `A && ! B` (exactly one in bash: `scan_go`, `tls\.Config\s*\{` without `MinVersion`) | `AllOf((Match(A), Not(Match(B))))` | each leaf as above | |
| `grep -qIE`, `grep -ohIE` (known credentials) | `Matcher`s in `credentials.py` | `line` | `skip` |
| `grep -E -A5 \| tr \| grep -E` (private key) | code in `universal.private_key_present` over two `Matcher`s (`universal/key-header`, `universal/key-body`) | `line` | `text` |

The pattern text is taken from `tests/conformance/patterns.json` (the record whose `enclosing_function` and `pattern` match); it is the text bash hands to `grep` after quote resolution. `tests/engine`
asserts (a) every `Match.pattern` and `Match.excl` of every table and `Matcher` occurs in `patterns.json`, and (b) after Wave 2, that every `patterns.json` entry of mode `line|line_i|excl|flat` occurs in some table, some `Matcher`
or in a waiver list. Compilation goes through `rx.ere_to_py`; `RuleSet` and `Matcher` register each leaf with `rx.rule(<id>, pattern, mode=<label>, excl=...)`, so `python3 tests/conformance/pattern_fuzz.py`
and `rx.registered()` see every engine rule. **A `Match` that was not registered by one of the two cannot be evaluated**: `rules.evaluate` raises `ValueError`, because an ad-hoc pattern compiled inside a scanner function
would be invisible to the registry, the hostile-line test and the fuzz gate (R-18, R-21; the first draft's `ctx.search(Match(...))` had exactly that blind spot). An invalid pattern is an exception when the module is imported, which the
registry reports as a load error (in bash it is a rule that never fires and never complains).

About the three modes the task statement lists (`line | flat | file`): `line` and `flat` are `Match.mode`; bash has no mode that lets one pattern span a line break except `flat`, so "file" is `AllOf`, a conjunction of line searches each taken over the whole file (the PowerShell
`fetch` and `execute` halves on different lines). The case-insensitive flag is `Match.ci` (forced for `flat` and `excl`, as `grep -iE` is in bash), the exclusion is `Match.excl`.

Semantics: a `fail` rule that matches sets `fired` whatever `record_fail` did with it. Rules run in table order; a rule skipped because the file deadline passed is reported as a FAIL (9.3).

### 9.2 The search policy (measured, F2 to F4, F11)

`rules.evaluate(Match)` chooses the matcher per buffer, not per rule:

```
line mode:   if target.has_long_line and rx.dfa_available(c):  rx.dfa_search(c, data, binary=b)            # linear
             else:                                             rx.search_lines(c, data, binary=b, budget=policy.rule_budget_s)
flat mode:   v = target.flat()   (the whole file with CR, LF, TAB folded; NO cap)
             if len(v) > policy.long_line_bytes and rx.dfa_available(c): rx.dfa_search(c, v)
             else: rx.search_lines(c, v, budget=policy.rule_budget_s)
excl mode:   if target.has_long_line and DFA for both: candidates = rx.dfa_matching_lines(pat, data);
                                                       hit if some candidate line has no match of excl (rx.dfa_search on the slice)
             else: rx.search_excl(pat, excl, data, binary=b, budget=policy.rule_budget_s)   # b = "grep" when policy.excl_nul_blind, else "text"
```

`long_line_bytes` is 8192. At that line length the worst measured `re` search costs about 0.05 s even when the alarm is late, so a file of any size made of lines under 8 KiB costs
`0.25 s + one line` per rule at worst, after which `rx` finishes the buffer with the linear matcher. A longer line never meets `re`. **No per-line cap exists anywhere**: padding a payload
past a cap would hide it (PYTHON_PORT_PLAN status block); a line of any length is searched, linearly. Contract S12 says the Python engine "MUST enforce a per-line cap"; that sentence is amended to "MUST bound the cost of every pattern
on every line length, by a reported cap or by a linear-time matcher" (D-043, section 12.3): the linear matcher meets the intent without the blind spot.

An implementation may send only the over-long lines to the linear matcher and the others to `re` (the linear matcher costs about 38 ns per byte, `re` about 5 on ordinary text, F11), provided the answer equals the
whole-buffer linear answer; that is an internal optimisation, not an interface, and the unit test compares both on random buffers.

`FileView.has_long_line()` is computed once per file by the aligned-block count described in its docstring (`bytes.count` on blocks of `(long_line_bytes + 1) // 2`, O(1) extra memory, about 0.2 s per GiB). It does **not** call `rx.lines_over`, which splits the
buffer into a list of lines and costs about 19 times the file in memory (F12: a hostile 512 MiB file of short lines would need about 10 GB and the kernel would kill the engine with no verdict).
`rx.after_context` is not used either, for the same reason and because it is unbudgeted (F13).

### 9.3 SIGALRM, deadlines and who may arm what

| Timer | Armed by | Scope |
|-------|----------|-------|
| `rx.time_limit(budget)` | `rx.search_*` when `budget=` is passed | one search, main thread only; **not nestable** (F3) |
| `SIGALRM` in `jar.py` / `office.py` | the helper program, in its own process | the helper's own budget plus 10 s |
| `subprocess` timeouts | `tools.run_process` | the child and its process group; no signal is used in the parent |
| per-file deadline | `layers.run_file_layers`: `layers.file_deadline(cfg, entry.size, now=time.monotonic())` = `now + Limits.file_budget_s + Limits.file_budget_s_per_mb * size_in_MiB` (120 s + 10 s per MiB) at the start of the file, shared by the universal layer and the family scanner | checked **between** rules (`run_ruleset`, `ScanContext.check_deadline`, `ScanContext.spans`); never by an alarm |
| the engine itself | nobody | there is **no** engine-level SIGALRM: arming one would be cancelled by the first `rx` search |

Consequences: a search is never wrapped in a second `time_limit`; the main thread is the only thread; `rules.evaluate` raises `RuntimeError` if called off the main thread. When the deadline passes, the
remaining rules of that file are returned as `skipped` and recorded as the **non-downgradable FAIL** `engine:scan_incomplete:<ruleset or id>:time_budget` plus a `partial` note. It is a FAIL because a file whose
rules were not all evaluated has not been examined, and because a deadline a hostile file could exhaust cheaply would be a way to buy a WARN (R-02, R-17).

Why the budget scales (F11): the linear matcher costs about 38 ns per byte per rule, so the 17 rows of the universal layer alone need about 650 ns per byte, and a fixed 120 s was exhausted by a single file of about 185 MB with one long line, inside the universal
layer, before the family scanner started; such a file is within the fetcher's 500 MB limit. At 10 s per MiB the allowance is about 9.5 microseconds per byte. The worst realistic case, every rule of the universal layer (15 patterns, 33 when the credential-format alternation hits and the 18 providers are tried) plus the heaviest scanner (PowerShell, 40 patterns) all running the linear matcher over the whole file, is 73 rules at 38 ns, 2.8 microseconds per byte (2.9 s per MiB), so the allowance is about 3.4 times that.
A file the engine accepts (at most 512 MiB) therefore completes on a normal host, and a file that does not complete is a real finding about the host or the file. The budget does not limit what an attacker can make the engine do (the work is linear in the file whatever the budget says); it decides when the engine stops waiting and says FAIL. The worst case for one file is bounded and linear: `file_budget_s + file_budget_s_per_mb * size` plus one rule's linear pass.
The budget can be overridden (`TRANSIT_FILE_BUDGET_S`, `TRANSIT_FILE_BUDGET_S_PER_MB`); lowering it is how the tests exercise the FAIL.

### 9.4 `rx.only_matching`, the flat view and memory

* `rx.only_matching` has no `budget=` and leftmost-first semantics. `credentials.py` calls it **only** on a line that `ctx.spans` (budgeted) already reported and that is not longer than
  `long_line_bytes`. For a longer matching line the provider is reported **without** the placeholder-exclusion test (fail closed; D-030). `KNOWN_CRED_EXCL` has a back-reference and so no linear matcher (F4); it
  is applied to the short matched text only, never to a line.
* `FileView.flat()` is built once per file and only if a `flat` rule asks. It has **no size cap** (D-039): the folded view is one line, so over `long_line_bytes` it is searched by the linear matcher, and the
  per-file deadline covers its cost.
* One `FileView` exists at a time and is released after its file. A file larger than `Limits.max_file_bytes` (512 MiB) is the FAIL `engine:file_unreadable:too_large`. Peak memory for a file is about twice its size: its bytes plus
  one derived copy (the flat view, or the NUL-to-LF copy of `binary="grep"`). No code in `files` or `rules` may materialise the lines of a buffer (`split`, `splitlines`, `rx.lines_over`, `rx.after_context`: about 19 times the file, F12). There is no `mmap`: `rx` takes `bytes`.
  `tests/engine/test_files.py` and `test_rules.py` read 90 MB of two-byte lines and assert a peak resident size under three times the file.

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
| `test_config.py` | `config` | defaults and overrides of every variable of contract 2; `MIN_SEVERITY` `bogus`, `HIGH`, ` high`, `Critical`, empty, unset -> 3,3,3,4,3,3 (E15); the `OFFLINE=false` notice text; `RUN_SCA` true only for exactly `true`; an unknown `TRANSIT_FIXES` id raises (and `D-004` is no longer a known id); `TRANSIT_*` limits ignore `0` and `abc`, including `TRANSIT_FILE_BUDGET_S_PER_MB`; `timestamp` format; `Config` is frozen |
| `test_console.py` | `console` | S1 with the six hostile names (bytes of both streams printable or LF), S2 (`\033` literal kept), D-017 characters, quiet silences info/ok only, `verdict` accepts only PASS/FAIL, a `BrokenPipeError` is swallowed, progress only on a tty; **the progress line is drawn with `err_is_tty=True` for every hostile name and every byte written is printable, LF, CR or the engine's own `ESC[...m` / `ESC[K`** (R-10); `BIDI_CONTROLS` including U+061C, U+200E, U+200F |
| `test_cli.py` | `cli` | the 19 argument variants of E4 with their exit-1 reasons, `--` words anywhere, trailing slashes (`/` kept), empty positional 2 honours 3, a symlinked directory, a file as directory, 150/151 characters, nothing created on refusal |
| `test_findings.py` | `findings` | `classify_severity` on the 23 messages of E6; `build_record` on the 26 messages of E6 including `engine:`; the 14 allowlist variants of E3 in both modes; `json_safe`; `neutralise_detail` (`a:LOW:b`); `join_scan_path`/`relative_to_scan_dir` for `/`; no `re` import; **`parse_allowlist` of a 400 KB `[[[[...` and of a document that raises `MemoryError` (mocked) returns an empty allowlist and a note, never raises** (R-05) |
| `test_verdict.py` | `verdict` | 6.1 first-writer table (E12) and the D-012 switch; counters (the clean scenario gives pass 4, warn 7); 6.2 order (allowlist before threshold, E21); the `ALLOWED:` and `LOW_SEV(` texts; `engine:` never downgraded; `Outcome` values; coverage validation; `note_incomplete` folding; `abort` (also before any other event); `set_allowlist` once, before the first event, `RuntimeError` after; `record_warn_once` records once per key and counts one event; `snapshot` idempotent and immutable |
| `test_files.py` | `files` | F5: the 24 pattern sets against real `find`; `glob_match` against `find -path` on brackets, escapes, `*`; E2 variants; D-001/D-002; symlinks not listed; E17 diff variants and D-019; `compute_hashes` equals the `sha256sum` recipe and the three E19 values; `FileView`; `TempArea` modes and cleanup; `read_repo_config_file` refusals. **Added by the review:** a file called `.manifest_sha256.txt` at the root and nested is listed (R-01); the 5,202-byte-deep tree of F14 is listed, opened with `open_beneath` and hashed, and `open_beneath` refuses a symlinked component and treats a FIFO as `vanished` (R-09); an unlistable directory (a mocked `PermissionError`) is in `ScanList.errors` with reason `permission`, a tree deeper than `MAX_WALK_DEPTH` has `too_deep`; `.transitignore` with 65 globs, a 257-character pattern, 100,000 literals (the literals work, by lookup) and the F5 sets again through the literal index (R-15); `excluded_by_patterns` counts; `has_long_line` equals `any(len(x) > L for x in data.split(b"\n"))` on random buffers for L in 1..20, and **90 MB of two-byte lines peaks under three times the file** (R-04); `flat()` has no cap: a 5.3 MB XML with an external entity is found (R-08); diff mode: the NUL format, the colon name (`a:b.py` is a key), the quoted non-ASCII name (`"\303\251.py"`), a deleted file with a colon (counted, no key), a hostile list (R-07); `contained_path` with `//`, a relative and a `..` scan directory returns the key of the file's own entry (R-13) |
| `test_rules.py` | `rules` | construction errors; `rx.registered()` contains every leaf; each mode against real `grep`; **a 600 KB hostile line finishes in under 1 s for each of the 28 table patterns of the slice** (the linear matcher measured 0.03 s at worst); deadline gives `skipped`; `RuntimeError` off the main thread; `AppliesTo`; `AllOf`/`AnyOf`/`Not` (the `scan_go` TLS case); `binary` modes; **an unregistered `Match` raises `ValueError`; every `Matcher` is in `rx.registered()` and is covered by the same 600 KB test; `Matcher.spans` equals `rx.matching_lines` and never materialises lines; the line-routing optimisation equals the whole-buffer linear answer on random buffers; a `flat` rule on a 6 MB file is evaluated** (R-08, R-18, R-21) |
| `test_scanners.py` | `scanners/__init__` | discovery (skips `manifests`, `_x`, a module without `SCANNERS`), load errors (unknown id, family mismatch, duplicate, import failure), `unported()`, the eight outcomes of `invoke`, `ScanContext` recording and `finish`, `delegate` depth, the four `file_tool` statuses with fake wrappers; **`invoke` turns a scanner's `SystemExit(0)` into the FAIL `engine:scanner_error:<id>:SystemExit` and the next file is scanned (R-06); a deadline that passed gives the FAIL `engine:scan_incomplete:<id>:time_budget`, not a WARN (R-02); the not-ported WARN of `file_tool` is recorded once for two files (R-22); `apply_tool_records` applies a `warn` then a `fail` in order, returns True only for the fail, and rejects a `pass` record (R-24)**; uses `tests/engine/support.py` |
| `test_dispatch.py` | `dispatch` | `routed_patterns()` equals `build_pdf_filetypes.routed_patterns()`; the 34 family keys; per-family extension sets equal `FAMILIES`; `UPPER.PY`; basename arm order; the 7 shebang lines of F8; every flow of `classify_file` with a fake `run` (xml chain, docs with RTF, unknown with RTF, unported returns True) |
| `test_layers.py` | `layers` | slot texts equal bash (F7); `run_slot` for not installed / not ported / ok / raising wrapper / no state; layers 3 and 6 disabled; the offline notes; `run_file_layers` with zero files, a vanished file, the universal layer guarded; **an unreadable directory gives the FAIL `engine:directory_unreadable:permission` (not a WARN) and 201 of them give 200 plus the summary; a `.transitignore` that removed every file gives `engine:nothing_scanned:transitignore` and a diff run with zero files does not; `file_deadline` is `now + 120 + 10 * MiB`; `search_policy` carries `rule_budget_s`, `long_line_bytes` and `excl_nul_blind = not D-029`; a deadline too short for the file gives the FAIL** (R-02, R-03, R-09, R-25) |
| `test_tools.py` | `tools` | `ToolLocator` cache and `PATH`; `run_process` timeout kills the group, output bounded, never a shell (`$(touch X)` stays an argument), `not_found`; `child_env`; `run_helper_script` against the four real helpers on a tiny input; `load_wrappers` ignores the old scripts |
| `test_report.py` | `report` | `build_report` equals the old `report_json.py` output on the same inputs; schema + invariants through `check_schema.py`; sorted output; `html_escape` (S3, D-017) and `render_html` on the two hostile names; `write_atomic` leaves no partial file when the replace fails and applies the umask; sidecar order; `report_paths` (relative report dir stays relative); **`clear_sidecars` removes both and falls back to overwriting; two snapshot paths that collide after `json_safe` are merged (worst status, both messages) and the checker's invariants hold (R-12); a U+202E name is written as `&#x202E;` in the HTML (R-14)** |
| `test_universal.py`, `test_credentials.py` | L4 | one positive and one near-miss fixture per rule (`tests/fixtures/rules`), tokens built at run time; the CWE-321 cases of F9; a NUL file (grep rules fire, formats do not); a 600 KB line **for every pattern including the key header and body, the alternation and each provider (they are `Matcher`s in `rx.registered()`; R-18)**; `private_key_present` on a 281 KB line of `PRIVATE KEY ` repeated finishes in under 1 s, finds a header followed by a 64-character body line, and finds nothing in a signature or a placeholder body; `fired`/`downgrade` semantics |
| `test_python_lang.py`, `test_shell.py`, `test_doc.py`, `test_requirements.py`, `test_unknown.py` | scanners | each rule row (fail and near-miss); `fired` when the allowlist downgrades; the three bandit/shellcheck statuses; the shebang table; the RTF hand-off; the clean-fixture per-file results |
| `test_pipeline.py` | `pipeline` | in-process run of the clean fixture (last stdout line, exit 0, sidecars, no temporary file left); refusals leave `WORK_DIR` uncreated; D-028 (a `layers.run_all` that raises gives `FAIL`, a FAIL sidecar and a valid report); SIGTERM gives 143 and no temporary file; `Console.verdict` called once and last; nothing about the cut-over gate (that is `test_cutover.py`). **Added by the review (R-02, R-03, R-05, R-06):** a stale `.scan_verdict` containing `PASS` and a stale `.scan_report_json` are gone after step 5 even if the run is then killed by an injected `os._exit`; an allowlist that raises `RecursionError` still completes the run (empty allowlist, note on stderr); an unwritable `TMPDIR` gives a FAIL report, a FAIL sidecar and exit 1; a `WORK_DIR` that cannot be prepared gives exit 1, no verdict line, no report, no sidecar; a scanner that calls `sys.exit(0)` is a FAIL for its file; a `layers.run_all` that raises `SystemExit(0)` gives `FAIL` last and exit 1; `.transitignore` of `*` over a vulnerable repository gives the FAIL `engine:nothing_scanned:transitignore` and a pattern that hides `src/db.py` gives the WARN `transitignore:exclusions_applied(1 pattern(s))`; a file budget of 0.001 s gives the FAIL `engine:scan_incomplete:...:time_budget` and a PASS never |
| `test_entrypoint.py` | `scan_pipeline.py` | runs under `python3 -I` from another directory; the version message under `python3.9` when present |
| `test_cutover.py` | the repository (Wave 4) | `Registry.unported() == ()`; every key of `tools.DIRECTORY_TOOLS` and `tools.FILE_TOOLS` has a wrapper; no `engine:*_not_ported` message on the real-file corpora |
| `test_lints.py` | the repository | the import rules of 3.2 **as amended (every module under `scanners/` and `rules/` except `scanners/__init__.py` is barred from `verdict` and `console`; the lint passes on the stubs as they are; R-11)**; no `rx.after_context`/`rx.lines_over`/whole-buffer `.split(b"\n")` in `files.py`, `rules/`, `universal.py`, `credentials.py`; no `shell=True`/`os.system`/`eval`; no import of the seven helper programs; `compile()` of every file under `transit/` with warnings as errors (F6); no contiguous token in `tests/engine`; every message string in a rule table occurs in `scan_pipeline.sh` |

Conformance (run by CI for each package that touches the output): `python3 tests/conformance/conformance.py check --engine python --case clean` (Wave 1), then the cases whose scanners exist,
and `diff` for bash against Python; `python3 tests/conformance/check_schema.py` on a Python report; `python3 tests/conformance/pattern_fuzz.py --quick` filtered to the rules the package registered.

## 12. Divergences

### 12.1 Handling of the register's entries

`proposed` means copy bash; a switch is a name in `config.KNOWN_FIXES`, off by default. Five rows are not copied because the contract says MUST (S1, S9, S15) or because copying bash would pass a repository with nothing examined (hard rule 6): D-004 (added by the review, R-03), D-017, D-019, D-028 and the Python behaviours of D-005 to D-008 and D-015. The new entries of 12.2 that close a blind spot (D-038 to D-045) are unconditional for the same reason.

| Id | Phase 2 handling | Owner module |
|----|------------------|--------------|
| D-001, D-002 | closed in bash; implemented (directories only, relative to the root) | `files` |
| D-003 | copy (last line without newline dropped, CR kept); switch `D-003` | `files.load_exclusions` |
| D-004 | **implemented, no switch** (review R-03; contract S15 says the Python engine reports exclusions and the first draft's "copy by default" contradicted it): WARN `transitignore:exclusions_applied(<n> pattern(s))` on `__global__` whenever `.transitignore` yields a pattern, and the FAIL `engine:nothing_scanned:transitignore` when the patterns removed every file (not in diff mode). Golden `ignored` stays the bash golden; `tests/conformance/conformance.py` drops that one WARN (and one from `summary.warn`) when it checks the Python engine (WP-13) | `pipeline` (records the WARN, step 8), `layers` (the FAIL) |
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
| D-023 | copy (U+FFFD per invalid byte); **colliding keys are merged, not overwritten** (D-045) | `findings.json_safe`, `report.build_report` |
| D-024 | implemented (sorted) | `report` |
| D-025 | copy (stderr notice only) | `config` |
| D-026 | drop (only the two `OFFLINE:` notes) | `layers` |
| D-027 | copy (`quarantine/` 0700 and `approved/` created) | `files` |
| D-028 | **implemented as proposed** | `pipeline`, `verdict` |

### 12.2 New entries this design proposes (to be appended to `docs/engine_divergences.md` by WP-12 together with the status change of D-004 to "implemented by default"; status `proposed`)

| Id | Area | Bash behaviour | Python behaviour | Decision |
|----|------|----------------|------------------|----------|
| D-029 | grep rules, NUL | `grep_check_excl` on a file with a NUL byte can never match (the first `grep` prints a notice, the second reads nothing): one NUL silences `pip:vcs_requirement_not_pinned_to_a_commit` and every future `excl` rule (E8, rx docstring) | default copies (`SearchPolicy.excl_nul_blind`); switch `D-029` searches as text | needs-decision, recommend fix-in-python |
| D-030 | credential formats | `grep -o` has no line-length problem | a matching line longer than `long_line_bytes` is reported without the placeholder-exclusion test (`rx.only_matching` has no budget) | fix-in-python, fail closed, no switch |
| D-031 | shebang routing | `#!/bin/bash -e` (a shebang with arguments) matches no `case` pattern, so an extensionless script gets no shell analysis (F8) | default copies; switch `D-031` matches the interpreter word | needs-decision, recommend fix |
| D-032 | not-ported tools and scanners | n/a | coverage `skipped:python engine has not ported <tool> yet` / `partial:...`, WARNs `engine:tool_not_ported:<tool>`, `engine:scanner_not_ported:<id>`; disappears when nothing is unported | interim, implemented |
| D-033 | scanner and engine errors | a crashing scanner reads as "ran, found nothing" (D-015) or aborts the run | non-downgradable FAILs `engine:scanner_error` (a `SystemExit` included), `engine:file_unreadable`, `engine:regex_timeout`, `engine:tool_error`, `engine:internal_error`, `engine:scan_incomplete` (time budget), `engine:directory_unreadable`, `engine:nothing_scanned`; `engine:` is never allowlisted | fix-in-python |
| D-034 | `file(1)` missing | unknown-extension files pass with no MIME check and no message (A22) | L5 `partial:file(1) is not installed: ...` when such a file was met | needs sign-off (changes a coverage state) |
| D-035 | resource limits | none | per-file budget `120 s + 10 s per MiB`, expiry a non-downgradable FAIL + `partial` (R-02: a WARN could be bought by a hostile file, and a fixed 120 s could not cover a 185 MB file); unreadable directories FAIL (D-041); file larger than 512 MiB FAIL `engine:file_unreadable:too_large` | implemented |
| D-036 | repository configuration | `.transit-allow.json` and `.transitignore` are read through symlinks, any size | regular file, not a symlink, at most 1 MiB, else treated as absent with a console note (fewer exceptions, never more); a `.transit-allow.json` that makes the JSON parser raise anything (a `RecursionError` from deep nesting) is an empty allowlist | fix-in-python |
| D-037 | per-file Semgrep for JS | `--config=p/javascript` needs the registry; offline it returns nothing and L5 is `ran` | the wrapper never contacts the registry; no staged ruleset gives `failed` and a `partial` note | fix-in-python (Wave 3-F) |
| D-038 | file selection | `[[ "$(basename "$f")" == ".manifest_sha256.txt" ]] && continue` (L3610) skips that name at **any depth**, with no trace; `fetch_repo.sh` writes it only at the root and `ai_transit.sh` excludes only the root one from the ZIP, so a nested file of that name carries any payload into the approved archive (F15) | no file is skipped by name. The root manifest the fetcher writes is scanned like any file (its rules can match a file name, so a repository with `md5.c` gets one extra WARN on the manifest; open question 6) | fix-in-python (fix-in-both recommended), needs sign-off: it adds an event to fetched-repository reports |
| D-039 | grep rules | `grep_flat` returns "no match" for a file over 5,242,880 bytes (L462): every XXE rule of `scan_xml` and `scan_powershell_xml` goes blind on an XML padded past 5 MiB (F15, A28) | no cap: the folded view is searched by the linear matcher, covered by the per-file budget | fix-in-python (fix-in-both recommended) |
| D-040 | outputs | the sidecars of an earlier run survive an aborted run (contract 3.3); only `ai_transit.sh` deletes them | both sidecars are removed right after the report directories exist (step 5); if one cannot be removed it is overwritten with `FAIL`; after that only this run can write one | fix-in-python |
| D-041 | file selection | `find ... 2>/dev/null` loses an unlistable directory without a word; a file below a path longer than PATH_MAX is listed by `find` and cannot be opened by bash, the repository passes (F14, A26) | walk and open through directory descriptors (`open_beneath`); an unlistable directory is a non-downgradable FAIL `engine:directory_unreadable:<reason>` (first 200, then a summary); nesting deeper than 512 is `too_deep`; `compute_hashes` reads such files too | fix-in-python |
| D-042 | diff mode | `fetch_repo.sh` writes `git diff --name-only \| sed \| tr '\n' ':'`; a name with `:` is split in two and a non-ASCII or special name is written quoted (`"\303\251.py"`), so the file is dropped from the diff set and never scanned (A27, F16) | `.diff_files` may be NUL-separated (`git diff -z`); the legacy list is rebuilt by joining up to 16 pieces and C-unquoting, every candidate that names an existing regular file is a key; what cannot be resolved is counted and becomes the WARN `engine:diff_entries_unresolved(<n>)` + `partial` on L4 and L5 | fix-in-python; the producer change in `fetch_repo.sh` is a request to the lead (open question 7) |
| D-043 | S12 | not applicable to bash (grep is linear); contract S12 says the Python engine "MUST enforce a per-line cap" | no per-line cap, because a cap hides a payload padded past it; the linear matcher bounds every pattern on every line length; contract S12 is reworded (12.3) | fix (contract amendment) |
| D-044 | `.transitignore` | any size up to 1 MiB, any number of patterns, any length: the matching cost is controlled by the repository | at most 64 globs and 256 characters per pattern, literals by set lookup; a file over a limit is refused as a whole with a console note, which can only make the scan examine more | fix-in-python |
| D-045 | report | two non-UTF-8 names that collapse to one key (A23): which entry survives is hash-order luck | the entries are merged: worst status wins, messages are concatenated, no finding is lost | fix-in-python |

### 12.3 Contract amendments requested by this design (owner: WP-13)

`docs/engine_contract.md` is the highest authority (precedence rule above), so every place where this design departs from it is an amendment, listed here with its new wording. WP-13 makes them, in one pull request, with `check_schema.py` still green.

| Section | Amendment |
|---------|-----------|
| 3.1 | progress line: `Sanitised: yes` (the name in it is repository text; bash printed it raw, R-10) |
| 3.3 | add: "The Python engine removes both sidecars right after the report directories exist, so no earlier run's sidecar survives an aborted run (D-040)." |
| 5.2 | add the prefixes `engine:` and `transitignore:` to the list of meta prefixes (open question 5; the messages of design 8.3) |
| 8.4 | add: "The Python engine records `transitignore:exclusions_applied(<n> pattern(s))` (D-004) and refuses a file with more than 64 globs or a pattern over 256 characters (D-044)." |
| 8.5 | replace "A file named `.manifest_sha256.txt` is skipped" by "No file is skipped because of its name (the bash engine skipped `.manifest_sha256.txt` at any depth: A25, D-038)"; add "an unlistable directory is a FAIL and a path longer than PATH_MAX is listed (D-041)" |
| 8.6 | add the NUL-separated `.diff_files` format and the colon/quote rebuild (D-042) |
| 8.7 | add: "`grep_flat` has no size cap in the Python engine (D-039)" |
| S1 | the bidi list also contains U+061C, U+200E, U+200F |
| S12 | "the Python engine MUST bound the cost of every pattern on every line length, by a reported per-line cap or by a linear-time matcher; it MUST enforce a per-file time budget whose expiry is a FAIL, and a fuzz gate over every registered pattern" (D-043, D-035) |
| 11 | add A25 (a file named `.manifest_sha256.txt` is never examined, at any depth), A26 (a path longer than PATH_MAX and an unlistable directory pass silently), A27 (a diff-mode name with `:` or non-ASCII characters is dropped), A28 (`grep_flat` ignores a file over 5 MiB) |



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
| 3.3 | sidecar files and order; removal of stale ones at the start (D-040) | `report` (`write_sidecars`, `clear_sidecars`) | `pipeline` calls them |
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
| 8.5 | what `find` lists: no name skipped (D-038), descriptor walk (D-041); a directory that could not be listed is a FAIL | `files` (`files_for_scan`, `open_beneath`); `layers` records the FAIL | |
| 8.6 | diff mode, both `.diff_files` formats (D-042) | `files` (`load_diff_selection`); `pipeline` records the unresolved WARN | |
| 8.7 | grep flags: `-I` versus not; flat view without a cap (D-039) | `rules` (`Match.binary`), `files` (`FileView.flat`) | `credentials` uses `skip` |
| 8.7 | binary and archive by extension | `binary`, `archive` (Wave 2-G) | |
| 8.7 | unknown extension: shebang then MIME | `unknown` | `dispatch.shebang_scanner` |
| 8.7 | RTF and Flat-OPC sniffing | `dispatch` | |
| 8.8 rule 1 | universal layer first | `layers` | `universal.scan` |
| 8.8 rules 2 to 4 | basename arms, lower-cased extension, inline rules | `dispatch` (arms), `doc` (inline rules) | |
| 8.8 rule 5 | every scanner records an outcome | `scanners` (`invoke` enforces, `ScanContext.finish`) | each scanner |
| S1, S2 | console is control-free, the progress line included; backslash text is data | `console` | |
| S3 | HTML escaped | `report` | |
| S4 | JSON always valid | `report` | `findings.json_safe` |
| S5 | report whole or not at all | `report` (`write_atomic`) | |
| S6 | no repository text reaches a shell | `tools` (`run_process`) | lint |
| S7 | severity never read from repository text | `findings` | `neutralise_detail` |
| S8 | gitleaks on our terms | `gitleaks_wrapper` (Wave 3-D) | |
| S9 | fail closed and say so | `layers` (`run_slot`, `finalise`), `scanners` (`invoke`) | every wrapper |
| S10 | tool output never echoed | `tools` | |
| S11 | containers never extracted, limits reported | `jar_scan`, `office_scan` (Wave 3-B/C) | the helper programs |
| S12 | hostile input costs bounded time: every pattern registered and linear-bounded; the size-scaled file deadline, whose expiry is a FAIL | `rules`; `layers` (`file_deadline`) | `files.FileView.has_long_line`, `ScanContext.check_deadline` |
| S13 | an allowlist can only lower, visibly | `verdict` | |
| S14 | the scanned directory is read-only | no module writes there; `ScanContext` has no write API | lint |
| S15 | hostile `.transit-allow.json` / `.transitignore`; exclusions are reported (D-004) | `findings` (allowlist), `files` (`.transitignore`, caps), `pipeline` (records the WARN), `layers` (the nothing-scanned FAIL) | `files.read_repo_config_file` |
| S16 | temporary files private and removed | `files` (`TempArea`) | |
| 11 | A1 to A24 (A25 to A28 added by the review) | section 12 | |

## 14. Work packages

Disjoint file ownership was checked by script (`own_check.py`, which parses the tables of this section; run on the pre-review text it reproduces the earlier "27 packages, 139 files", so the parser is trustworthy): **28 packages, 141 files, no file owned twice**, every scanner id has exactly one module and every module one owner. The review added WP-13 (the contract and the conformance normaliser) and corrected the "Merges after" column: `files.FileView` is a real dependency of WP-05, WP-06 and WP-08 to WP-10 (R-28). Packages that say "all" can be built by
different engineers at the same time: they code against the frozen stubs, and only the *merge order* is constrained (column "Merges after"). A package may not edit a file it does not own; a needed
change is an amendment (1.3).

Shared test support: `tests/engine/support.py` (a fake `ScanContext`, a fake `Verdict` sink, a stub-tool directory builder, a temp-repository builder) is owned by WP-05 and lands first; every scanner package imports it.

### 14.1 Wave 1: Phase 2 completion (13 packages, all parallel; first vertical slice)

| Id | Owns exclusively | Implements | Consumes (frozen interfaces) | Acceptance tests | Merges after |
|----|------------------|------------|------------------------------|------------------|--------------|
| WP-01 | `transit/config.py`, `console.py`, `cli.py`, `tests/engine/test_config.py`, `test_console.py`, `test_cli.py` | `load_config`, `env_number`, `Config.fix`; `sanitise`, `BIDI_CONTROLS`, `Console` (the progress line sanitised before it is cut); `positional_words`, `scanning_name_error`, `parse_args` | nothing | section 11 rows for the three files; the byte-level S1 test, **including the progress line drawn with `err_is_tty=True`**; the 19 E4 variants. Mutations: drop the C1 range; drop the bidi range; **cut the progress line before sanitising it**; accept 151 characters; do not lower-case `MIN_SEVERITY`; strip only the first `--` word | none |
| WP-02 | `transit/findings.py`, `verdict.py`, `tests/engine/test_findings.py`, `test_verdict.py` | everything in the two modules, `Verdict.set_allowlist` and `record_warn_once` included | `console.Console` (a fake with the same methods in tests) | section 11 rows; E6 (23 + 26 messages), E3 (14 variants), E12, E21; the clean scenario gives `pass 4, warn 7`; **`parse_allowlist` never raises (a `RecursionError` document)**. Mutations: threshold before allowlist; `record_warn` overwriting FAIL; per-file instead of per-event counters; drop the `engine:` exemption; `snapshot` returning live dictionaries; **catch `ValueError` instead of `Exception` in `parse_allowlist`; let `set_allowlist` run after an event** | none |
| WP-03 | `transit/files.py`, `tests/engine/test_files.py` | the whole module, `open_beneath`, the descriptor walk, the two `.diff_files` formats, the caps | `config.Config/Limits`, `findings.join_scan_path`, `rules.Target`, `rx` | F5 against real `find` (24 sets), E2, E17, D-001/D-002, D-019, E19 hashes, `read_repo_config_file`, `TempArea` modes; **the review rows of section 11 (nested `.manifest_sha256.txt` listed, the 5,202-byte-deep tree, unlistable directory, caps, `has_long_line` equivalence and the 90 MB RSS test, uncapped `flat`, diff colon/quote/NUL, `contained_path`)**. Mutations: test the scan root against the exclusions; match files against built-in names; **skip `.manifest_sha256.txt` by name; walk by path string; implement `has_long_line` with `rx.lines_over`; cap `flat` at 5 MiB; stop joining diff pieces**; unsorted output; follow symlinks | none |
| WP-04 | `transit/rules/__init__.py`, `tests/engine/test_rules.py` | `Match`/`AllOf`/`AnyOf`/`Not` validation, `RuleSet`, `Matcher` (`search`, `spans`), `evaluate`, `run_ruleset`, the registered-`Match` check | `rx` | section 11 row; the 600 KB hostile line under 1 s for each of the 28 table patterns of the slice **and for every `Matcher` any module registers** (measured worst case of the linear matcher: 0.03 s); each mode against real `grep`; `Not` on the `scan_go` TLS case. Mutations: always use `re`; skip the long-line test; nest `time_limit`; ignore the deadline; **evaluate an unregistered `Match`; materialise the lines in `Matcher.spans`** | none |
| WP-05 | `transit/scanners/__init__.py`, `transit/dispatch.py`, `tests/engine/support.py`, `test_scanners.py`, `test_dispatch.py` | registry, `ScanContext` (`spans`, `file_tool`, `apply_tool_records` included), `invoke`, `guard`; route tables' functions | `verdict.Verdict` (real once WP-02 is merged, fake before), `files.FileView`, `rules`, `tools` types | section 11 rows; `routed_patterns()` equals `build_pdf_filetypes.routed_patterns()`; the nine `invoke` outcomes (the `SystemExit` one added). Mutations: let an exception escape; **let a `SystemExit` escape; make the time budget a WARN**; accept `no_outcome`; import `manifests`; **keep the not-ported WARN in a module global** | WP-02, WP-03, WP-04 |
| WP-06 | `transit/tools/__init__.py`, `transit/layers.py`, `tests/engine/test_tools.py`, `test_layers.py` | `ToolLocator`, `run_process`, `run_helper_script`, `child_env`, `load_wrappers`; `run_slot`, layers 1, 2, 3, 6, `search_policy`, `file_deadline`, `run_file_layers` (directory and nothing-scanned FAILs), `finalise`, `run_all` | `scanners.invoke`, `verdict`, `files`, `dispatch.classify_file` | section 11 rows; the four helper programs run on tiny inputs; `$(touch X)` stays an argument; timeout kills the group; the nine slot texts equal bash. Mutations: run a shell; record `ran` after a wrapper exception; swallow a missing layer; **record an unreadable directory as a WARN; use a fixed deadline; forget `diff.active` in the nothing-scanned test** | WP-02, WP-03, WP-05 |
| WP-07 | `transit/report.py`, `tests/engine/test_report.py` | the whole module, `clear_sidecars`, the collision merge, the bidi escapes | `verdict.Snapshot`, `findings`, `files.SourceHashes`, `cli.Args`, `config`, `console.BIDI_CONTROLS` | `build_report` equals the old `report_json.py`; schema + invariants; S3 on both hostile names; atomic write failure leaves no file; **two colliding names keep the FAIL**. Mutations: no escaping; non-atomic write; verdict before sidecars; **last-writer-wins on a collision; drop the bidi range from `html_escape`** | WP-02 |
| WP-08 | `transit/scanners/universal.py`, `credentials.py`, `tests/engine/test_universal.py`, `test_credentials.py` | the 17 universal rows, `private_key_present` (windows from `ctx.spans`, no `rx.after_context`), `check_known_credentials`, the `Matcher`s of both modules | `ScanContext`, `rules` (`Matcher`) | one positive and one near-miss per rule; F9; NUL; a 600 KB line **for every pattern including the key header and body and the alternation**; the 281 KB `PRIVATE KEY ` line in under 1 s (F13); D-030. Mutations: drop the body requirement; run the formats on a NUL file; apply the exclusion to a long line; **call `rx.after_context`; compile a pattern inside a function** | WP-03, WP-04, WP-05 |
| WP-09 | `transit/scanners/python_lang.py`, `shell.py`, `tests/engine/test_python_lang.py`, `test_shell.py` | both scanners and their tables | `ScanContext`, `rules` | every row (fail and near-miss); `fired` stays true after an allowlist downgrade; the clean fixture's `bandit missing` / `shellcheck missing`; a `failed` tool run keeps its WARN (`apply_tool_records`). Mutations: `finish` always passes; wrong order of bandit and rules; **loop over `run.records` and drop the WARN** | WP-03, WP-04, WP-05 |
| WP-10 | `transit/scanners/doc.py`, `requirements.py`, `unknown.py`, `tests/engine/test_doc.py`, `test_requirements.py`, `test_unknown.py` | the five scanners | `ScanContext`, `rules`, `dispatch.shebang_scanner` | every row; the RTF hand-off; the shebang table of F8 (`first_word_only` from `cfg.fix("D-031")`); `file(1)` missing note. Mutations: skip the RTF hand-off; route `#!/bin/bash -e` | WP-03, WP-04, WP-05 |
| WP-11 | `transit/pipeline.py`, `scan_pipeline.py`, `tests/engine/test_pipeline.py`, `test_entrypoint.py`, and **one hunk** of `scan_pipeline.sh` (section 15) | `main`, the 15 steps of section 6 in that order, `_Terminated` and the signal handlers, sidecar removal, the D-004 and diff WARNs | every module | `python3 tests/conformance/conformance.py check --engine python --case clean` prints `ok clean`; `check_schema.py` accepts the report; `TRANSIT_ENGINE=python bash scan_pipeline.sh` gives the same report; D-028 test; SIGTERM test; **the review rows of section 11 for `test_pipeline.py`**; `tests/run_tests.sh` still passes. Mutations: **construct the `Verdict` after the temporary area; leave the old sidecars; catch only `Exception`; return the status of a `SystemExit`; skip the D-004 WARN** | WP-01 to WP-10 (codes in parallel) |
| WP-12 | `tests/engine/test_lints.py`, `tests/conformance/family_diff.py`, `Dockerfile` (COPY line), `prepare_offline_install.sh` (file loop), `.github/workflows/ci.yml` (engine jobs), `docs/engine_divergences.md` (D-029 to D-037) | the lints of 3.2 **as amended (the `scanners/__init__.py` exemption)**, `family_diff.py` (runs both engines on a directory holding only the fixtures routed to given scanner ids and prints per-file status and rule-id differences), CI job `python3 -I -m unittest discover -s tests/engine` and `conformance.py check --engine python`, `scan_pipeline.py` in the image and the offline bundle (`selfcheck.py` needs no change: it globs `*.py` and `transit/**/*.py`) | the stubs | `test_lints.py` fails on each forbidden construct (mutation per lint) and **passes on the stubs as delivered** (checked by hand at the freeze), except the `-W error` lint, which needs open question 1 | none |
| WP-13 | `docs/engine_contract.md`, `tests/conformance/conformance.py` | the amendments of section 12.3, in one pull request; for `--engine python` only, a table of accepted divergences in the normaliser: the WARN `transitignore:exclusions_applied(` is dropped from `file_results.__global__` and `summary.warn` is lowered by one before the comparison with the bash golden `ignored` (D-004), and nothing else is dropped | the review log, sections 8.3 and 12 | `python3 tests/conformance/check_schema.py` still passes; `conformance.py check` for bash still prints `ok` for the 17 cases; with WP-11 merged `check --engine python --case ignored` prints `ok ignored`; mutation: also drop an unrelated WARN and the comparison must go red | none (the conformance change is tested after WP-11) |

Wave 1 exit criterion (the first vertical slice): all of the above merged (WP-13 may follow); `python3 -I -m unittest discover -s tests/engine` green; the clean fixture reproduces `golden/clean.json`; `Registry.unported()` lists exactly the 31 ids of Waves 2 and 3.

### 14.2 Wave 2: Phase 3 pattern scanners (7 packages, parallel with each other and with Wave 3)

They start the day this design is merged (they need only the stubs) and merge after WP-04 and WP-05. Each owns `transit/scanners/<module>.py` and `tests/engine/test_<module>.py` for its modules.
Shared acceptance for every one: (1) a rule-row test with a positive and a near-miss fixture per row, tokens built at run time; (2) `python3 tests/conformance/family_diff.py <ids>` reports no difference in per-file status
and rule ids against bash on `tests/fixtures/rules`; (3) the real-file corpus counts written in CLAUDE.md for the family are reproduced when the corpus exists (run by WP-V); (4) every message string occurs in `scan_pipeline.sh`;
(5) every pattern occurs in `patterns.json` and is registered at import (a `RuleSet` row or a `Matcher`; nothing compiled inside a function); (6) the registry reports the ids as ported; (7) **memory**: a 64 MB file of short lines, and one with a few 1 MB lines, scan with a peak resident size under four times the file (a derived view is built with C-speed `bytes` operations or in chunks of at most 4 MiB split at a line boundary, never by splitting the file into a list of lines; R-04).

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

Dependencies are acyclic (checked by the same script on the "Merges after" column). Critical path to the first vertical slice: {WP-03, WP-04} -> WP-05 -> {WP-06, WP-08, WP-09, WP-10} -> WP-11 (WP-02 and WP-07 are off it, WP-01 only gates WP-11). WP-12 and WP-13 are off the critical path.

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
   D-034 (`partial` when `file(1)` is missing and an unknown-extension file was met), D-035 (resource limits), D-036 (repository configuration must be a regular, non-symlink file of at most 1 MiB), and, added by the review, D-004 (the `.transitignore` WARN and the nothing-scanned FAIL), D-038 (no file skipped by name), D-039 (no flat-view cap), D-040 (stale sidecars removed), D-041 (unlistable directory is a FAIL, PATH_MAX-proof walk), D-042 (diff-mode entry rebuilding and its WARN), D-044 (`.transitignore` caps), D-045 (collision merge). Defaults are the safe direction in every case.
3. **Switches whose default copies a bash blind spot** and which the owner should decide: D-029 (`excl` rules go blind on a file with a NUL byte), D-031 (`#!/bin/bash -e` is not routed to the shell scanner), D-014 (the credential formats skip a file with a NUL), and D-003 (a `.transitignore` whose last line has no newline loses it).
   Recommendation for all: fix in Python and in bash. D-004 was on this list in the first draft and is not any more: the review made it unconditional (R-03).
4. **Per-file Semgrep for JavaScript (D-037)**: `prepare_offline_cache.sh` stages four rule sets but not `javascript`. Until the owner stages one (or decides the call is dropped), the wrapper reports `failed` and L5 is `partial`.
5. **Amending contract 5.2 with the `engine:` prefix** (section 8.3). Needed so that `findings.build_record` and `generate_excel_report.py` (which reads the `[FAIL]`/`[WARN]` tags only) treat it as a documented producer.
6. **The root `.manifest_sha256.txt` is now scanned (D-038).** `fetch_repo.sh` writes it, `ai_transit.sh` keeps it out of the ZIP, and bash skipped it. Scanning it adds one PASS event to every fetched-repository report and, for a repository with a path such as `lib/md5.c`, one WARN
   (`CWE-327:weak_crypto_algorithm` on the manifest). The alternative, skipping exactly the root file when it has the fetcher's shape, was considered and not taken: the engine cannot tell the fetcher's file from a repository's own file of that name without hashing the repository twice, and any shape test leaves the
   path part of a line free for a payload. Decision wanted: accept the noise (default), or let the fetcher write the manifest outside the scanned directory.
7. **`fetch_repo.sh` should write `.diff_files` with `git diff -z --name-only` (NUL-separated)** (D-042). The engine already reads both formats; until the producer changes, a changed file whose name holds `:` is rebuilt by joining and a non-ASCII name by unquoting, and what cannot be rebuilt is reported (WARN + `partial`). `fetch_repo.sh` is under the feature freeze, so this
   is a request to the lead, not a work package. Same for the bash engine reading the new format.
8. **Golden `ignored` and D-004.** The bash golden stays as it is; the Python engine's extra WARN is removed by an accepted-divergence table in the normaliser (WP-13) rather than by regenerating the golden, because bash cannot produce that WARN while the feature freeze lasts. When bash gets the same WARN (fix-in-both), the table entry is deleted and the golden is regenerated.

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
    fields: rule_budget_s: float; file_budget_s: float; file_budget_s_per_mb: float; long_line_bytes: int; max_file_bytes: int; tool_timeout_s: float; helper_timeout_s: float
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
constants: `COLOUR_INFO`, `COLOUR_WARN`, `COLOUR_OK`, `COLOUR_FAIL`, `COLOUR_RESET`, `BIDI_CONTROLS`
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
    def set_allowlist(self, allowlist: Allowlist) -> None
    @property def verdict(self) -> str
    @property def counters(self) -> Counters
    @property def events(self) -> int
    def status_of(self, file: str) -> 'str | None'
    def coverage_state(self, layer_id: str) -> 'str | None'
    def record_pass(self, file: 'str | None'=None) -> None
    def record_warn(self, file: 'str | None', message: str) -> None
    def record_warn_once(self, key: str, file: 'str | None', message: str) -> bool
    def record_fail(self, file: str, message: str, *, severity: 'str | None'=None, downgradable: bool=True) -> Outcome
    def record_layer(self, layer_id: str, state: str, *, overwrite: bool=True) -> None
    def note_incomplete(self, layer_id: str, reason: str) -> None
    def abort(self, reason: str) -> None
    def snapshot(self) -> Snapshot
```

### `transit/files.py`

The file system side of a run: which files are scanned, how one file is read, temporary files, and the content hashes.

```text
constants: `MAX_WALK_DEPTH`, `MAX_GLOB_PATTERNS`, `MAX_PATTERN_CHARS`, `GLOB_METACHARS`
class `FileReadError(Exception)` - A file that was listed could not be read.
    def __init__(self, reason: str) -> None
class `FileEntry()` (frozen dataclass) - One regular file chosen for the per-file layers.
    fields: path: str; rel: str; size: int
class `FileView()` - One file, read at most once.
    def __init__(self, scan_dir: str, rel: str, limits: Limits) -> None
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
    fields: active: bool; keys: frozenset[str]; stale_ignored: bool; unresolved: int
class `ScanList()` (frozen dataclass) - The files of the per-file layers, sorted by the bytes of rel, plus what could not be listed and what was excluded.
    fields: entries: tuple[FileEntry, ...]; errors: tuple[tuple[str, str], ...]; excluded_by_patterns: int
class `SourceHashes()` (frozen dataclass) - sha256: contract 4 source.sha256; repo_hash: contract 4 repo_hash.
    fields: sha256: str; repo_hash: str
def open_beneath(scan_dir: str, rel: str) -> int  - Open the regular file rel below scan_dir for reading and return the descriptor (the caller closes it).
def prepare_work_dirs(work_dir: str) -> None  - Create WORK_DIR/reports, WORK_DIR/quarantine (mode 0700) and WORK_DIR/approved with parents (mkdir -p; D-027: created although unused).
def read_repo_config_file(scan_dir: str, name: str, *, max_bytes: int=1 << 20) -> 'tuple[bytes | None, str | None]'  - Read scan_dir/name (.transit-allow.json or .transitignore; name has no separator, else ValueError) as repository configuration, S15 / D-036: it must be a REGULAR file that is NOT a symlink (lstat) and at most max_bytes.
def contained_path(scan_dir: str, path: str) -> 'str | None'  - For a wrapper that must map a path reported by a tool (absolute, or relative to scan_dir) to the RECORDED path.
def glob_match(pattern: str, text: str) -> bool  - fnmatch(3) without FNM_PATHNAME, as find -path applies it: * matches any string INCLUDING /; ? any one character; [...] a set with ! or ^ negation and ranges; \x the character x.
def load_exclusions(scan_dir: str, *, cfg: Config) -> 'tuple[Exclusions, tuple[str, ...]]'  - Read scan_dir/.transitignore through read_repo_config_file and return the exclusions plus the console notes.
def load_diff_selection(work_dir: str, since_commit: str, scan_dir: str) -> DiffSelection  - Parse WORK_DIR/.diff_files.
def files_for_scan(scan_dir: str, exclusions: Exclusions, diff: DiffSelection) -> ScanList  - Contract 8.5: regular files only (lstat; symlinks to files and to directories are neither listed nor followed), hidden files included, pruned by exclusions, restricted to diff.keys when diff.active.
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
class `Not()` (frozen dataclass) - Negation of one condition (bash ! grep_check ...).
    fields: member: 'Cond'
class `AppliesTo()` (frozen dataclass) - Restricts a rule to some files of the scanner that owns it.
    fields: basenames: 'tuple[str, ...] | None'; exts: 'tuple[str, ...] | None'
class `RuleSpec()` (frozen dataclass) - One row of a rule table = one record_fail / record_warn of the bash scanner.
    fields: id: str; outcome: str; message: str; cond: Cond; severity: 'str | None'; applies_to: 'AppliesTo | None'; source: str
class `RuleSet()` - An ordered, compiled table.
    def __init__(self, name: str, rules: Sequence[RuleSpec]) -> None
    @property def name(self) -> str
    @property def rules(self) -> tuple[RuleSpec, ...]
class `Matcher()` - A Match that is not a report row: the private-key header and body tests, the credential-format alternation, a helper pattern of a container scanner.
    def __init__(self, id: str, match: Match) -> None
    @property def id(self) -> str
    @property def match(self) -> Match
    def search(self, target: Target, policy: SearchPolicy) -> bool
    def spans(self, target: Target, policy: SearchPolicy) -> Iterator[tuple[int, int]]
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
    def spans(self, matcher: Matcher, *, data: 'bytes | None'=None) -> Iterator[tuple[int, int]]
    def target(self, data: 'bytes | None'=None) -> Target
    def check_deadline(self) -> None
    def file_tool(self, name: str) -> FileToolRun
    def apply_tool_records(self, run: FileToolRun) -> bool
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
def classify_file(view: FileView, run: RunScanner) -> None  - Contract 8.8 rules 2 to 5 for one file (the universal layer has already run).
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
def search_policy(cfg: Config) -> SearchPolicy  - The ONLY producer of a SearchPolicy: SearchPolicy(rule_budget_s=cfg.limits.rule_budget_s, long_line_bytes=cfg.limits.long_line_bytes, excl_nul_blind=not cfg.fix("D-029")).
def file_deadline(cfg: Config, size: int, *, now: float) -> float  - The time.monotonic() value after which the rules of ONE file may no longer start: now + limits.file_budget_s + limits.file_budget_s_per_mb * size / 2**20, size being FileEntry.size.
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
def html_escape(text: str) -> str  - S3 / D-017: & first, then <, >, ", ' (as &#39;); then every C0 control (TAB and LF included), DEL, every C1 control and every character of console.BIDI_CONTROLS (U+202A-U+202E, U+2066-U+2069, U+061C, U+200E, U+200F) i...
def render_html(report: dict, *, timestamp_local: str) -> str  - The HTML report (contract 3.4): title AI Transit Report - <timestamp_local>, <h1>Verdict: <V></h1>, the escaped directory, the three counters, a coverage table (new, allowed), and one row for EVERY file_results entry...
def write_atomic(path: str, data: bytes, *, mode: int=438) -> None  - S5.
def write_reports(report: dict, paths: ReportPaths, *, timestamp_local: str) -> None  - JSON first (json.dumps(..., ensure_ascii=False, indent=2) + LF, UTF-8, strict), then HTML, each through write_atomic.
def clear_sidecars(paths: ReportPaths) -> None  - D-040, pipeline step 5.
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
constants: `RULES`, `KEY_HEADER`, `KEY_WITH_BODY`, `PRIVATE_KEY_HEADER`, `PRIVATE_KEY_WITH_BODY`
def private_key_present(ctx: ScanContext, data: 'bytes | None'=None) -> bool  - CWE-321 test, in bash a pipeline: grep -E -A5 HEADER | tr '\r\n\t' ' ' | grep -E HEADER.{0,200}[A-Za-z0-9+/]{60,}.
def scan(ctx: ScanContext) -> bool  - Run steps 1 to 6 on ctx's file.
```

### `transit/scanners/credentials.py`

Known credential formats (bash _known_cred_check and the KNOWN_CRED_* tables).

```text
constants: `PROVIDER_NAMES`, `PROVIDER_PATTERNS`, `ALTERNATION`, `PROVIDER_MATCHERS`, `JWT`, `EXCLUSION`, `JWT_PATTERN`, `JWT_MESSAGE`
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
| F10 stubs | `python3.10`, `3.11`, `3.12`, `3.13` `-I -B` import of the 20 modules with stdout/stderr and warnings captured, `SIGALRM` compared; `ast.parse(feature_version=(3, 10))` and `compile()` with warnings as errors of the 22 files; AST import graph and layering lints. Run before the freeze, after all edits of the review | no output, no warning from a new file, no signal change; none of the seven helper programs imported; 41 import edges, acyclic, no lint violation |
| clean fixture | the 28 table patterns against the four fixture files, the key header and the 18 formats | 57 rule-by-file evaluations, no hit |
| ownership | `own_check.py` (B.2) over the work-package tables: on the pre-review text it reproduces 27 packages and 139 files; on the frozen text | **28 packages, 141 files, no file owned twice**; "Merges after" acyclic; every one of the 37 scanner ids maps to a module with an owner |
| Appendix A | the generator below run on the pre-review stubs (`git archive HEAD`) and compared with the pre-review Appendix A | byte-identical, so the regenerated Appendix A differs from the old one only where the stubs changed |

### B.1 Reproductions made for the review

Every defect of the review log was reproduced, or confirmed against the contract text, before it was accepted. Scratch repositories lived under the session scratchpad with a private `WORK_DIR` and `TMPDIR`; bash 5.2.21, GNU grep 3.11, Python 3.10 to 3.13, running as root.

| Defect | What was run | Result |
|--------|--------------|--------|
| R-01 | `scan_pipeline.sh` on a repository holding `os.system(input())` and a password literal as `sub/evil.py`, `.manifest_sha256.txt` and `sub/.manifest_sha256.txt`; then on a repository holding only `sub/.manifest_sha256.txt`; then `zip -r . -x ".manifest_sha256.txt"` | FAIL with `file_results` = `sub/evil.py` and `__global__` only; PASS for the second repository; the ZIP lists `sub/.manifest_sha256.txt` |
| R-02, R-17 | `rx.dfa_search` and `rx.search_lines(budget=0.25)` for the 11 universal table patterns over 10 MB with one 9 KB line | 4.16 s in total for the DFA (0.31 to 0.48 s per pattern, about 38 ns per byte per rule), 1.07 s for `re`; 17 rows reach 120 s at about 185 MB (computed from the measured rate; a 185 MB file was not run, the Python engine does not exist yet) |
| R-03 | `.transitignore` of `*` over a vulnerable file (E14, contract A4); the golden `ignored` fixture (`src/db.py` hidden) | PASS with only `__global__` in `file_results`; the golden is a PASS that hides an SQL-injection file |
| R-04, R-26 | `resource.getrusage` around `rx.lines_over` on `ab\n` repeated, and around a `bytes.find` loop | 28 MB: 576 MB against 40 MB; 85 MB: 1,705 MB; the loop adds nothing (but takes 1.2 s for 28 MB of 3-byte lines, which is why the design uses the aligned-block count instead) |
| R-05 | `json.loads('[' * 200000 + ']' * 200000)` on Python 3.10, 3.11, 3.12, 3.13; reading the draft's steps 4 to 8 and the D-028 paragraph | `RecursionError`, not a `ValueError`, on all four; the Verdict was constructed in step 8 while D-028 covered steps 5 to 13 |
| R-06 | `try: raise SystemExit(0) / except Exception` on the four interpreters | not caught |
| R-07 | bash with `SINCE_COMMIT` set and `.diff_files` = `<repo>/a:b.py:` (file holds the payload) and `<repo>/plain.py:`; `git diff --name-only` for `é.py` | PASS for `a:b.py`, FAIL for `plain.py`; git prints `"\303\251.py"` |
| R-08, R-20 | bash on an XML with `<!ENTITY x SYSTEM "file:///etc/passwd">` padded to 4,000,059 and to 5,300,055 bytes; `grep -n grep_flat` | FAIL, then PASS; `grep_flat` is used by `scan_xml` (3 rules) and `scan_powershell_xml` (1) |
| R-09 | a tree 102 directories deep (5,202 bytes) built with `os.mkdir(dir_fd=)`; `find`, an `os.scandir`-by-path walk, a walk by descriptors, `scan_pipeline.sh` | `find` lists a 5,217-byte path; the path walk fails at 4,135 bytes with ENAMETOOLONG; the descriptor walk lists it; bash PASS with the file absent from `file_results`. (EACCES cannot be produced as root; the WARN-versus-FAIL contradiction is read from the draft's rows, and the test uses a mocked `PermissionError`.) |
| R-10 | reading `scan_pipeline.sh` L3623-L3626 and contract 3.1 | the progress line prints `${short_f:0:80}` raw; the contract row says "not needed" |
| R-11, R-23 | `check_graph.py` with the draft's lint wording | `transit/scanners/__init__.py` imports `transit.console` and `transit.verdict`; with the amended wording the stubs pass |
| R-12 | bash on `x<0xFE>.py` (payload) and `x<0xFF>.py` (clean) | one `file_results` key |
| R-13, R-27 | `os.path.abspath('/tmp//repo/a.py')` against `scan_dir + "/" + rel` | `/tmp/repo/a.py` against `/tmp//repo/a.py` |
| R-15 | a naive iterative matcher over 170,000 six-character patterns (1 MiB, the allowed size) and the 5 suffixes of a 4-component path | 0.16 s per entry, 2.2 hours for 50,000 files; a set lookup of the same literals costs 0.3 microseconds |
| R-18 | `rx.after_context`, `rx.matching_lines(budget=0.25)` and `rx.dfa_search` on `-----BEGIN ` + `PRIVATE KEY ` * k + `x` | 46 KB: 0.20 / 0.19 / 0.002 s; 93 KB: 0.87 / 0.26 / 0.003 s; 281 KB: 6.70 / 0.31 / 0.010 s |
| R-21 | `git show 4b2746b:scan_pipeline.sh \| grep -n '! *grep'` | exactly one negation, L1443 in `scan_go` |
| R-28 | `own_check.py` on the pre-review text; `grep engine_contract.md` in the work-package tables | 27 packages and 139 files reproduced; no package owned `docs/engine_contract.md`; WP-06 merged "after WP-02, WP-05" while `layers` imports `files` |

### B.2 The scripts

Appendix A generator (run from the repository root; `python3 gen_appx.py .`; its output was compared with the pre-review Appendix A and was byte-identical on the pre-review stubs):

```python
"""Regenerate Appendix A of the design from the stubs. usage: gen_appx.py <repo root> -> markdown on stdout"""
import ast, sys, re, pathlib
root = pathlib.Path(sys.argv[1])
FILES = ["transit/config.py", "transit/console.py", "transit/cli.py", "transit/findings.py", "transit/verdict.py", "transit/files.py",
         "transit/rules/__init__.py", "transit/tools/__init__.py", "transit/scanners/__init__.py", "transit/dispatch.py",
         "transit/layers.py", "transit/report.py", "transit/pipeline.py", "transit/scanners/universal.py",
         "transit/scanners/credentials.py", "transit/scanners/python_lang.py", "transit/scanners/shell.py",
         "transit/scanners/doc.py", "transit/scanners/requirements.py", "transit/scanners/unknown.py"]
def summary(doc):
    para = " ".join((doc or "").strip().split("\n\n")[0].split()).replace("``", "")
    cut = para.find(". ")
    if cut >= 0 and cut <= 220: return para[: cut + 1]
    if para.endswith(".") and len(para) <= 220: return para
    return para if len(para) <= 220 else para[:217].rstrip() + "..."
def sig(fn):
    ret = " -> " + ast.unparse(fn.returns) if fn.returns else ""
    return "def %s(%s)%s" % (fn.name, ast.unparse(fn.args), ret)
def is_frozen(n):
    for d in n.decorator_list:
        if isinstance(d, ast.Call) and getattr(d.func, 'attr', '') == 'dataclass':
            return any(k.arg == 'frozen' and getattr(k.value, 'value', False) for k in d.keywords)
    return False
def is_dc(n):
    return any((isinstance(d, ast.Call) and getattr(d.func, 'attr', '') == 'dataclass') or getattr(d, 'attr', '') == 'dataclass' for d in n.decorator_list)
out = []
out.append("### `scan_pipeline.py`\n\nAI Transit Pipeline - Python engine entry point.\n\n```text\nscript: checks Python >= 3.10, puts its own directory first on sys.path, calls transit.pipeline.main(sys.argv[1:], os.environ)\n```\n")
for rel in FILES:
    tree = ast.parse((root / rel).read_text(encoding="utf-8"))
    out.append("### `%s`\n\n%s\n\n```text" % (rel, summary(ast.get_docstring(tree))))
    consts = []
    for n in tree.body:
        tgt = None
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name): tgt = n.targets[0].id
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name): tgt = n.target.id
        if tgt and re.match(r"^[A-Z][A-Z0-9_]*$", tgt): consts.append(tgt)
    if consts: out.append("constants: " + ", ".join("`%s`" % c for c in consts))
    ordered = [n for n in tree.body if isinstance(n, ast.ClassDef)] + [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    for n in ordered:
        if isinstance(n, ast.ClassDef):
            bases = ", ".join(map(ast.unparse, n.bases))
            tag = " (frozen dataclass)" if is_dc(n) and is_frozen(n) else (" (dataclass)" if is_dc(n) else "")
            out.append("class `%s(%s)`%s - %s" % (n.name, bases, tag, summary(ast.get_docstring(n))))
            fields = []
            for s in n.body:
                if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name) and not s.target.id.startswith('_'):
                    if is_dc(n): fields.append("%s: %s" % (s.target.id, ast.unparse(s.annotation)))
            if fields: out.append("    fields: " + "; ".join(fields))
            for s in n.body:
                if isinstance(s, ast.FunctionDef) and (not s.name.startswith("_") or s.name in ("__init__", "__len__")):
                    pre = ""
                    for d in s.decorator_list:
                        txt = ast.unparse(d)
                        if txt in ("property", "abc.abstractmethod"): pre = "@%s " % txt
                    out.append("    " + pre + sig(s))
        elif isinstance(n, ast.FunctionDef) and not n.name.startswith("_"):
            out.append(sig(n) + "  - " + summary(ast.get_docstring(n)))
    out.append("```\n")
sys.stdout.write("\n".join(out))
```

File-ownership check (`python3 own_check.py docs/python_engine_design.md`):

```python
"""Parse the work-package tables of the design and check that file ownership is disjoint. Usage: own_check.py <design.md>"""
import re, sys, collections
text = open(sys.argv[1], encoding='utf-8').read()
ROOT_NAMES = {'Dockerfile', 'prepare_offline_install.sh', 'scan_pipeline.py', 'scan_pipeline.sh'}

def section(start, end):
    i = text.index(start); j = text.index(end, i + 1)
    return text[i:j]

def tokens(cell):
    cell = re.sub(r'\([^)]*\)', '', cell)           # drop parenthesised notes
    return re.findall(r'`([^`]+)`', cell)

def expand(toks):
    cur = ''
    out = []
    for t in toks:
        if t in ROOT_NAMES:
            out.append(t); continue
        if '/' in t:
            cur = t.rsplit('/', 1)[0] + '/'
            out.append(t)
        else:
            out.append(cur + t)
    return out

owners = collections.defaultdict(list)
pkgs = {}
# Wave 1 and WP-13: rows start with | WP-nn |
for line in text.splitlines():
    m = re.match(r'\| (WP-\d\d) \| (.*?) \| ', line)
    if m:
        files = expand(tokens(m.group(2)))
        pkgs[m.group(1)] = files
# Wave 2
w2 = section('### 14.2', '### 14.3')
for line in w2.splitlines():
    m = re.match(r'\| (WP-2[A-G]) \| (.*?) \| ', line)
    if m:
        mods = [t for t in tokens(m.group(2))]
        files = []
        for mod in mods:
            files += ['transit/scanners/%s.py' % mod, 'tests/engine/test_%s.py' % mod]
        pkgs[m.group(1)] = files
# Wave 3
w3 = section('### 14.3', '### 14.4')
for line in w3.splitlines():
    m = re.match(r'\| (WP-3[A-G]) \| (.*?) \| ', line)
    if not m: continue
    cell = m.group(2)
    toks = tokens(cell)
    files = []
    for t in toks:
        if t.startswith('tools/'):
            files.append('transit/' + t)
            files.append('tests/engine/test_' + t.split('/')[1].replace('.py', '') + '.py')
        elif t.startswith('test_'):
            files.append('tests/engine/' + t)
        elif t.endswith('_wrapper.py'):
            files.append('transit/tools/' + t)
            files.append('tests/engine/test_' + t[:-3] + '.py')
        else:
            files.append('transit/scanners/' + t)
    pkgs[m.group(1)] = files
# Wave 4
w4 = section('### 14.4', '## 15.')
for line in w4.splitlines():
    m = re.match(r'\| (WP-V) \| (.*?) \| ', line)
    if m:
        pkgs['WP-V'] = expand(tokens(m.group(2)))
for p, fs in pkgs.items():
    for f in fs:
        owners[f].append(p)
dups = {f: o for f, o in owners.items() if len(set(o)) > 1}
print('packages:', len(pkgs), ' files:', len(owners), ' duplicates:', dups)
if '-v' in sys.argv:
    for p, fs in pkgs.items(): print(p, len(fs), fs)
```

Import check (`python3.N -I -B check_stubs.py <repo root>`; each of the 20 modules is imported with stdout, stderr and warnings captured and the `SIGALRM` handler compared):

```python
"""Import check of every stub, run under each interpreter: python -I -B check_stubs.py import <repo>"""
import ast, io, os, signal, sys, warnings, contextlib, importlib, pathlib

MODS = ["transit.config", "transit.console", "transit.cli", "transit.findings", "transit.verdict", "transit.files",
        "transit.dispatch", "transit.layers", "transit.report", "transit.pipeline", "transit.rules", "transit.tools",
        "transit.scanners", "transit.scanners.universal", "transit.scanners.credentials", "transit.scanners.python_lang",
        "transit.scanners.shell", "transit.scanners.doc", "transit.scanners.requirements", "transit.scanners.unknown"]
FILES = ["scan_pipeline.py", "tests/engine/__init__.py"] + [m.replace(".", "/") + (".py" if m not in ("transit.rules", "transit.tools", "transit.scanners") else "/__init__.py") for m in MODS]
HELPERS = ["transit.containers.office", "transit.containers.jar", "transit.containers.pdf", "transit.scanners.manifests",
           "transit.tools.gitleaks", "transit.tools.scancode", "transit.report_json"]

def do_import(repo):
    sys.path.insert(0, repo)
    os.chdir("/")
    before_alarm = signal.getsignal(signal.SIGALRM)
    out, err = io.StringIO(), io.StringIO()
    problems = []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            for m in MODS:
                try:
                    importlib.import_module(m)
                except BaseException as e:
                    problems.append("%s: %s %s" % (m, type(e).__name__, e))
    if signal.getsignal(signal.SIGALRM) != before_alarm: problems.append("SIGALRM handler changed")
    if out.getvalue() or err.getvalue(): problems.append("output at import: %r %r" % (out.getvalue()[:80], err.getvalue()[:80]))
    mine = [str(w.message)[:80] + " @" + os.path.basename(w.filename) for w in caught if "rx.py" not in w.filename]
    if mine: problems.append("warnings from new files: %s" % mine)
    for helper in HELPERS:
        assert helper not in sys.modules, "a helper PROGRAM was imported: " + helper
    return problems

if __name__ == "__main__":
    repo = sys.argv[1]
    probs = do_import(repo)
    print("python %d.%d: %d modules imported, problems: %s" % (sys.version_info[0], sys.version_info[1], len(MODS), probs or "none"))
    sys.exit(1 if probs else 0)
```

Syntax, import-graph and layering check (`python3.N -I -B check_graph.py`):

```python
"""AST checks of the stubs: python3.10 syntax, warnings-as-errors compile, import graph (acyclic), layering lints of design 3.2 as amended."""
import ast, sys, warnings, pathlib, collections
ROOT = pathlib.Path('/home/user/Claude')
NEW = ["scan_pipeline.py", "tests/engine/__init__.py", "transit/config.py", "transit/console.py", "transit/cli.py", "transit/findings.py",
       "transit/verdict.py", "transit/files.py", "transit/dispatch.py", "transit/layers.py", "transit/report.py", "transit/pipeline.py",
       "transit/rules/__init__.py", "transit/tools/__init__.py", "transit/scanners/__init__.py", "transit/scanners/universal.py",
       "transit/scanners/credentials.py", "transit/scanners/python_lang.py", "transit/scanners/shell.py", "transit/scanners/doc.py",
       "transit/scanners/requirements.py", "transit/scanners/unknown.py"]
def modname(rel):
    p = rel[:-3].replace('/', '.')
    return p[:-9] if p.endswith('.__init__') else p
errors = []
graph = collections.defaultdict(set)
for rel in NEW:
    src = (ROOT / rel).read_text(encoding='utf-8')
    ast.parse(src, rel, feature_version=(3, 10))
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        compile(src, rel, 'exec')
    tree = ast.parse(src)
    me = modname(rel)
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.startswith('transit'): graph[me].add(a.name)
        elif isinstance(n, ast.ImportFrom) and n.module and n.module.startswith('transit') and n.level == 0:
            graph[me].add(n.module)
            for a in n.names:   # "from transit import rx" style
                full = n.module + '.' + a.name
                if (ROOT / (full.replace('.', '/') + '.py')).exists(): graph[me].add(full)
    # lints
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or '']
            if any(x == 're' or x.startswith('re.') for x in names): errors.append(f'{rel}: import re')
            if any(x.split('.')[0] == 'subprocess' for x in names) and rel != 'transit/tools/__init__.py': errors.append(f'{rel}: subprocess')
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ('print', 'eval', 'exec'):
            if not (n.func.id == 'print' and rel in ('transit/console.py', 'scan_pipeline.py')): errors.append(f'{rel}: {n.func.id}(')
# layering rules (3.2 as amended)
for rel in NEW:
    me = modname(rel)
    deps = graph[me]
    if (me.startswith('transit.scanners') or me.startswith('transit.rules')) and me != 'transit.scanners':
        bad = deps & {'transit.verdict', 'transit.console'}
        if bad: errors.append(f'{rel}: imports {sorted(bad)} (only transit/scanners/__init__.py may)')
    if me.startswith('transit.scanners') or me.startswith('transit.rules'):
        bad = {d for d in deps if d in ('transit.layers', 'transit.pipeline', 'transit.report')}
        if bad: errors.append(f'{rel}: imports {sorted(bad)}')
    for d in deps:
        if d in ('transit.layers',) and me not in ('transit.pipeline', ): errors.append(f'{rel}: imports {d}')
        if d == 'transit.pipeline' and me != 'scan_pipeline': errors.append(f'{rel}: imports {d}')
# parent packages are imported implicitly: model "import a.b.c" as depending on a.b.c only; cycle detection on explicit edges
def cycle():
    color = {}
    def dfs(u, path):
        color[u] = 1
        for v in graph.get(u, ()):
            if color.get(v) == 1: return path + [u, v]
            if color.get(v) is None:
                r = dfs(v, path + [u])
                if r: return r
        color[u] = 2
    for u in list(graph):
        if color.get(u) is None:
            r = dfs(u, [])
            if r: return r
c = cycle()
if c: errors.append('import cycle: ' + ' -> '.join(c))
print('files checked:', len(NEW), '| errors:', errors or 'none')
print('edges:', sum(len(v) for v in graph.values()))
for k in sorted(graph): print(' ', k, '->', sorted(graph[k]))
sys.exit(1 if errors else 0)
```


## Review log

Interfaces frozen 2026-11-12. Two independent reviewers attacked the first draft and reported 28 defects (R-01 to R-28, numbered in the order they were delivered: R-01 to R-16 from the first reviewer, R-17 to R-28 from the second): 4 blockers, 13 majors, 11 minors. Six are duplicates of an earlier entry (R-17 of R-02, R-19 of R-01, R-20 of R-08, R-23 of R-11, R-26 of R-04, R-27 of R-13), so there are 22 distinct problems. Each was reproduced or checked against the contract before it was accepted (Appendix B.1). **All 28 are accepted**; four proposals inside them were deliberately not taken and are named in the "what changed" column. Nothing was rejected outright, because every claim reproduced.

**Rule from now on:** a change to a stub, a constant, a message string, a step of section 6 or the ownership of section 14 needs a new row here first (id `R-29` onward, severity, evidence, what changes), and the same pull request changes the stub, this document and the tests. A row is never deleted; a later row may supersede it.

| Id | From | Severity | Verdict | Evidence | What changed |
|----|------|----------|---------|----------|--------------|
| R-01 | 1st | blocker | accepted | bash: a payload in `.manifest_sha256.txt` at the root and in `sub/` is never in `file_results`; a repository whose only payload is the nested file is PASS; `zip -x ".manifest_sha256.txt"` still ships `sub/.manifest_sha256.txt` (F15) | `files.MANIFEST_SKIP_NAME` removed; `files_for_scan` skips nothing by name (D-038); rows in 1.4, 12.2, 13; tests and a WP-03 mutation; open question 6. **Not taken:** "skip the root file when it is the one the fetcher wrote": the engine cannot tell without hashing the repository twice, and any shape test leaves the path part of a line free for a payload. The cost is one extra PASS event, and a WARN when a file name matches a WARN rule (`md5.c`) |
| R-02 | 1st | blocker | accepted | F11: 38 ns per byte per rule; 11 table patterns over 10 MB took 4.16 s, so the 17 universal rows reach a fixed 120 s at about 185 MB, inside the universal layer; the draft recorded only a WARN and the verdict stayed PASS | expiry is a non-downgradable FAIL `engine:scan_incomplete:<id>:time_budget` (1.4, 7.5, 8.3, 9.3, `invoke`, `run_rules`); the budget is `120 s + 10 s per MiB` (`Limits.file_budget_s_per_mb`, `layers.file_deadline`, env `TRANSIT_FILE_BUDGET_S_PER_MB`); `Limits.max_file_bytes` 1 GiB to 512 MiB; D-035 rewritten. **Not taken:** "evaluate the family scanner's FAIL rules before the universal WARN rules": the order is bash's and is visible in the report, and the scaled budget makes it unnecessary |
| R-03 | 1st | blocker | accepted, with a different golden strategy | contract S15 says the Python engine reports exclusions (D-004); the draft copied bash by default (a switch), contradicting it and its own reasoning for D-019; `ignored` golden is a PASS that hides `src/db.py` | D-004 is unconditional and not in `KNOWN_FIXES`: WARN `transitignore:exclusions_applied(<n> pattern(s))` on `__global__` (step 8); FAIL `engine:nothing_scanned:transitignore` when the patterns removed every file (not in diff mode; `ScanList.excluded_by_patterns`, `layers.run_file_layers`). **Not taken:** regenerating `golden/ignored.json`: bash cannot produce the WARN under the feature freeze, so its own `check` would go red; WP-13 adds an accepted-divergence table to the normaliser for `--engine python` instead (open question 8) |
| R-04 | 1st | major | accepted | F12: `rx.lines_over` peaked at 576 MB for 28 MB and 1,705 MB for 85 MB | `FileView.has_long_line` is an aligned-block `bytes.count` test with O(1) memory (algorithm in its docstring); `rx.lines_over` and `rx.after_context` are linted out of `files`, `rules`, `universal`, `credentials`; RSS test of 90 MB of two-byte lines; Wave 2/3 memory acceptance (14.2 item 7); 9.2 and 9.4 |
| R-05 | 1st | major | accepted (all four parts) | (a) draft step 8 built the Verdict while D-028 covered steps 5 to 13; (b) nothing removed the sidecars; (c) `json.loads` of a 400 KB `[[[[` raises `RecursionError`, not a `ValueError`, on 3.10 to 3.13 (F16); (d) draft step 4 said "print FAIL", contradicting contract 3.2 | section 6 renumbered to 15 steps: the Verdict exists from step 5 (`Verdict.set_allowlist`), sidecars removed in step 5 (`report.clear_sidecars`, D-040), `parse_allowlist` and `read_repo_config_file` never raise (`except Exception`), step 4 is `Console.error` plus exit 1 with no verdict line; tests for each |
| R-06 | 1st | major | accepted, and extended | `SystemExit` is not caught by `except Exception` (F16); the draft turned signals into `SystemExit(128+n)` and converted any `SystemExit` to the exit status | the handler raises the private `_Terminated(BaseException)`; `main` returns 128+n only for it, treats every other `BaseException` as an internal error (FAIL, exit 1), and returns 0 only after `PASS` was written; **beyond the proposal**, `invoke` and `guard` also catch `SystemExit`, so a scanner or a helper import that exits costs one file a FAIL instead of ending the run (7.5) |
| R-07 | 1st | major | accepted in part | bash with `.diff_files` = `<repo>/a:b.py:`: PASS (`plain.py`: FAIL); git quotes `é.py` as `"\303\251.py"` (F16) | `load_diff_selection` reads a NUL-separated format and rebuilds the legacy list by joining up to 16 pieces and C-unquoting; `DiffSelection.unresolved` becomes the WARN `engine:diff_entries_unresolved(<n>)` plus `partial` on L4 and L5 (D-042); open question 7 asks the lead to change the producer. **Not taken:** falling back to a full scan: diff mode exists to be fast, the WARN and the coverage note make the gap visible |
| R-08 | 1st | major | accepted | F15: XML with an external entity FAIL at 4,000,059 bytes, PASS at 5,300,055; `grep_flat` is used by `scan_xml` (3 rules) and `scan_powershell_xml` | `FileView.flat()` and the flat branch of `evaluate` have no cap (D-039); the linear matcher is fast enough and the budget scales with the file; no "not evaluated" result type was needed, so `RuleRun` is unchanged |
| R-09 | 1st | major | accepted (both parts) | F14: `find` lists a 5,217-byte path, a path walk fails at 4,135 bytes, bash PASS; the draft's rows 58 and 59 made a directory a WARN and a file a FAIL | `files_for_scan` walks and `FileView` opens through directory descriptors (`files.open_beneath`, `O_NOFOLLOW`; `MAX_WALK_DEPTH` 512); `ScanList.errors` is `(rel, reason)` and `layers.run_file_layers` records the FAIL `engine:directory_unreadable:<reason>` (first 200, then a summary); `compute_hashes` reads such files; D-041; `engine:unreadable_directories` removed |
| R-10 | 1st | major | accepted | `scan_pipeline.sh` L3623 to L3626 prints `${short_f:0:80}` raw to the terminal; contract 3.1 says "not needed" | `Console.progress` docstring and the S1 test (drawn with `err_is_tty=True`); sanitise first, cut after; contract 3.1 amended (12.3); WP-01 mutation |
| R-11 | 1st | major | accepted | `check_graph.py` with the draft wording: `transit/scanners/__init__.py` imports `console` and `verdict` | the lint exempts exactly `transit/scanners/__init__.py` (3.2, `verdict.py` docstring, `scanners/__init__` docstring, WP-12); the amended lint passes on the stubs as delivered |
| R-12 | 1st | minor | accepted | bash: `x<0xFE>.py` and `x<0xFF>.py` give one `file_results` key | `build_report` merges colliding entries: worst status, concatenated messages (D-045); test with the checker's invariants |
| R-13 | 1st | minor | accepted | `abspath('/tmp//repo/a.py')` is `/tmp/repo/a.py`, the recorded key is `/tmp//repo/a.py` | `contained_path` decides containment on normalised strings and returns `join_scan_path(scan_dir, rel)` with the original `scan_dir`; tests for `//`, relative and `..` scan directories |
| R-14 | 1st | minor | accepted, and extended | `html_escape` handled only controls | `console.BIDI_CONTROLS` (the S1 ranges plus U+061C, U+200E, U+200F) is used by `sanitise` and by `html_escape` (character references) |
| R-15 | 1st | minor | accepted | a naive matcher with 170,000 six-character patterns: 0.16 s per entry, 2.2 hours for 50,000 files; a set lookup 0.3 microseconds | `Exclusions` keeps literals in a set and tries globs on the useful suffixes; `MAX_GLOB_PATTERNS` 64 and `MAX_PATTERN_CHARS` 256, a file over either is refused as a whole (it can only make the scan examine more); D-044; the worst case at the cap is about 20 s per 50,000 entries |
| R-16 | 1st | minor | accepted | contract S12 says "MUST enforce a per-line cap"; the draft says "no per-line cap exists anywhere" and filed nothing | D-043 and the S12 rewording in 12.3; WP-13 makes it; 9.2 states the reason (a cap hides a padded payload) |
| R-17 | 2nd | blocker | accepted, duplicate of R-02 | same measurement | see R-02; also: routing only the over-long lines to the linear matcher is allowed as an internal optimisation, if equal to the whole-buffer answer (9.2) |
| R-18 | 2nd | major | accepted | F13: `rx.after_context` is unbudgeted and quadratic (281 KB: 6.70 s) | `private_key_present` walks `ctx.spans(KEY_HEADER)` and builds the five-line windows itself (docstring states the one difference from bash); `rules.Matcher` registers code patterns; `credentials` uses `Matcher`s; the hostile-line test covers every registered pattern |
| R-19 | 2nd | major | accepted, duplicate of R-01 | same | see R-01 |
| R-20 | 2nd | major | accepted, duplicate of R-08 | same | see R-08; the interface needs no "not evaluated" result because the cap is gone |
| R-21 | 2nd | major | accepted | the reference script has exactly one negation, `scan_go` L1443 (`git show 4b2746b:scan_pipeline.sh`) | `rules.Not`; `evaluate` raises `ValueError` for a `Match` that no `RuleSet` or `Matcher` registered, so `ctx.search` cannot hide a pattern from `rx.registered()`; rule (8) of 7.1 |
| R-22 | 2nd | major | accepted | `ScanContext` is built per file; nothing held the "once per run" state | `Verdict.record_warn_once(key, file, message)`; `file_tool` uses it; the test moved to `test_scanners.py` / `test_verdict.py` (the owner of the code) |
| R-23 | 2nd | minor | accepted, duplicate of R-11 | same | see R-11 |
| R-24 | 2nd | minor | accepted | the 7.1 example dropped the `warn` record of a `failed` run | `ScanContext.apply_tool_records(run)`; the example and the `python`/`shell` docstrings use it; rule (9) of 7.1 |
| R-25 | 2nd | minor | accepted (all three) | no producer of `SearchPolicy`; D-029 had two control points; `fix_d031` had no caller | `layers.search_policy(cfg)` is the only producer; an `excl` row says `binary="text"` and the policy decides (`BINARY_MODES` is `("text", "skip")`); `classify_file` lost its `fix_d031` parameter |
| R-26 | 2nd | minor | accepted, duplicate of R-04 | same | see R-04 |
| R-27 | 2nd | minor | accepted, duplicate of R-13 | same | see R-13 |
| R-28 | 2nd | minor | accepted (all three) | the tables: no package owned `docs/engine_contract.md`; `own_check.py` | WP-13 (the contract amendments of 12.3 and the normaliser entry); S12 is D-043; "Merges after" now includes WP-03 for WP-05, WP-06, WP-08 to WP-10; counts recomputed (28 packages, 141 files) |

### Checks after the last edit

| Check | Result |
|-------|--------|
| the 20 stub modules import with no output, no warning from a new file, no `SIGALRM` change, no helper program imported (`check_stubs.py`) | Python 3.10, 3.11, 3.12 and 3.13: no problem |
| the 22 files parse with `feature_version=(3, 10)` and compile with warnings as errors; import graph acyclic; layering lints of 3.2 as amended (`check_graph.py`) | no error; 41 import edges |
| work packages own disjoint files (`own_check.py`) | 28 packages, 141 files, no file owned twice |
| Appendix A regenerated from the stubs (`gen_appx.py`, validated byte for byte against the pre-review appendix) | done |
| files changed outside the stubs and this document | none: `scan_pipeline.sh`, `ai_transit.sh`, `fetch_repo.sh`, `tests/run_tests.sh`, `transit/rx.py` and every other existing file are untouched; nothing was committed |
