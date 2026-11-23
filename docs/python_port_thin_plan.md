# Python port, thin variant: the shell's behaviour, in Python, calling the same tools

**Status: P0 to P3 done on 2026-11-14 (owner said go the same day).** The earlier "swap the matching backend" proposal is
replaced by this one. Result: `scan_pipeline.py` and `transit/{core,scan_lang,scan_build,scan_docs,layers}.py`, 3,215 lines;
all 26 golden reports match; the whole shell suite passes against the Python engine except two Layer H launcher checks.
P4 (documents, counts, cut-over decision) is in progress; the default engine stays bash until the owner decides.

## 1. The expectation this plan returns to

Run the pipeline either as `scan_pipeline.sh` or in Python, with **the same behaviour**, and write **as little Python as
possible** by calling the same external tools the shell calls.

The modular engine built so far (`transit/` modules, `tests/engine`, 10 of 13 first-wave packages) went the other way:
it matches patterns inside Python and re-implements the tools' behaviour. It is parked by this plan (section 6).

## 2. What "the same as the shell" means here

`scan_pipeline.py` is the shell script in Python: the same functions in the same order and with the same names, the
same messages byte for byte, the same state kept in the same variables. Where the shell runs a program, Python runs the
same program with an argument list and never a shell.

| The shell does | The Python does |
|---|---|
| `grep -qE -e PATTERN FILE` (`grep_check`, `grep_check_i`, `grep_check_excl`, `grep_flat`) | the same grep command, through one helper per shell helper |
| `find` with prune expressions for the file list | the same find command |
| `sha256sum` for the manifest and the hashes | the same command |
| gitleaks, detect-secrets, ClamAV, YARA, Semgrep, trivy, ScanCode, Bandit, ShellCheck, cppcheck, hadolint, checkov, `file`, `strings`, `unzip` | the same programs, the same arguments and the same offline flags |
| `python3 helper.py` (Office, jar, PDF, manifests, report writer, ScanCode and gitleaks readers) | the same helper programs in `transit/`, unchanged |
| `tr`, `sed`, `awk`, `sort`, `head`, `cut`, `basename`, `date`, `mktemp`, bash variables and arrays | Python builtins. This is shell glue, not a tool, and calling `tr` from Python would add nothing. |

The last row is the one judgement call; section 9 asks the owner to confirm it.

## 3. Size, measured

`scan_pipeline.sh` is 4,306 lines, of which 1,286 are comments and 345 blank: **2,676 lines of code**, in 65 functions.
Of those, 1,859 lines are the `scan_*` functions, 200 are the record, finding and report helpers, and the rest is
flow. A line-for-line port is therefore about **3,000 lines of Python** (my estimate), in one file. For comparison, the
modular engine is 7,447 lines of code today with 21,369 lines of tests, and is not finished.

Most scanner functions are a run of `if grep_check '...' "$f"; then record_fail ...; fi`. In Python each becomes a
table of (pattern, message, severity) rows and one loop, so the port is shorter than the shell where the shell
repeats itself.

## 4. What stays

| Stays | Why |
|---|---|
| `scan_pipeline.sh` | It is the reference and stays the default. The only edit is the `TRANSIT_ENGINE=bash\|python` switch (one hunk). |
| `transit/containers/`, `transit/tools/gitleaks.py`, `transit/tools/scancode.py`, `transit/report_json.py`, `transit/scanners/manifests.py` | The helper programs the shell already runs. |
| `tests/conformance/` (harness, `family_diff.py`, `check_schema.py`), the 26 golden reports, `docs/engine_contract.md`, `docs/report.schema.json`, `docs/engine_divergences.md` | They define "the same behaviour" and prove it. They already exist. |
| `ai_transit.sh`, `fetch_repo.sh`, `tests/run_tests.sh` | Untouched. The suite runs once per engine. |

## 5. Phases

| # | Phase | Work | Estimate | Exit criteria |
|---|---|---|---|---|
| P0 | Park | Stop the modular engine work; remove it from the working branch in one commit (section 6). | hours | Branch builds; suite green |
| P1 | Skeleton | `scan_pipeline.py` with the arguments, environment, console sanitiser, `record_*`, allowlist, finding records, JSON and HTML report, sidecars and the main flow, plus the universal rules and the scanners the `clean` fixture needs | 2 to 3 days | `conformance.py check --engine python --case clean` prints `ok clean` |
| P2 | Scanners | The 38 `scan_*` functions in four groups (languages; build and config files; documents and archives through the helper programs; unknown and binary), each checked with `family_diff.py` against bash on `tests/fixtures/rules` | 4 to 6 days | Per-file status and rule ids equal to bash for every family |
| P3 | Tool layers | Layers 1 to 3 and 6: the same tool calls, the offline flags and staged data, the coverage block and every state string the hardened shell records | 2 to 3 days | The stub-tool golden cases equal |
| P4 | Verify and cut over | All 26 golden cases; `tests/run_tests.sh` with `TRANSIT_ENGINE=python`; the real-file corpora of CLAUDE.md; documented counts, PDFs and Word documents; the default stays bash until everything is equal | 2 to 3 days | Zero unexplained differences |

About **10 to 15 days** in total, my estimate, against 44 to 67 in the earlier plan. The calendar time under usage limits
will be longer. The method is deliberately light: one file, the harness that already exists, no design document, no frozen
interfaces, no mutation programme.

## 6. What happens to the modular engine

The state at commit `796d5a9` is kept in git history. On approval one commit removes from the working branch:
`transit/{cli,config,console,dispatch,files,findings,layers,pipeline,report,rx,verdict}.py`, `transit/rules/`,
`transit/scanners/` except `manifests.py`, `transit/tools/__init__.py`, `tests/engine/`, `tests/conformance/test_rx.py`,
`pattern_fuzz.py` and `pattern_inventory.py`, the engine jobs of `.github/workflows/ci.yml`, and
`docs/python_engine_design.md`. Pieces that turn out to be exact and expensive to redo (the severity classifier, the
finding record builder, the allowlist parser, the report builder) can be copied into `scan_pipeline.py` from that
commit rather than rewritten.

## 7. What is given up

The in-process matching speed (about 700 times faster per pattern test; a scan runs the same grep processes as the
shell instead), unit tests per module, the frozen module interfaces, and independence from GNU grep and find. None of
these was part of the expectation.

## 8. Risks

| Risk | Answer |
|---|---|
| The port copies the shell's bugs | The shell is hardened, and the golden reports and the contract are the definition |
| Shell semantics that Python does not share (`set -e`, `\|\| true`, pipe statuses, associative array order) | The contract lists them; each is ported on purpose and covered by a golden case |
| A line-for-line port drifts while rules change | Rule changes land in both engines until the cut-over; the harness fails if they differ |
| A mistake in a translated pattern or message | `family_diff.py` compares per-file status, messages and rule ids with bash on the whole rule corpus |
| Speed | The same as the shell, measured: 1.36 ms per grep call from Python against 1.39 ms from the shell |

## 9. What the owner confirms

1. **Go**, and the removal of the modular engine in P0 (default: yes, recoverable from `796d5a9`).
2. **The glue line** in section 2: `tr`, `sed`, `awk`, `sort` and similar become Python builtins; `grep`, `find`,
   `sha256sum` and every scanner stay external programs.
