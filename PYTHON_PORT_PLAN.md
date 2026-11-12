# Plan: a Python engine for `scan_pipeline.sh`

Goal: the same pipeline, launchable as `scan_pipeline.sh …` **or** `python3 scan_pipeline.py …`, with the
same arguments, environment variables, output files, verdict and exit status. Date of this plan:
2026-11-12. Nothing in it has been implemented yet.

## 1. What "launch either way" should mean

There are three readings; the plan recommends the third.

| | Reading | Cost | Verdict |
|---|---|---|---|
| A | A thin `scan_pipeline.py` that runs `bash scan_pipeline.sh` | A day | Not an equivalent: it is still the bash engine |
| B | Two independent engines, bash and Python, both maintained | Every rule written and fixed twice, forever | Drifts; avoid |
| **C** | **One Python engine. `scan_pipeline.sh` stays as a launcher with the same interface. The bash engine is kept only as the reference oracle during migration, then retired** | Port once, prove equivalence, cut over | **Recommended** |

Why C is safe: `scan_pipeline.sh` already cannot run without `python3`. Seven embedded Python blocks (the
office, jar, PDF and manifest helpers, the report generator, the ScanCode result parser and the gitleaks report reader) and `has_cmd python3`
checks make it a hard dependency today, so a Python engine adds no new requirement. INSTALL.md already says
Python 3.10+.

## 2. Where we start (measured on the current tree)

| Fact | Value |
|---|---|
| `scan_pipeline.sh` | 6,698 lines, 59 functions |
| Already Python, embedded in heredocs | **2,837 lines (42%)** in seven blocks: `_office_facts` 1,763, `_jar_facts` 515, `_pdf_searchable` 332, `_pkg_facts` 93, report JSON 93, ScanCode parser 32, gitleaks reader 9 |
| Pattern rules | about 230 `grep_check` / `grep_check_i` / `grep_check_excl` / `grep_flat` call sites; each one forks `grep` |
| Regex dialect in those rules | POSIX ERE with GNU extensions: about 87 lines use `[[:class:]]`, 58 use `\s`, 31 use `\b` |
| Dispatch | `classify_file()` routes 109 extensions and 7 basename patterns to 34 scanner families |
| External tools called | gitleaks, detect-secrets, clamscan, yara, semgrep, trivy, pip-audit, safety, npm audit, scancode, bandit, shellcheck, cppcheck, hadolint, checkov, plus `file`, `strings`, `unzip` |
| Speed today | the 362-file rule corpus takes 49.5 s, about 0.14 s per file, dominated by process forks |
| Callers | `ai_transit.sh` (reads sidecars `.scan_verdict`, `.scan_report_json`, `.diff_files`), `Dockerfile` COPY list, `prepare_offline_install.sh`, CI lint file lists, the test suite |
| Tests | 740 assertions; 23 `run_pipeline` calls drive `ai_transit.sh`; 8 assertions read the shell source (lint) |

The 42% already in Python is the main reason this port is cheaper than it looks: those blocks move into real
modules almost verbatim.

## 3. The contract both engines must honour

Equivalence is defined against this list, written down in Phase 0 as `docs/engine_contract.md` plus a JSON
Schema and checked by tests.

1. **CLI.** `scan_pipeline.{sh,py} <dir> [report_dir] [scanning_name]`; words starting `--` are ignored; the
   scanning-name rules (no `/`, no control characters, no leading dot, at most 150 characters).
2. **Environment.** `WORK_DIR`, `VERBOSITY`, `MIN_SEVERITY`, `SINCE_COMMIT`, `OFFLINE` (forced true),
   `OFFLINE_CACHE`, `SEMGREP_RULES_DIR`, `TRIVY_CACHE_DIR`, `CLAMAV_DB_DIR`, `RUN_SCA`, `RUN_SCANCODE`, `REPO_INPUT`,
   the `JAR_*` and `OFFICE_*` limits, `TMPDIR`.
3. **Outputs.** The last stdout line is `PASS` or `FAIL`; exit 0 only for PASS; sidecars `.scan_verdict` and
   `.scan_report_json`; `report_scan_<name>.json/.html` or `reports/report_<timestamp>.json/.html`; the JSON
   keys (`verdict`, `decision`, `coverage*`, `source`, `findings` as a list of records, `findings_by_file`,
   `file_results`, `summary`, `standards`, …).
4. **Verdicts.** Same PASS/WARN/FAIL per file, same rule identifiers and message text (the tests assert on
   strings such as `CWE-89:SQL_injection…`), same coverage block, same allowlist and `--min-severity` behaviour.
5. **Security properties.** Every property in CLAUDE.md "Reports and console output must not trust the
   repository" holds in Python: sanitised console, escaped HTML, byte-safe JSON, no repository text reaching a
   shell, gitleaks run on the pipeline's terms.

Allowed differences, each recorded in a **divergence register** with a decision: ordering of findings (Python
will sort; bash hash order was arbitrary), timing, tool stderr text, and any bash bug the port deliberately
does not copy.

## 4. Target design

```
scan_pipeline.py            entry point (also: python3 -m transit)
scan_pipeline.sh            launcher: exec python3 scan_pipeline.py "$@"   (engine switch: TRANSIT_ENGINE=bash|python)
transit/
  cli.py  config.py         arguments, environment, offline/layer switches
  console.py                sanitised info/warn/ok/fail (the _san rule)
  verdict.py  findings.py   record_pass/warn/fail, allowlist, severity classification, structured records
  files.py  dispatch.py     walk + prune + .transitignore + diff mode; classify_file()
  rx.py                     ERE -> Python translator and the only place a rule regex is compiled
  rules/                    declarative rule tables (id, pattern, mode, severity, applies-to)
  scanners/                 python, javascript, shell, java, go, php, ruby, c_cpp, rust, kotlin, csharp, sql, yaml,
                            terraform, docker, makefile, cmake, html, xml, bat, powershell, setup_py, gradle,
                            manifests, universal (L4), credentials, unknown
  containers/               pdf, jar, office (the existing helpers), binary, archive
  tools/                    one wrapper per external tool: argv list, timeout, offline flags, output parser
  layers.py                 L1..L6 orchestration and the coverage block
  report.py                 JSON, HTML, sidecars
  pipeline.py               main
```

Standard library only, Python 3.10+. Optional single-file deployment with `python -m zipapp` (a
`scan_pipeline.pyz` for Jenkins agents).

Bash function to module, in short: `_office_facts`/`_rtf_head`/`_flat_office_head` to `containers/office.py`;
`_jar_facts` to `containers/jar.py`; `_pdf_searchable` to `containers/pdf.py`; `_pkg_facts` to
`scanners/manifests.py`; `scan_universal_patterns`/`_known_cred_check` to `scanners/universal.py` and
`credentials.py`; each `scan_<lang>` to its module; `_ps_rules` to `scanners/powershell.py`;
`scan_global`/`_scan_gitleaks`/`scan_owasp_cwe`/`scan_dependencies`/`scan_scancode` to `tools/` and `layers.py`;
`record_*`/`_classify_severity`/`_emit_finding` to `verdict.py` and `findings.py`; `generate_report_*`/`_html_esc`
to `report.py`; `classify_file`/`scan_by_type` to `dispatch.py`/`files.py`.

## 5. The hard parts, and how the plan deals with each

**5.1 Regex dialect.** `grep -E` is POSIX ERE, per line. Python `re` differs: no `[[:class:]]`, `[^x]` also
matches a newline, `.` rules, and matching is leftmost-first. For a yes/no question ("does the pattern match
anywhere") the two agree whenever the pattern is a plain regular expression, so the work is syntax and line
semantics, not theory. Plan: write `rx.py` with an ERE-to-`re` translator (POSIX classes mapped, `\s \w \b`
kept, matching done per line so a `[^"]` cannot cross a line, `grep_flat` modelled as an explicit mode with the
same 5 MB cap), then **prove it by differential fuzzing against real `grep -E` on all ~230 patterns** before any
scanner is ported. Patterns that cannot be translated cleanly are rewritten in *both* engines first.

**5.2 Catastrophic backtracking (the main new risk).** `grep` is automaton-based and linear; Python's `re`
backtracks, so a pattern that is harmless in bash can hang on a hostile file. The project has been hit by this
class before (`_jar_facts` and `_office_facts`: a 3 KB file ran 98 s). Controls: every rule runs through
`rx.py`, which enforces a per-line length cap (reported, never silent), a per-file time budget with the same
`SIGALRM` backstop the helpers already use, and a registry that lets CI fuzz **every** compiled pattern with
pathological inputs (the Layer F ReDoS lint grows from two helpers to the whole engine). A pattern that fails the
fuzz gate does not merge.

**5.3 Bytes, encoding, locale.** `grep` behaviour depends on the locale (invalid UTF-8 can make a file "binary").
The engine reads bytes, decodes with `surrogateescape`, treats a file as binary by an explicit rule (NUL in the
first 8 KB, matching `grep -I` in the C locale) and writes all output through the sanitiser. Differences from
bash under unusual locales go in the divergence register.

**5.4 Speed.** In-process matching removes about 230 forks per scanned file. Target: not slower than bash on
the rule corpus (49.5 s today); expectation is several times faster for the pattern layers. External tools
(semgrep, trivy, scancode) dominate real scans and are unchanged.

**5.5 Determinism.** Bash associative arrays iterate in hash order. The Python engine emits findings and file
results sorted (path, then rule), which also makes reports diff-able.

**5.6 Subprocess handling.** Every external tool call uses an argument list (never `shell=True`), a timeout, a
captured and sanitised output, and an explicit mapping of exit codes. This removes the quoting bug classes in
CLAUDE.md "Bug classes that have already shipped" (multi-character IFS, top-level `local`, RETURN traps,
`grep` without `-e`, backslash classes in brackets, `find | head`, `echo -e`, uninitialised associative arrays):
those lints retire for the Python engine and are replaced by the ones in section 7, Phase 5.

**5.7 Behaviour hidden in `set -e`.** Several bash paths rely on `|| true`, SIGPIPE and exit-status quirks
(the review found two empty-associative-array aborts this month). Phase 0 captures current behaviour as golden
files for fixtures **and** hostile inputs; the port is checked against them, and any bash bug is a conscious entry
in the divergence register rather than an accident.

**5.8 Drift during the port.** Rule changes keep happening (three review rounds in the last weeks). Rule: while
both engines exist, any rule change lands in both, and the conformance job fails if they disagree. A feature
freeze on new scanners during Phases 2 to 4 is the cheaper alternative and is the recommended default.

## 6. Phases

| # | Phase | Deliverables | Exit criteria | Rough effort |
|---|---|---|---|---|
| 0 | **Freeze and prove feasibility** | `engine_contract.md` + JSON Schema; golden outputs from the bash engine for every fixture and hostile input; the differential harness (`tests/conformance/`); the `rx.py` translator spike fuzzed against `grep -E` on all ~230 patterns | Go/no-go: every pattern translates or is rewritten; harness runs both engines on the fixtures and prints a diff report | 4 to 6 days |
| 1 | **Share the Python that already exists** | The seven heredoc blocks become real modules under `transit/`; the bash script calls them by path; the splice tooling (`splice_office.py`) is retired; Dockerfile, offline bundle, manifest and CI file lists updated | `scan_pipeline.sh` shrinks by about 2,800 lines, the full suite is still 740/740, helper modules have their own unit tests | 5 to 8 days |
| 2 | **Skeleton and the shared machinery** | `cli`, `config`, `console`, `verdict`, `findings`, `files`, `dispatch`, `report`, `pipeline`; allowlist, `.transitignore`, diff mode, `--min-severity`, JSON and HTML reports, sidecars, `scan_pipeline.py` and the launcher | Python engine runs end to end on the `clean` fixture with the same JSON keys and exit status; `TRANSIT_ENGINE` switch works | 6 to 9 days |
| 3 | **Pattern scanners** | `rules/` tables and `scanners/*` in this order: universal L4 + credentials, then javascript, python, shell, java, go, php, ruby, c/c++, rust, kotlin, c#, then sql, yaml, terraform, docker, then makefile, cmake, html, xml, bat, powershell, setup.py, gradle, manifests | Per scanner, before merge: differential test on the rule corpus and on a real-file corpus shows identical per-file status and rule ids | 12 to 18 days (scanners are independent, so this parallelises) |
| 4 | **Containers and tool layers** | `containers/pdf,jar,office,binary,archive` (thin, they reuse Phase 1 modules); `tools/*` wrappers; L1 to L6 orchestration, offline logic, gitleaks on the pipeline's terms, coverage block, `RUN_SCA` / `RUN_SCANCODE` | Same coverage block as bash with stub tools and with real gitleaks; the Layer C2 and G tests pass on the Python engine | 8 to 12 days |
| 5 | **Verification and hardening** | The suite runs twice in CI (`TRANSIT_ENGINE=bash` and `python`); ReDoS fuzz gate over every compiled pattern; new lints (no `shell=True` or `os.system`, every subprocess has a timeout, no `print` of repository text outside `console.py`, no bare `except`); real-file corpora (Makefiles, HTML, CMake, Gradle, XML, jars, documents) rebuilt as a script; performance report | Zero unexplained differences; divergence register reviewed; speed not worse than bash | 6 to 10 days |
| 6 | **Cut-over** | `scan_pipeline.sh` becomes the launcher; default engine is Python; bash engine kept for one release behind `TRANSIT_ENGINE=bash`; docs (CLAUDE.md, INSTALL.md, runbook) and all PDFs and Word documents regenerated; Dockerfile and CI updated | One release with no regression reports; then delete the bash engine and its lints | 3 to 4 days |
| 7 | *Optional:* **`ai_transit.sh` and `fetch_repo.sh`** | Same treatment for the orchestrator and the fetch step | Only if you want a pure-Python pipeline; not needed for "launch either way" | 4 to 6 days |

Total for phases 0 to 6: about **44 to 67 person-days** (9 to 13 weeks for one engineer). With three streams
working in parallel after Phase 2 (patterns, containers and tools, verification) it is nearer 6 to 8 weeks. These
are estimates with wide error bars: the biggest unknown is how many patterns need rewriting after the Phase 0
fuzz.

## 7. How equivalence is proved

1. **Differential harness.** Run both engines on the same directory, normalise the JSON (sort, drop timestamps
   and paths that differ by design) and diff verdict, per-file status, rule ids, messages and coverage. Corpus:
   the 362-file rule corpus, all test fixtures, the hostile inputs from the review (non-UTF-8 names, ESC bytes,
   stale `.diff_files`, empty allowlist, trailing slash, repository-supplied `.gitleaks.toml`), and the real-file
   corpora named in CLAUDE.md (88 Makefiles, 388 HTML, 1,116 CMake, about 6,300 Gradle, 3,362 XML, 365 jars,
   217 documents).
2. **The existing suite, twice.** `./tests/run_tests.sh` already drives `ai_transit.sh`, so one environment
   variable runs all 740 assertions against each engine. Assertions that read the shell source become
   engine-specific lints.
3. **Pattern fuzz.** Every compiled rule against `grep -E` (agreement) and against pathological input (time bound).
4. **Mutation checks** on the translator and the shared machinery, as the project already does: break each
   piece on purpose and confirm the right assertion turns red.
5. **Red before green.** New tests are first run against the previous behaviour, as the repository rule requires.

## 8. Rollout and rollback

- Phase 6 flips only the default; `TRANSIT_ENGINE=bash` restores the old engine until it is deleted.
- Jenkins and other callers keep working unchanged because the CLI, sidecars and report names are the contract.
- The bash engine is removed only after one release with the Python engine as the default and a clean divergence
  register. Until then CI runs both.

## 9. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A pattern backtracks catastrophically in Python | Medium | A hostile file hangs the gateway | Section 5.2: length cap, time budget, fuzz gate in CI |
| Dialect or line-semantics mistakes make a rule silently stop firing | Medium | False negatives, the worst failure for this product | Section 5.1 fuzz against real `grep`; per-scanner differential tests; every rule keeps a positive fixture |
| Bash and Python engines drift during the port | High if rules keep changing | Hard-to-explain differences | Feature freeze, or "both engines or neither" rule enforced by the conformance job |
| Tool output parsers differ subtly (semgrep, trivy, bandit text, cppcheck) | Medium | Wrong findings or missing coverage | Stub tools in tests as today, plus real tools in the advisory CI job; record each tool's exact output shape in the contract |
| Behaviour that only exists as a bash quirk is relied on by callers | Low to medium | Surprise at cut-over | Golden files (5.7); divergence register; one release with the bash engine still available |
| Distribution gets harder (a package instead of one file) | Medium | Offline bundles, Docker and the self-check manifest miss new files | Phase 1 updates every file list in one place; optional zipapp gives a single file again |
| Effort is underestimated | Medium | Delay | Phase 0 is a cheap go/no-go; phases 3 and 4 are parallel and independently shippable |

## 10. Decisions I need from you

| # | Decision | My recommendation |
|---|---|---|
| 1 | Engine strategy: one Python engine plus a shell launcher, or two maintained engines | One Python engine; bash engine kept only as the oracle, then retired (reading C) |
| 2 | Python floor | 3.10 (what INSTALL.md already states); standard library only |
| 3 | Feature freeze on new scanners during phases 2 to 4 | Yes; otherwise every change is made twice |
| 4 | Port `ai_transit.sh` and `fetch_repo.sh` too | Not now (phase 7, optional); they are small and not what blocks "launch either way" |
| 5 | Ship a single-file `scan_pipeline.pyz` for Jenkins agents | Yes, as a build artefact, in addition to the package |
| 6 | Keep the bash engine after the cut-over | One release behind `TRANSIT_ENGINE=bash`, then delete |

## 11. If you say go, the first two days

1. Write `docs/engine_contract.md` and the JSON Schema from the current report and the CLAUDE.md contract.
2. Generate golden outputs from the bash engine for all fixtures and the hostile inputs.
3. Build the ERE-to-`re` translator spike and fuzz it against `grep -E` on all ~230 patterns, and report how many
   translate cleanly. That single number settles the biggest uncertainty before any scanner is rewritten.
4. Extract `_office_facts` into `transit/containers/office.py` as the proof of Phase 1 (the largest block, 1,763 lines).
