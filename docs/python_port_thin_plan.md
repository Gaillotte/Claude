# Python port, thin variant: call the tools the way the shell does

**Status: proposal of 2026-11-14, not approved.** Nothing in the repository changes until the owner approves it.
It amends `PYTHON_PORT_PLAN.md` sections 5.1 to 5.4 and `docs/python_engine_design.md` section 9; every other part of
the plan and the design stands.

## 1. Why this proposal

The owner's expectation was the same architecture as the shell, with Python calling the tools as the shell does.
The current design does something different: it matches every pattern **inside Python** (`transit/rx.py`, a translator
from `grep -E` syntax to Python's `re`, with a lazy DFA to survive slow patterns) instead of starting `grep`. That was
my choice (plan 5.1). It was never offered as a decision. Most of the weight of the Python design follows from it: the
translator, the fuzzing against grep, the slow-pattern work, find's glob rules re-implemented, and the proof that both
agree.

Measured on this host, one pattern test on a 355-byte file, 1,000 calls each:

| | Per call |
|---|---|
| Python starting `grep -qE` | 1.36 ms |
| The shell starting `grep -qE` | 1.39 ms |
| The same test inside Python (`rx.py`) | 0.002 ms |

Calling grep from Python costs what the shell pays. In-process matching is about 700 times faster per test, and that is
its only clear advantage.

## 2. The principle

**Call a tool when the tool defines the behaviour. Use the standard library when the behaviour is exact and trivial.**

| Call the tool | Use the standard library |
|---|---|
| `grep` (every rule), `find` (optional, see 8.2) | SHA-256 (`hashlib`), sorting, JSON, argument parsing |
| gitleaks, Semgrep, ClamAV, YARA, trivy, ScanCode, detect-secrets, Bandit, ShellCheck, cppcheck, hadolint, checkov | text views of a file (CR stripped, comments stripped, UTF-16 decoded) as `bytes` operations |
| `file`, `strings`, `unzip` | |

Rules for every call: an argument list and never a shell; `-e` before every pattern and `--` before every path; a
timeout; `LC_ALL=C` in the child environment (already the case); exit 0 is a match, 1 is none, 2 or more is
`engine:search_incomplete` (already designed); output size bounded. The tool layer (`transit/tools`) already works this
way for the external scanners.

## 3. What happens to what is built

| | Modules | Lines |
|---|---|---|
| **Keep unchanged** | `cli`, `config`, `console`, `findings`, `verdict`, `report`, `layers`, `tools`, `dispatch`, the scanner registry, the helper programs, the conformance harness and the 26 golden reports | the rest of the engine and its tests |
| **Change** | `rules` (evaluate through grep, same public API), `credentials` (`grep -o` instead of `rx.only_matching`), `scanners/__init__` (drop one timeout class), `files` (flat view without `rx`) | about 1,000 |
| **Add** | `transit/grep.py`: builds the argument list for each rule mode, runs it, maps the exit status. The flags are those of contract 8.7 (`grep_check`, `grep_check_i`, `grep_check_excl`, `grep_flat`, the known-credential helper) | about 150 (estimate) |
| **Remove** | `rx.py` (1,490), `tests/conformance/test_rx.py` (1,166), `tests/conformance/pattern_fuzz.py` (1,492), their lints, the long-line routing and memory tests of `rules` | about 4,100 plus part of the rules tests |

`PYTHON_PORT_PLAN.md` section 4 already maps each shell function group to a module, so the architecture matches the
shell's. The one thing that differs is how a pattern is matched.

Divergences that disappear because the same grep does the matching: the dialect differences, D-030 (long lines
reported without the exclusion test), the 32 KiB versus 96 KiB window of `grep -I`, `grep -a` versus plain `grep` on
files with a NUL byte, leftmost-first versus leftmost-longest, and the folded view across a NUL.

## 4. Phases

| # | Phase | Work | Estimate | Exit criteria |
|---|---|---|---|---|
| T0 | Decide | The owner approves this plan, or picks another route (section 7). Nothing is deleted. | | Written decision |
| T1 | Spike | In a scratch copy: `transit/grep.py` plus a grep-backed `Match` for the line, case-insensitive, exclusion and flat modes, and the credential helper. Evaluate every rule on every file of `tests/fixtures/rules` through both backends. | about 1 day | (1) the same answer as the in-process backend on every rule and file pair; (2) evaluating the corpus is not slower than the bash engine's whole scan of it (49.5 s); (3) the code removed is at least `rx.py` and its fuzzers |
| T2 | Swap | Apply the spike to the tree: add `Target.path` (additive), switch `rules` and `credentials`, delete `rx.py` and its tests, update the import lint, the pattern inventory check and the documents. | 2 to 3 days | Whole `tests/engine` green; pattern inventory still lists every pattern the engine passes to grep |
| T3 | Finish Wave 1 | WP-09, WP-10 and WP-11 as designed. They reach matching only through the rules layer, so they can run now. | as planned | `conformance.py check --engine python --case clean` prints `ok clean`; `TRANSIT_ENGINE` switch works |
| T4 | Waves 2 and 3 | The 31 scanner ids and the tool wrappers as designed. Each scanner is rule rows plus tests; the per-scanner hostile-line tests are dropped. | as planned, smaller | `family_diff.py` equal to bash per family |
| T5 | Verification and cut-over | WP-V without the regex fuzz gate: corpora, performance report, cut-over gate, documented counts, regenerated PDFs and Word documents. | as planned, smaller | All 26 golden cases and the real-file corpora equal |

Only T1 and T2 are new estimates; T3 to T5 keep their existing estimates and should be re-estimated after the spike.

## 5. Speed, stated honestly

A scan starts the same grep processes as the shell. The shell engine takes about 135 ms per file on the rule corpus
(49.5 s for 365 files); at 1.4 ms per process that is at most about 100 process starts per file. The real number is
lower because the same time pays for other work. Two optimisations keep calling grep and stay out of the parity work:
one grep over many files for the whole-directory rules, and a worker pool. The shell cannot do either easily.

## 6. Risks and how they are met

| Risk | Answer |
|---|---|
| A large repository is as slow as the shell | Parity is the goal; the optimisations above come after |
| GNU grep differs between hosts | The Docker image installs it; `selfcheck.py` records the version; BSD grep stays unsupported, as for the shell |
| A path that starts with `-` becomes an option | `--` before every path and `-e` before every pattern, enforced by a lint |
| Many small processes | The same as the shell; each call has a timeout and bounded output |
| The per-file time budget (D-035) loses its in-process alarm | The subprocess timeout and a monotonic deadline replace it |
| Discarded work | About 4,100 lines of code and tests; the remaining 30,000 or so lines stay |

## 7. The alternative: a literal translation

Translate `scan_pipeline.sh` function by function into one Python package that calls the tools, and drop the modular
design. It is the closest reading of "same architecture", but it discards the ten finished packages and their 1,700
tests, gives up the unit tests and the frozen interfaces, and still needs the conformance harness. The module map already
mirrors the shell's functions, so I do not recommend it.

## 8. What the owner decides

1. **Route.** Approve the T1 spike (recommended), choose the literal translation, or keep the in-process engine.
2. **File listing.** Default: keep the Python walk, which equals `find` on 38 pattern sets and 1,750 random trees. Use
   `find` instead only for literal parity; it brings back find's known limits (a quadratic cost and the argument-list
   limit with thousands of `.transitignore` patterns).
3. **Wave 1.** Continue WP-09, WP-10 and WP-11 now (default); they do not depend on the matching backend.

## 9. Documents that change on approval

`PYTHON_PORT_PLAN.md` 5.1 to 5.4 and the phase table; `docs/python_engine_design.md` section 9 (rule tables and search
policy) and the divergence entries listed in section 3; `docs/engine_divergences.md`; `CLAUDE.md` (the conformance
tooling paragraph loses `test_rx.py` and `pattern_fuzz.py`); the slide deck.
