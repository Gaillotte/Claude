# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**AI Transit Pipeline** — a Bash-based security gateway that scans AI-generated Git repositories through 6 security layers before allowing them into an enterprise environment. The pipeline either produces an approved ZIP archive (PASS) or quarantines the repo (FAIL).

## Running the pipeline

```bash
# Native (all tools must be installed — see INSTALL.md)
./ai_transit.sh https://github.com/org/repo [branch]
./ai_transit.sh /local/path/to/repo

# Common flags
./ai_transit.sh --quiet https://github.com/org/repo          # CI mode — verdict only
./ai_transit.sh --verbose https://github.com/org/repo        # full debug output
./ai_transit.sh --min-severity medium https://github.com/org/repo  # lower threshold
./ai_transit.sh --since abc1234 https://github.com/org/repo        # diff mode (changed files only)
./ai_transit.sh --report-only https://github.com/org/repo          # never block (observe)
./ai_transit.sh --no-zip --no-excel https://github.com/org/repo    # reports only, no archive
OFFLINE_CACHE=/opt/ai-transit/offline-cache \
  ./ai_transit.sh --offline /local/path/to/repo                    # air-gapped

# Private GitHub repos
GITHUB_TOKEN=ghp_... ./ai_transit.sh https://github.com/org/private-repo

# Docker (no local tool installation needed)
./docker-run.sh --build                              # build image once
./docker-run.sh https://github.com/org/repo [branch]

# Scan pipeline only (already-fetched directory)
WORK_DIR=/opt/ai-transit bash scan_pipeline.sh /path/to/fetched/repo
```

Output: PASS → ZIP in `./Good/` · FAIL → quarantine in `$WORK_DIR/quarantine/` + JSON + HTML reports in `$WORK_DIR/reports/`.

## Key environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `WORK_DIR` | `/opt/ai-transit` | Root for fetch/, quarantine/, reports/, logs/ |
| `OUTPUT_DIR` | `<script_dir>/Good` | Destination for approved ZIPs |
| `GITHUB_TOKEN` | _(unset)_ | Authenticated clone for private GitHub repos |
| `MAX_SIZE_MB` | `500` | Repository size limit in MB |
| `MIN_SEVERITY` | `high` | Minimum severity to FAIL (`low\|medium\|high\|critical`) |
| `VERBOSITY` | `normal` | Log verbosity (`quiet\|normal\|verbose`) |
| `SINCE_COMMIT` | _(unset)_ | Diff mode: only scan files changed since this commit SHA |
| `OFFLINE` | `false` | Air-gapped: no scanner attempts a network call |
| `OFFLINE_CACHE` | `$WORK_DIR/offline-cache` | Staged Semgrep rules, trivy DB, ClamAV signatures |

## Allowlist and exclusions

- **`.transitignore`** (repo root): gitignore-style patterns; matched files are excluded from all scans.
- **`.transit-allow.json`** (repo root): JSON array of `{rule, path, reason}` entries that downgrade a matching FAIL to WARN. Example:
  ```json
  [{"rule": "CWE-798", "path": "tests/fixtures/dummy_key.py", "reason": "test fixture only"}]
  ```

## Regenerating documentation artefacts

```bash
# Installation guide PDF (from INSTALL.md)
python3 build_install_pdf.py

# Air-gapped operating procedure PDF (from OFFLINE_RUNBOOK.md)
python3 build_install_pdf.py OFFLINE_RUNBOOK.md AI_Transit_Pipeline_OFFLINE_RUNBOOK.pdf

# French slides PDF
python3 build_pdf.py

# English slides PDF  (41 pages, 16 tool slides + summary)
python3 build_pdf_en.py

# French Word doc
python3 build_doc.py

# English Word doc
python3 build_doc_en.py
```

All PDF builders use **ReportLab**; Word docs use **python-docx**. Install with:
```bash
pip install reportlab python-docx openpyxl
```

## Architecture

```
ai_transit.sh          ← orchestrator: flag parsing, phase 1 → fetch, phase 2 → scan
  fetch_repo.sh        ← clones GitHub repo (github.com whitelist, 500 MB limit)
                          writes FETCH_DIR to .fetch_result; diff mode → .diff_files
  scan_pipeline.sh     ← 6-layer scanner; emits PASS or FAIL on stdout last line

generate_excel_report.py  ← report_<ts>.json → .xlsx (Summary / Files / Findings tabs)
selfcheck.py              ← self-check integrity report → PDF/JSON report (7 checks)
docker-run.sh             ← Docker wrapper; auto-builds; forwards env vars to container
Dockerfile                ← multi-stage image (builder: Go/betterleaks; runtime: 16 tools)
```

## scan_pipeline.sh internals

All 6 layers run in sequence inside a single process. Verdict accumulates in `GLOBAL_VERDICT` (starts `PASS`, irreversibly flips to `FAIL`).

| Layer | Function region | Tools |
|-------|----------------|-------|
| L1 | `~line 75–360` | betterleaks, detect-secrets, ClamAV, YARA |
| L2 | `~line 361–420` | Semgrep (p/owasp-top-ten, p/cwe-top-25, p/security-audit, p/secrets) — single run |
| L3 | `~line 421–550` | trivy, pip-audit, safety, npm audit |
| L4 | `~line 551–985` | grep built-ins (CWE-798/22/918/327/338, OWASP-A09), plus known credential formats (18 providers) |
| L5 | `scan_by_type()` | Bandit (py), ShellCheck (sh), cppcheck (c/cpp), hadolint (Dockerfile), checkov (tf/yaml), Semgrep per-lang, **scan_rust** (rs), **scan_kotlin** (kt, and kts other than `*.gradle.kts`), **scan_csharp** (cs), **scan_pdf** (pdf — stream decoding + anchored name rules), **scan_makefile** (mk/mak/Makefile), **scan_html** (html/htm/xhtml), **scan_cmake** (cmake/CMakeLists.txt), **scan_xml** (xml/pom + Maven/Ant build rules), **scan_powershell** (ps1/psm1/psd1/pssc/psrc), **scan_powershell_xml** (ps1xml/psc1/cdxml), **scan_setup_py** (setup.py, conanfile.py), **scan_gradle** (*.gradle, *.gradle.kts, gradle.properties, gradle-wrapper.properties), **scan_package_json** (package.json, composer.json), **scan_requirements** (requirements*.txt) |
| L6 | `scan_scancode()` | ScanCode Toolkit — licence (risky: GPL/AGPL/LGPL/SSPL/BUSL → WARN), CVE HIGH/CRITICAL → FAIL |

**Verdict helpers:**
- `record_pass file` / `record_warn file msg` / `record_fail file msg`
- `record_fail` checks `.transit-allow.json` (ALLOW_MAP) → downgrades to WARN if matched
- `record_fail` checks `SEV_THRESHOLD` → downgrades to WARN if severity below `MIN_SEVERITY`
- `FILE_STATUS[path]` → `PASS | WARN | FAIL`; `FINDINGS[path]` accumulates FAIL messages

**Diff mode** (`--since COMMIT`): `fetch_repo.sh` writes changed file paths to `.diff_files`; `scan_by_type()` skips files not in that set.

**Output:** `generate_report_json` + `generate_report_html` → JSON/HTML in `$WORK_DIR/reports/`; then `echo "$GLOBAL_VERDICT"`.

## Air-gapped operation

`--offline` exists because several scanners fetch at **scan** time (semgrep pulls
rulesets, trivy downloads a CVE database, pip-audit/safety/npm audit query advisory
services, ScanCode's `--vulnerability` queries VulnerableCode). Without it on an
isolated host those calls block on timeouts and return nothing, so L2 and L3 quietly
contribute no findings while the report still shows them as having run — a PASS that
means very little.

Two separate bundles, with different lifetimes: `prepare_offline_install.sh` stages
the **software** (apt packages, Python wheels, binaries, scripts — rebuild only when a
tool version changes), and `prepare_offline_cache.sh` stages the **data** the scanners
read (rules, CVE database, signatures — perishable, rebuild weekly). INSTALL.md §2 is the
end-to-end walkthrough (blank machine → install → offline-enable each tool →
disconnect and verify); §12 covers disconnected installation, §11 disconnected
scanning. `verify_offline_install.sh` is the final acceptance step: it checks each
tool individually before running the pipeline, because a tool that cannot work
offline yields an empty result that looks exactly like a clean one.

`--offline` points each tool at staged data (`prepare_offline_cache.sh` builds it),
passes update-suppressing flags, and records an explicit `OFFLINE:` warning for any
layer that could not run. pip-audit, safety, npm audit and ScanCode's CVE lookup have
no offline mode at all; the staged trivy database is the only offline CVE coverage.
Full per-tool reference: INSTALL.md §11. Step-by-step operating procedure,
including the acceptance gate: OFFLINE_RUNBOOK.md.

The JSON report carries a `coverage` block naming, per layer, whether it ran, plus
`coverage_complete` and `coverage_gaps`. A verdict alone cannot distinguish "clean"
from "nothing was examined" — automated consumers should gate on coverage, not on
the verdict.

## WARN vs FAIL semantics

- **FAIL** → pipeline blocks; repo quarantined; no ZIP produced.
- **WARN** → logged, pipeline continues; ZIP produced; findings appear in reports. WARNs are degraded-mode signals (missing optional tool, risky licence, severity below threshold, allowlisted finding).

## PDF scanning

A PDF is a container, not a flat document: the format can auto-run JavaScript on
open (`/OpenAction`, `/AA`), start an external program (`/Launch`), and carry an
embedded executable (`/EmbeddedFile`). `scan_pdf()` treats it accordingly —
**FAIL** on active content, **WARN** on content it cannot inspect, PASS on an
ordinary document. Two format properties make this harder than a grep:

- **Encoding.** From PDF 1.5 an object dictionary may live inside an `/ObjStm`,
  so none of those names need appear in the plaintext. `_pdf_searchable()`
  decodes the declared filter chain of every stream — `FlateDecode`,
  `LZWDecode`, `ASCIIHexDecode`, `ASCII85Decode`, `RunLengthDecode`, all
  stdlib-only, with a 64 MB decompression-bomb ceiling. Chains are real:
  ReportLab writes `/Filter [ /ASCII85Decode /FlateDecode ]`. A stream behind a
  filter it cannot decode is WARNed about **by name** — "not inspected" must
  never read as "clean". Image filters (`DCTDecode`, `JPXDecode`,
  `CCITTFaxDecode`, `JBIG2Decode`) are excluded: they carry pixels, never
  dictionaries, so warning about them would fire on every PDF with a photo.
- **Name escaping.** `/J#61vaScript` and `/JavaScript` are the same name to a
  reader, so escapes are decoded before matching. An escape is reported as
  obfuscation only where it decodes to a dangerous name; a bare `#xx` inside a
  compressed stream is binary noise, and matching it flagged this project's own
  PDFs.

### Two views, and why both are needed

`_pdf_searchable()` emits **two** renderings, and each rule reads exactly one:

| View | Contents | Rules |
|------|----------|-------|
| `$names` | string literals blanked | key rules (`/JavaScript`, `/OpenAction`, …) |
| `$searchable` | everything, plus markers | payload rules (shellcode, exploit APIs, embedded PE) |

The split is not cosmetic. This guide contains the prose "Python/JavaScript
dependency CVE", which a content stream renders as
`(Python/JavaScript dependency CVE) Tj` — so a key rule reading the full view
fails the guide against its own scanner. Anchoring cannot fix it: requiring a
non-name byte before the slash would also reject `/S/JavaScript`, which is valid
PDF because names self-delimit. Only string context distinguishes them. The
payload rules need the opposite view, since the script lives inside `/JS ( … )`.

Blanking string literals is itself attackable, so it is bounded: a `(` that does
not close within `MAX_STRING` is treated as data, and raw stream bodies are
blanked before string tracking. Otherwise one stray `0x28` in an image stream
opens a string that never closes and swallows every dictionary after it.
`pdf_paren_swallow_js.pdf` pins this down.

**Anchoring is still load-bearing.** TrueType subsetting produces font tags like
`/AAAAAA+DejaVuSans`, which an unanchored `/AA` rule reads as an
AdditionalActions key — that false positive blocks this project's own INSTALL
guide. Every short name is matched only where the next byte cannot continue a
PDF name. `tests/fixtures/rules/benign_doc.pdf` embeds a subset font to guard
this; regenerate fixtures with `python3 tests/fixtures/make_pdf_fixtures.py`.

**Acceptance test:** this project ships four PDFs, and they are the realistic
negative set. After any change to `scan_pdf()`, scan a directory containing them
and confirm `PASS` with no findings.

**Remaining gap:** an encrypted PDF (`/Encrypt`, or a `/Crypt` stream filter) is
WARNed about but not decrypted, so its streams go uninspected.

## CMake scanning

`scan_cmake()` handles `.cmake` by extension and `CMakeLists.txt` by basename.
The basename branch is essential: `CMakeLists.txt` ends in `.txt`, so without it
the file is routed to the plain-text scanner and gets no CMake analysis at all.

Two things make CMake worth its own scanner:

- **`file(DOWNLOAD …)` and `execute_process(…)` run at *configure* time.**
  `cmake .` is enough to fire them; there is no build step to decline. Same
  hazard as a Makefile's `$(shell …)`, one stage earlier.
- **`set(NAME "value")` is a function call, not an assignment**, so the
  universal CWE-798 rule — which expects `key = "value"` — cannot see a
  credential in a CMake file at all.

**FAIL:** credential in `set()` · download over plaintext `http://` ·
`TLS_VERIFY OFF` · download piped into a shell · hardening removed
(`-fno-stack-protector`, `_FORTIFY_SOURCE=0`, `execstack`) · `file(WRITE …)`
into `/etc`, `~/.ssh` or cron.
**WARN:** a build step that fetches · `COMMAND sh -c` · `install(CODE|SCRIPT)` ·
`GIT_TAG` on a moving branch.

Rates are measured against **1116 real CMake files** (the CMake 3.28 module tree
plus installed projects). Calibration changed two rules:

- `execute_process` appears in **106 of 1116**, so it cannot be a finding by
  itself — only one running a downloader or a shell is.
- **`URL` is overloaded.** `set_package_properties(… URL "http://xmlsoft.org/")`
  is a project homepage, not something fetched, and a rule that could not tell
  the difference failed two of CMake's own modules. The download rule therefore
  requires either `file(DOWNLOAD …)` or a URL ending in an archive extension.

The credential rule excludes a value that is a variable reference or starts with
a backslash, because real CMake contains both
`set(DROP_SITE_PASSWORD "${CTEST_DROP_SITE_PASSWORD}")` and
`set(CMAKE_SHARED_LIBRARY_RPATH_ORIGIN_TOKEN "\$ORIGIN")` — the second being a
name that merely contains `TOKEN`.

**Result: 1 of 1116 fails**, and that one is a plaintext archive URL inside
CMake's own `ExternalProject` documentation. `tests/fixtures/rules/safe.cmake`
carries the near-miss of every rule above.

## HTML scanning

`scan_html()` handles `.html`, `.htm` and `.xhtml`. Inline `<script>` is
entirely ordinary, so the rules cannot target script itself — they target
constructs with no innocent explanation.

**Which those are was decided by measurement, not intuition.** Every rule was
counted against 388 real HTML files taken off this host (Go tool bundles,
Playwright reports, gcloud and Python package docs), and the count appears in a
comment beside each rule. Two results changed the design:

- A bare `unescape(` appeared only as `unescape(encodeURIComponent(x))`, the
  standard UTF-8-to-byte-string idiom in most bundled JS. The rule therefore
  requires a percent-encoded blob — `unescape('%u9090…')`.
- `innerHTML` appeared in 8 of 388. A genuine XSS sink, far too common to
  block, so it warns.

**FAIL** (each 0 of 388 unless noted): `eval(` *(2 of 388 — the bundled Go
trace viewer genuinely calls eval; vendoring it needs a `.transit-allow.json`
entry rather than a weaker rule)* · percent-encoded payload in `unescape()` ·
`document.write()` fed from a decoder · `<script src="http://">` · hidden
iframe (`display:none`, `visibility:hidden`, zero width/height) ·
`<base href="http://">` · `<form action="http://">` · credential in a
`name`/`value` attribute pair · credential in a `<meta content>` · cookie read
wired to a network sink.

**WARN:** `innerHTML`/`outerHTML`/`insertAdjacentHTML` · `new Function(` ·
bare `atob(` · protocol-relative `<script src="//…">` · external meta refresh ·
`javascript:` URI.

Two rules need their shape explained:

- **Credentials.** The universal CWE-798 rule expects `key = "value"`; HTML
  splits the name and the value across two attributes, so
  `<input name="api_key" value="sk_live_…">` is invisible to it. Hence the
  attribute and `<meta>` rules here.
- **Cookie exfiltration** is matched in *both* orders, because
  `new Image().src = '…' + document.cookie` puts the sink first, and is bounded
  to one statement by `[^;]` so a page that reads a cookie somewhere and calls
  `fetch()` elsewhere does not match.

Generated HTML is the main false-positive risk and most of it is already out of
scope: `DEFAULT_EXCLUDE_DIRS` prunes `dist/`, `build/`, `coverage/` and
`node_modules/` first. `tests/fixtures/rules/safe.html` is the negative guard
and deliberately carries the near-miss of almost every rule above.

## Makefile scanning

`scan_makefile()` handles `.mk`, `.mak`, `.make` by extension and
`Makefile*` / `makefile*` / `GNUmakefile*` by basename — the basename branch is
required because `Makefile` contains no dot, so `${f##*.}` yields the whole path
and the extension branch cannot route it.

Recipe lines are shell, so what `scan_shell` covers applies here too. Two things
make a Makefile a worse problem than a shell script:

- **`$(shell …)` runs at parse time**, before any target. `make -n`, or `make`
  with a mistyped target, is enough to fire it — a hostile Makefile does not
  need to be built to act. The rule names the fetching commands rather than
  matching `$(shell …)` generally, because `$(shell git rev-parse)` is ordinary.
- **Assignments are unquoted**, so `PASSWORD = hunter2` is invisible to the
  universal CWE-798 rule, which requires a quote after the `=`. Hence the
  credential rule repeated in `scan_makefile`, via `grep_check_i` because
  Makefile variables are upper-case by convention.

**FAIL:** download piped into a shell · parse-time fetch · base64-decoded
payload executed · reverse shell · hardcoded credential · TLS verification
disabled · setuid/setgid bit · cron/`authorized_keys` persistence · `rm -rf` of
`/` or `$HOME`.
**WARN:** `sudo` in a recipe · `chmod 777` · plaintext `http://` download ·
clone-and-build from a remote.

**False positives are the whole difficulty here** — the dangerous commands look
almost identical to the ordinary ones. `rm -rf $(BUILD)` in a clean target and
`curl -o file url` in a fetch target are the most common rules in any Makefile,
so the destructive-delete rule matches only when the target is exactly `/`, `~`
or `$HOME`, and the download rule requires the pipe into a shell.
`tests/fixtures/rules/safe.mk` guards that distinction.

**Validation:** 88 real Makefiles taken off a Debian host (dpkg, java, vim,
postgresql build fragments) produce **zero findings of any kind**. Re-run that
check after changing these rules:

```bash
find / \( -name 'Makefile' -o -name '*.mk' \) -type f 2>/dev/null \
  | grep -v "$PWD" | while read -r p; do cp "$p" /tmp/realmk/$RANDOM.mk; done
WORK_DIR=/tmp/mkcheck bash scan_pipeline.sh /tmp/realmk --quiet
```

There is deliberately **no rule for a bare `$(eval …)`**: it fired on 7 of those
88 as ordinary metaprogramming, and the dangerous composition
`$(eval $(shell curl …))` is already a FAIL under the parse-time fetch rule.

## PowerShell

Every PowerShell file type is routed, and all of them share one rule set (`_ps_rules`):

| Extension | What it is | Scanner |
|-----------|-----------|---------|
| `.ps1` | script | `scan_powershell` |
| `.psm1` | module | `scan_powershell` |
| `.psd1` | module manifest (a data hashtable) | `scan_powershell` |
| `.pssc` | session configuration | `scan_powershell` |
| `.psrc` | role capability (JEA) | `scan_powershell` |
| `.ps1xml` | type / format data (XML carrying script blocks) | `scan_powershell_xml` |
| `.psc1` | console file (XML) | `scan_powershell_xml` |
| `.cdxml` | CIM cmdlet definition (XML) | `scan_powershell_xml` |
| *(none)* | a `#!…pwsh` or `#!…powershell` first line | `scan_unknown` → `scan_powershell` |

The legacy Monad extensions (`.msh`, `.msh1`, `.msh2`, `.mshxml`) are **not** routed:
PowerShell has not associated them since 1.0 shipped. The XML-based types get the
PowerShell rules *and* the external-entity check from `scan_xml`.

**Extension matching is case-insensitive.** The dispatch used to compare the extension
as written, so `UPPER.PS1` and `UPPER.PY` fell through to `scan_unknown` and **passed**
while `lower.ps1` and `lower.py` failed — renaming a file bypassed its scanner. Windows
users write `.PS1` and `.BAT` as a matter of course. `classify_file` now lower-cases the
extension. This is a general fix, not a PowerShell one; `case_upper.PY` pins it.

**The old scanner was wrong in both directions.** It had three rules. On the 69 real
`.ps1` files on this host (32 distinct) it FAILed 8, **every one a false positive**:
`npm.ps1` and `npx.ps1` (they ship with every Node install and call `Invoke-Expression`
on a command they assemble), pnpm's completion script (same), and Playwright's five
browser installers (download an MSI over https, run `msiexec`). Meanwhile `iex $c`,
`IEX (iwr …)` and `powershell -enc …` all **passed**, because the rules were
case-sensitive — PowerShell is not — and `iex` was only matched before a parenthesis.

The shape that came out of it: a construct that is ordinary on its own (`Invoke-Expression`,
`Start-Process`, a download) is a **WARN**; it becomes a **FAIL** only in a composition with
no innocent reading.

**FAIL** — fetch then execute (`irm … | iex`, `DownloadString` + `iex`, or a shell pipe) ·
`-EncodedCommand` and its abbreviations (`-enc`, `-e`) followed by a base64 blob · decode
then execute (`FromBase64String` with `iex` / `ScriptBlock::Create` / `Assembly::Load` /
`VirtualAlloc`) · a backtick inside the command name (``i`e`x``) · an AMSI bypass · Defender
disabled · persistence (a `CurrentVersion\Run` key, WMI event consumers, the Startup folder) ·
a socket stream fed to a shell · `VirtualAlloc` with `CreateThread` · offensive tooling by
name (`Invoke-Mimikatz`…) · a literal `$Password` or `ConvertTo-SecureString "…" -AsPlainText` ·
a plaintext `http://` download that is then run.
**WARN** — `Invoke-Expression` alone · `Start-Process` / `cmd /c` · an https download that is
then run · execution-policy bypass · hidden window · a Defender exclusion · a scheduled task ·
certificate validation off · creating a local account · a command name built from strings ·
`ScriptsToProcess` in a manifest · a wildcard `VisibleCmdlets` in a role capability.

Several FAIL rules are **whole-file** tests, because the halves sit on different lines and
PowerShell spreads a pipeline across them; `ps_decode_exec.psm1` puts the decode and the
`iex` on separate lines and its assertion goes red if the rule is made line-based.

> **A deliberate relaxation.** `Invoke-Expression` was a FAIL and is now a WARN. In the real
> corpus it occurred in 3 distinct scripts and was benign every time, and PSScriptAnalyzer
> ranks it a warning. The dangerous uses are covered by the FAIL compositions above, but a
> lone `Invoke-Expression $userInput` no longer blocks. `ps_safe_npm_shim.ps1` is modelled on
> `npm.ps1` and pins the decision. Mutation 7 (turn it back into a FAIL) turns that red.

**Result on the 69 real scripts: 8 FAIL → 0 FAIL, 8 WARN** (the same eight files).

**Calibration, honestly.** 32 distinct real scripts is small, and **none** of `.psm1`,
`.psd1`, `.pssc`, `.psrc`, `.ps1xml`, `.psc1` or `.cdxml` exists on this host, so those routes
are tested from fixtures and reasoned from the format, not measured. Comments are not
stripped: a payload inside `#` or `<# #>` is still matched, which errs towards reporting.
`.bat` and `.cmd` remain unscanned.

## setup.py and conanfile.py

`scan_setup_py()` handles `setup.py` and `conanfile.py` **by basename**. `setup.py`
runs on a source `pip install`, and a Conan recipe on `conan install`: both are
install-time code, so everything in them fires before the package is imported by
anything. They route here rather than to `scan_python` because the risk model is
different — `os.system` and `subprocess` are ordinary build tools in a setup script,
and fetching-then-executing is the thing that is not.

The generic Python rules failed **4 of 36** real `setup.py` files, and three of the
four were idioms rather than attacks:

- `exec(fp.read(), version)` — loading a **local** version file into a namespace
  (two files). The generic `exec(` rule cannot tell it from `exec(payload)`.
- `os.system('pip install .')` / `os.system("twine upload dist/*")` — a **literal**
  command, which the "command injection" rule flagged although a literal cannot be
  injected into.

**FAIL** — a download piped into a shell · `exec`/`eval` of a network response ·
decoding a blob **and** executing in one file · a socket handed to a shell, or a
`pty` · writing `authorized_keys`, a crontab or a systemd unit.
**WARN** — overriding `install`/`develop`/`egg_info` · downloading at install time ·
running a program.

The decode and reverse-shell rules each have a **whole-file arm**, because the
pieces sit on different lines (`payload = b64decode(…)` … `exec(payload)`). Both arms
were mutation-tested: delete one and exactly its own assertion goes red.

> **This replaces `scan_python` for these two filenames, and that is a trade-off, not
> a free win.** `bandit` and the generic `eval`/`exec`/`os.system` FAILs no longer run
> on them. The attacks those rules would have caught in a setup script are covered by
> the explicit rules above, and every install-time FAIL rule measured **0 of 36**.

Result: 36 real `setup.py` go from 4 FAIL to **0 FAIL, 3 WARN**. `build.rs` was
considered and **not** extended: this host has no `build.rs` to measure against, and
`std::process::Command` in one is ordinary (it is how `pkg-config` and `cc` are
invoked), so a rule written without a corpus would only guess. It still reaches
`scan_rust`, whose `unsafe` and `Command` FAILs will over-fire on legitimate build
scripts; that is a known gap, not a covered case.

## Gradle scanning

`scan_gradle()` handles `*.gradle`, `*.gradle.kts`, `gradle.properties` and
`gradle-wrapper.properties`, all **by basename**. The basename branch for
`*.gradle.kts` is essential: its extension is `.kts`, so the extension branch
would send it to `scan_kotlin` — Kotlin *source* rules (`Runtime.exec`, MD5, a
quoted credential) and none of the build constructs below. `foo.main.kts` and
other non-Gradle Kotlin scripts still reach `scan_kotlin`. Plain `*.gradle` had
no entry at all and fell through to `scan_unknown`, recorded PASS.

**A Gradle script is a program, not a declarative file.** Groovy is compiled to a
`Script` subclass and Kotlin to a class, and both are evaluated in full at
**configuration** time: on `gradle tasks`, on `--dry-run`, and automatically when
an IDE imports the project. There is no read-only mode and no declarative stage to
retreat to, so a hostile top-level statement fires before any target is chosen.
`settings.gradle` runs first of all, before any project exists.

**FAIL** — build scripts: `apply from: 'http(s)://…'` (downloads a script and runs
it) · `allowInsecureProtocol = true` (Kotlin: `isAllowInsecureProtocol`) · a process
started from a literal or list, a `ProcessBuilder`, or `Runtime.exec`.
`gradle.properties`: a literal `*.password` / `*.secret` / `*.apiKey` ·
`org.gradle.dependency.verification=off|lenient` · `-javaagent` / `-agentpath` in
`org.gradle.jvmargs`. `gradle-wrapper.properties`: a plaintext `distributionUrl`.
**WARN** — a configuration-time remote fetch · `exec` / `commandLine` / `javaexec` ·
a `trustStore` override · `validateDistributionUrl=false`.

**Calibration is real here.** ~6290 build scripts, 101 `gradle.properties` and 26
wrapper files from gradle/gradle, spring-boot, kafka and elasticsearch. The corpus
is *cloned*, because this host has no `.gradle` file at all, so it measures what real
projects write and not what an AI-generated repository does. The workflow agent's
counts were re-measured independently and agreed once its own `attackdemo/` fixture
directory was excluded.

Two calibration results drove the design, and the first is the CMake `URL` lesson
over again:

- **`url = 'http://…'` matched 21 of 6249 and almost none were repositories** —
  licence urls, developer urls and project homepages in POM metadata. Bare `http://`
  is 341 of 6249. So no rule keys on a URL scheme: Gradle 7+ refuses an `http://`
  repository unless `allowInsecureProtocol` is set, which makes the flag the reliable
  tell and the scheme noise.
- **`.execute()` is also a Gradle API call** — `ArtifactResolutionQuery.execute()` was
  2 of the 3 hits. The spawn rule needs a string literal or a list in front of it.

`ProcessBuilder` is matched **without `new`**. The research agent's pattern required
it; Kotlin has no such keyword, so `ProcessBuilder("sh", …)` — the whole spelling —
would have evaded the rule in every `.gradle.kts`. The fix cost nothing on the
corpus and `gradle_kts/build.gradle.kts` pins it.

**Result on 6413 real files:** 99.8% pass. The remaining FAILs are all accounted
for: 8 `signing.password=<literal>` in Gradle's own publishing docs, 2
`allowInsecureProtocol` in the documentation snippet whose comment reads *"you
shouldn't"*, 2 genuine process spawns, and 2 Elasticsearch integration-test users
caught by the pre-existing universal credential rule. A missing
`distributionSha256Sum` is deliberately not reported: 20 of 26 real wrappers omit it.

**Not covered:** `gradle-wrapper.jar` (a committed binary that `./gradlew` runs before
any code the repo declares — `.jar` is in neither the binary nor archive extension
list, so it reaches `scan_unknown`); version catalogs (`libs.versions.toml`);
`-SNAPSHOT` and dynamic versions (71 and 33 of 6249 — dependency hygiene for Layer 3,
not an execution vector).

## Package manifests

`package.json`, `composer.json` and `requirements*.txt` / `constraints*.txt` are
routed **by basename**. Before, the first two ended in `.json` and got one
credential grep, and the third ended in `.txt` and went to the documentation
scanner — so the thing that matters in a manifest, code that runs when
dependencies are installed, was never examined.

**npm.** `preinstall`, `install` and `postinstall` run on every `npm install`, and
`prepare` on a bare one, so a hostile hook fires before anything is built or
reviewed.

- **FAIL** a lifecycle hook that pipes a download into a shell · a hook that
  decodes base64 (or opens a `/dev/tcp` socket, or `nc -e`) into a shell · a
  dependency on `http://`, `git://` or `git+http://`.
- **WARN** an install-time hook being present · a non-lifecycle script that pipes
  or fetches · a dependency from a git or tarball URL rather than the registry.

**Composer.** The same hook rules over `post-install-cmd` and friends. A hook
beginning `@` (a script reference) or containing `::` (a PHP callable) is skipped:
only a shell command line can fetch and execute. **FAIL** also on
`"secure-http": false` or an `http://` repository.

**pip.** **FAIL** an index, `-f`, or requirement over `http://` or `git://`, and
credentials embedded in a URL. **WARN** `--trusted-host` (TLS verification off for
that host), `--extra-index-url` (dependency confusion: pip takes the highest
version from *any* index), and a VCS requirement not pinned to a commit.

**JSON is parsed, not grepped.** A key can be written `"post\u0069nstall"`, which
npm reads as `postinstall` and a pattern never sees. `pkg_escaped/package.json`
has no literal `postinstall` anywhere in the file, and the assertion on it goes
red if parsing is disabled — which is how it was verified. Invalid JSON falls back
to patterns on the raw text with a WARN saying so; there that fallback may FAIL on
a hook but only WARN on a plaintext URL, because without parsing a dependency
cannot be told from the `repository.url` of most published packages.

> **Two bugs the real corpus caught that no fixture could.** The first version
> treated *empty* fact output as "could not parse"; a valid manifest with nothing
> to report prints nothing, so 1172 of 1193 real files took the weaker fallback. And
> that fallback matched any `"url": "git://github.com/…"`, failing 154 of them. The
> fix makes parsing success an explicit `FACT parsed`.

**Calibration is weak here, and this section would be wrong to claim otherwise.**
Of 1193 real `package.json`, **0 fail, 27 warn**; of 47 `requirements.txt`, 0 fail.
But the corpus is mostly published packages under `node_modules`, not application
roots, so it says little about how often an AI-generated repository's own
manifest carries an install hook (2 of 1193 here). The FAIL rules rest on what the
constructs mean, not on a measured rate.

A dependency *name* ending in `token` (`"csrf-token": "^2.0.0"`) sits in the same
key position as a credential, so the JSON credential rule excludes semver-shaped
values. `pkg_safe/package.json` carries that near-miss.

**Not covered:** lockfiles (`package-lock.json`, `yarn.lock`, `go.sum`) — generated
integrity data, large, and little rule value; `go.mod` (cannot execute anything);
`meson_options.txt` (declarative).

## XML, Maven and Ant

`scan_xml()` handles `.xml` and `.pom`. `pom.xml` and Ant's `build.xml` have no
scanner of their own: they arrive here, so everything in this section is what a
Maven or Ant repository gets.

**XXE needs an entity that points at something, not a DOCTYPE.** A bare
`<!DOCTYPE` failed **736 of 3362** real XML files (22%) — `toolbar` 390,
`feature` 82, `rss` 50, `node` 45 — and a bare `<!ENTITY` failed 8 more, every
one a text shortcut (`&nbsp;`) or a W3C HTML DTD reference. The rules are now:

- **FAIL** `xxe_external_entity_references_a_resource` — `<!ENTITY … SYSTEM` with
  a `file:`, `expect:`, `php:`, `gopher:`, `jar:`, `netdoc:`, `ftp:`, `http(s):`
  or absolute-path target.
- **FAIL** `xml_entity_expansion_bomb` — four or more named entity references in
  one entity value (`&#160;` is a character reference and does not count).
- **WARN** `xml_declares_an_external_entity` — a relative `SYSTEM` include
  (DocBook) or a `PUBLIC` DTD reference.

The match runs on the file with **newlines folded** (`grep_flat`), because an
`<!ENTITY` split across lines is still a declaration and a line-based rule is
evaded by pressing Return. It also runs on a **comment-stripped view**:
Maven's own shipped `settings.xml` documents its credentials inside `<!-- -->`,
and an `<!ENTITY` in a comment is not a declaration. Both properties have a
fixture and were confirmed by mutation — disable either and an assertion goes red.

**Credentials key on the element name.** The old rule let `[^>]*>` run from a
`token`-ish *attribute* across the rest of the tag into a later element's closing
tag, so checkstyle's `tokens="LITERAL_DO,…"` and the sentence
"password manager! Thanks</p>" both matched. It now requires
`<password>`, `<token>`, `<secret>`, `<apiKey>`, `<privateKey>` … followed by a
value of six or more characters, excluding `${…}` references, Maven-encrypted
`{…}`, a *path* to a key, placeholder words and a value cut short with `...`.

**Maven (`pom.xml`, `*.pom`)**

- **FAIL** a `<repository>` whose `<url>` is `http://`. It is scoped to the
  repository block: the default Maven archetype writes
  `<url>http://maven.apache.org</url>` as a project *homepage*, and an unscoped
  rule would fail every generated POM. The 5 hits in 221 real poms are all
  Gradle's own `insecureProtocol*` test fixtures — true positives by content.
- **FAIL** `exec-maven-plugin` / antrun whose `<executable>` is `sh`, `bash`,
  `cmd`, `powershell`, `curl` or `wget`. The plugins themselves are ordinary
  (1 of 221) and only the executable decides.
- **WARN** the exec or antrun plugin being present · `system` scope.
- **No rule for `-SNAPSHOT`:** 176 of 221 real poms use one.

**Ant (`build.xml`, `build-*.xml`, `*-build.xml`)** — **FAIL** `<get>` over
`http://` · `<exec>` of a shell or downloader · `<sshexec>`/`<scp>` with a literal
`password=`; **WARN** any `<exec>`. This rests on **22** real files and measured
0 for every FAIL rule, so treat it as less calibrated than the Maven half.

**Result: 0 of 3362 real XML files fail** (previously 736 on DOCTYPE alone).
`pom_evil`/`safe.pom` and `build.xml`/`build-safe.xml` are the fixture pairs;
the basenames matter because the Maven and Ant rules are gated on them.

## Traversal and key material in the universal layer (L4)

`scan_universal_patterns()` runs on **every** file, so a loose rule here
quarantines repositories wholesale. Two of its rules did exactly that until they
were narrowed, and both now carry fixtures in each direction — neither had any
test coverage at all before.

| Rule | Real Makefiles | Real HTML | Real CMake |
|------|---------------|-----------|------------|
| old `CWE-22:path_traversal_pattern` | 27 of 88 (30%) | 254 of 388 (65%) | 33 of 1116 (3%) |
| **narrowed** | **0 of 88** | **0 of 388** | **0 of 1116** |

A literal `../` is a relative path, not an attack: the old rule was failing
`-I../include`, `VPATH = ../src` and `href="../commands"`. Traversal is now
reported only in the three contexts that actually indicate it, each a separate
finding:

- `CWE-22:path_traversal_encoded` — `%2e%2e`, `..%2f`, `%252e%252e`. Encoding a
  `..` has no innocent reading.
- `CWE-22:path_traversal_to_sensitive_path` — traversal arriving at
  `/etc/passwd`, `~/.ssh`, `~/.aws`, `id_rsa`, `system32`, `/proc/self`.
- `CWE-22:path_traversal_composed_with_input` — traversal concatenated or
  interpolated with something else (`"../" + name`, `f"{dir}/../{f}"`,
  `$_GET['p'] . '../'`), which is the shape the vulnerability takes.

In the composed rule the quote **and** the slash are both required. Leaving
either optional makes an ellipsis (`"..."`) match, which is how an earlier cut
of this appeared to leave 14 hits on the HTML corpus.

Two arms were **measured out** of the composed rule rather than reasoned out. A
bare `${VAR}/../` matched 21 of 1116 real CMake files and `../${VAR}` another 2:
joining a known path variable with `..` is ordinary path arithmetic
(`${CMAKE_CURRENT_SOURCE_DIR}/../common.cmake`), not traversal. The f-string and
template-literal arms keep the interpolated case that does matter, because they
require the format-string marker — and none of the ten attack forms in
`tests/fixtures/rules/traversal.txt` needed the arms that were dropped.

`CWE-321` now requires a real PEM header, `-----BEGIN … PRIVATE KEY-----`, and
a public certificate is reported without blocking:

- `CWE-321:hardcoded_private_key` — **FAIL**
- `crypto:public_certificate_embedded` — **WARN**; a certificate is the public
  half of the pair and is published by design, so it is not a leaked key.

The old rule matched the bare words `PRIVATE KEY`, `CERTIFICATE` and
`BEGIN RSA`, so prose such as "store the PRIVATE KEY in an HSM" failed the
repository.

**The header alone is still not enough — a key has a body.** Narrowing to a PEM
header was itself too loose, and the XML corpus showed it. The shared-mime-info
database carries `magic="-----BEGIN PGP PRIVATE KEY BLOCK-----"`: a file-type
*signature*, describing how to recognise a key file rather than containing one.
npm's configuration reference does the same with a placeholder body,
`key="-----BEGIN PRIVATE KEY-----\nXXXX\nXXXX\n-----END PRIVATE KEY-----"`.
`CWE-321` therefore requires the header followed, within five lines, by a run of
60 or more base64 characters — 64 per line in PEM, 70 in OpenSSH. Folding those
lines together is also what lets it see a key held on one line as a JSON string
(where the newlines are the two characters `\n`), and a PGP block whose armor
headers push the body down.

> **Correction.** An earlier version of this section, and two commit messages,
> said the three HTML files that failed this rule "genuinely embed a private key
> in an example TLS config" and were true positives. That was wrong: I had seen
> only that the header was present. All three are npm's documentation with an
> `XXXX` placeholder body. The body requirement is what removes them.

**After narrowing, 2 of 388 real HTML files fail**, both genuine `eval()` calls
in the bundled Go trace viewer; the whole 88-file Makefile corpus, the 3362-file
XML corpus and the 1116-file CMake corpus have no `CWE-321` finding at all.

### Known credential formats

Providers issue tokens with a fixed, distinctive shape: a literal prefix plus a
body of known length and alphabet. Matching the **shape** is a different and much
more precise test than matching a *name* such as `password`, and it works in any
file type, quoted or not — `export GITHUB_TOKEN=ghp_…`, a TOML value, a URL, a
comment. The per-type credential rules cannot do that: they expect `key = "value"`,
so an unquoted value in a Makefile, a `.properties` file, a CMake `set()` or an HTML
attribute is invisible to them, and the same gap had to be patched separately in
`scan_makefile`, `scan_cmake`, `scan_html` and `scan_gradle`.

`CWE-798:known_credential_format_<provider>` is **FAIL** for: AWS access key ids and
secret keys (`AKIA…`, `aws_secret_access_key`), GitHub (`ghp_`/`gho_`/`ghu_`/`ghs_`/
`ghr_` and `github_pat_`), GitLab `glpat-`, Stripe live keys (`sk_live_`/`rk_live_` —
test keys are deliberately not matched), Slack `xox[bpars]-`, Google API keys
(`AIza…`) and OAuth tokens (`ya29.`), SendGrid `SG.`, npm `npm_`, PyPI `pypi-AgEIcHlw…`,
Hugging Face `hf_`, Anthropic `sk-ant-`, OpenAI `sk-proj-` and legacy `sk-`, Shopify
`shpat_`, and DigitalOcean `dop_v1_`. A **JWT** is a **WARN**: it is a signed token
and not necessarily a secret (Supabase's anon key is one and is public by design).

**This is deliberately not a generic `name = value` rule.** That was measured and
rejected: it fires on **34 of 800** real `.py` files (`token = tokens.pop(0)`),
because in a programming language `name = expr` is an expression. A fixed prefix and
length has no such reading. It is also why the existing universal credential rule
requires a quote.

**Calibration.** Over 100,052 files of source, docs and tests (gradle, spring-boot,
kafka, elasticsearch), the ~6,600 other real files collected here, and the host's
`/usr /opt /etc /var /mnt`: no false positive on a real file. The only matches were
AWS's own documentation key (18 times, removed by the `EXAMPLE` exclusion) and three
genuine Google API keys hardcoded in `gcloud` and `gsutil`. What the host *cannot*
test is recall — it holds almost no real tokens — so every provider has a positive
case in the test suite.

**Placeholders are excluded:** `EXAMPLE`, `SAMPLE`, `DUMMY`, `YOUR`, `REDACTED`,
`FAKE`, a run of six `x`, ten zeros, or ten of any one character, and the canonical
GitHub documentation token. Each pattern is bounded on both sides, so a token inside
a longer identifier or a base64 blob does not count. Binary files are skipped (`grep
-I`), which is a limit: a token inside an image or a jar is not seen.

**Not matched, by design:** providers whose secrets are bare hex or base64 with no
prefix (Heroku, Mailgun, Twilio and the like). Nothing distinguishes them from a hash,
and a rule for them would be a guess.

**The tests build every token at run time.** `tests/run_tests.sh` assembles each one
from a context, a prefix and two halves of a body held in separate quoted strings, so
the file never contains a contiguous token. Two reasons: this pipeline run over its own
repository would otherwise flag its own test suite, and a secret scanner on the remote
may refuse a push containing provider-shaped strings. The near-miss file carries the
AWS example key, a placeholder body, a repeated character, the GitHub documentation
token, a Stripe *test* key, a git SHA, and a token embedded mid-identifier; the
exclusion, the word boundary and the repeated-character rule were each mutation-tested.

Cost: one extra `grep` per file — about **9%** on the 1116-file CMake corpus (69.1 s
against 63.3 s) — because a single alternation decides whether any provider is present
before each is named.

### grep_check must pass its pattern after `-e`

A third silent-inert-rule bug, found while writing the PEM rule and now linted
alongside the other two. A pattern beginning with a dash —
`-----BEGIN RSA PRIVATE KEY-----` — is parsed by grep as options, so grep exits
2 with "unrecognized option". `if` reads 2 as false, so the rule never fires
and never complains. `-e` ends the ambiguity.

## Files with unknown extensions

`scan_pipeline.sh` classifies unknown extensions via `scan_unknown()`, which first
inspects the shebang: an extensionless `entrypoint` starting with `#!/usr/bin/env
python3` is routed to `scan_python()` and gets full per-language analysis. Only files
with neither a recognised extension nor a recognised shebang fall back to a MIME-type
check — those pass through L1–L4 (pattern-based) but are skipped by L5 per-type SAST.
ScanCode (L6) still inspects them for licences.

## selfcheck.py flags

```bash
python3 selfcheck.py [--bundle-dir DIR] [--output report] [--checksums file.json]
                     [--format pdf|json|both] [--only 11.1,11.3,11.5]
```

- `--format both` produces both `report.pdf` and `report.json`
- `--only 11.1,11.4` runs only the specified self-check checks
- `--write-manifest` regenerates `.bundle_manifest.sha256` and exits

**Manifest lifecycle:** `.bundle_manifest.sha256` is deliberately **not** tracked in
git (it would report "tampering" after every ordinary edit). Generate it at install
time, and after any intentional change to the bundle:

```bash
python3 selfcheck.py --write-manifest
```

## Adding or modifying a scan layer

1. Add a new function in `scan_pipeline.sh` following the `record_pass/warn/fail` pattern.
2. Call the function in `classify_file()` or the execution block near line 1350.
3. **Add fixtures and assertions** in `tests/`: one file that must trigger the rule and
   one similar-but-safe file that must not. Run the suite and confirm the new assertion
   fails before the rule exists, then passes after.
4. Update the `"standards"` array in `generate_report_json()`.
5. Update `INSTALL.md` (§5 tool section), `build_pdf_en.py` (`TOOL_CATALOG` list), and `build_pdf_en.py` summary table.
6. Regenerate all PDFs.

### Bug classes that have already shipped — lint enforces each

All five are the same kind of defect: a rule or a script that fails *silently*,
so nothing in a normal run shows it is broken.

- **Multi-character `IFS`.** `IFS=':::'` is a character *set*, silently identical to
  `IFS=':'`. This broke the allowlist and the semgrep result parser.
- **Top-level `local`.** Valid syntax, but aborts at runtime under `set -e`; `bash -n`
  cannot see it. It silently broke private-repo cloning.
- **A `RETURN` trap that defers expansion.** The trap is not scoped to the function
  that sets it, so it keeps firing as later functions return and dies on `set -u`.
- **`grep_check` without `-e`.** A pattern starting with a dash is parsed as options,
  grep exits 2, and `if` reads 2 as false: the rule never fires and never complains.
- **`find … | head -N`.** Under `set -o pipefail`, `head` exits early, `find` dies of
  SIGPIPE once its output exceeds one 4 KB write, the pipeline returns 141, and
  `set -e` aborts the scan with no verdict and no report. Eight short paths never
  trigger it; a few dozen realistic ones do (a monorepo with 30 requirements files
  reproduces it). `ai_transit.sh` clears stale sidecars and defaults a missing
  verdict to `FAIL`, so it failed *closed* — wrong, but not unsafe. Use
  `sed -n '1,Np'`, which reads its whole input.

## Tests

```bash
./tests/run_tests.sh          # full suite (needs no scanning tools installed)
./tests/run_tests.sh -v       # show detail for failures
./tests/run_tests.sh rules    # only groups matching "rules"
```

The suite runs in degraded mode (grep-based rules only), which is how CI executes it.
Fixtures live in `tests/fixtures/`; `rules/` is a corpus where each file is crafted to
trigger — or deliberately not trigger — one rule. `safe_sql.py` is the regression guard
for a false positive that once flagged correct parameterised queries.

When adding a rule, add both a positive fixture and a negative one, then confirm the
new assertion **fails** before the rule exists. A test that has never been seen red
proves nothing.

## CI

`.github/workflows/ci.yml` — `lint` (shellcheck, errors fatal) · `test` (suite, no
tools) · `test-with-tools` (scanners installed, advisory) · `pins` (verify pinned tool
versions resolve and match their SHA-256) · `docker` (build image, assert non-root,
smoke-test both fixtures).

## Commit & push convention

Working branch: `claude/vigilant-carson-f8twy0` on `gaillotte/claude`.
Always push to this branch. Never push to `main` directly.

```bash
git add <files>
git commit -m "short imperative description"
git push -u origin claude/vigilant-carson-f8twy0
```
