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
| L4 | `~line 551–985` | grep built-ins (CWE-798/22/918/327/338, OWASP-A09) |
| L5 | `scan_by_type()` | Bandit (py), ShellCheck (sh), cppcheck (c/cpp), hadolint (Dockerfile), checkov (tf/yaml), Semgrep per-lang, **scan_rust** (rs), **scan_kotlin** (kt/kts), **scan_csharp** (cs), **scan_pdf** (pdf — stream decoding + anchored name rules), **scan_makefile** (mk/mak/Makefile), **scan_html** (html/htm/xhtml), **scan_cmake** (cmake/CMakeLists.txt), **scan_xml** (xml/pom + Maven/Ant build rules) |
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

### Two bug classes that have already shipped — lint enforces both

- **Multi-character `IFS`.** `IFS=':::'` is a character *set*, silently identical to
  `IFS=':'`. This broke the allowlist and the semgrep result parser.
- **Top-level `local`.** Valid syntax, but aborts at runtime under `set -e`; `bash -n`
  cannot see it. It silently broke private-repo cloning.

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
