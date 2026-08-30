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
selfcheck.py              ← §11 self-integrity check → PDF/JSON report (7 checks)
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
| L5 | `scan_by_type()` | Bandit (py), ShellCheck (sh), cppcheck (c/cpp), hadolint (Dockerfile), checkov (tf/yaml), Semgrep per-lang, **scan_rust** (rs), **scan_kotlin** (kt/kts), **scan_csharp** (cs) |
| L6 | `scan_scancode()` | ScanCode Toolkit — licence (risky: GPL/AGPL/LGPL/SSPL/BUSL → WARN), CVE HIGH/CRITICAL → FAIL |

**Verdict helpers:**
- `record_pass file` / `record_warn file msg` / `record_fail file msg`
- `record_fail` checks `.transit-allow.json` (ALLOW_MAP) → downgrades to WARN if matched
- `record_fail` checks `SEV_THRESHOLD` → downgrades to WARN if severity below `MIN_SEVERITY`
- `FILE_STATUS[path]` → `PASS | WARN | FAIL`; `FINDINGS[path]` accumulates FAIL messages

**Diff mode** (`--since COMMIT`): `fetch_repo.sh` writes changed file paths to `.diff_files`; `scan_by_type()` skips files not in that set.

**Output:** `generate_report_json` + `generate_report_html` → JSON/HTML in `$WORK_DIR/reports/`; then `echo "$GLOBAL_VERDICT"`.

## WARN vs FAIL semantics

- **FAIL** → pipeline blocks; repo quarantined; no ZIP produced.
- **WARN** → logged, pipeline continues; ZIP produced; findings appear in reports. WARNs are degraded-mode signals (missing optional tool, risky licence, severity below threshold, allowlisted finding).

## Files with unknown extensions

`scan_pipeline.sh` classifies unknown extensions via `scan_unknown()`. They pass through L1–L4 (pattern-based) but are skipped by L5 per-type SAST. ScanCode (L6) still inspects them for licences.

## selfcheck.py flags

```bash
python3 selfcheck.py [--bundle-dir DIR] [--output report] [--checksums file.json]
                     [--format pdf|json|both] [--only 11.1,11.3,11.5]
```

- `--format both` produces both `report.pdf` and `report.json`
- `--only 11.1,11.4` runs only the specified §11 checks

## Adding or modifying a scan layer

1. Add a new function in `scan_pipeline.sh` following the `record_pass/warn/fail` pattern.
2. Call the function in `classify_file()` or the execution block near line 1350.
3. Update the `"standards"` array in `generate_report_json()`.
4. Update `INSTALL.md` (§5 tool section), `build_pdf_en.py` (`TOOL_CATALOG` list), and `build_pdf_en.py` summary table.
5. Regenerate all PDFs.

## Commit & push convention

Working branch: `claude/vigilant-carson-f8twy0` on `gaillotte/claude`.
Always push to this branch. Never push to `main` directly.

```bash
git add <files>
git commit -m "short imperative description"
git push -u origin claude/vigilant-carson-f8twy0
```
