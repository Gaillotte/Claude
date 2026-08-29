# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**AI Transit Pipeline** — a Bash-based security gateway that scans AI-generated Git repositories through 6 security layers before allowing them into an enterprise environment. The pipeline either produces an approved ZIP archive (PASS) or quarantines the repo (FAIL).

## Running the pipeline

```bash
# Native (all tools must be installed — see INSTALL.md)
./ai_transit.sh https://github.com/org/repo [branch]
./ai_transit.sh /local/path/to/repo

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
ai_transit.sh          ← orchestrator: calls fetch then scan
  fetch_repo.sh        ← clones GitHub repo (github.com whitelist, 500 MB limit)
  scan_pipeline.sh     ← 1295-line scanner; emits PASS or FAIL on stdout last line

generate_excel_report.py  ← reads report_<ts>.json → .xlsx (tab 0: summary, tab 1: per-file)
selfcheck.py              ← §11 self-integrity check → PDF report (7 checks)
docker-run.sh             ← Docker wrapper; auto-builds if image missing
Dockerfile                ← standalone image with all 16 tools pre-installed
```

## scan_pipeline.sh internals

All 6 layers run in sequence inside a single process. Verdict accumulates in `GLOBAL_VERDICT` (starts `PASS`, irreversibly flips to `FAIL`).

| Layer | Function region | Tools |
|-------|----------------|-------|
| L1 | `~line 75–360` | betterleaks, detect-secrets, ClamAV, YARA |
| L2 | `~line 361–420` | Semgrep (p/owasp-top-ten, p/cwe-top-25, p/security-audit, p/secrets) |
| L3 | `~line 421–550` | trivy, pip-audit, safety, npm audit |
| L4 | `~line 551–985` | grep built-ins (CWE-798/22/918/327/338, OWASP-A09) |
| L5 | `scan_by_type()` ~line 1036 | Bandit (py), ShellCheck (sh), cppcheck (c/cpp), hadolint (Dockerfile), checkov (tf/yaml), Semgrep per-lang |
| L6 | `scan_scancode()` ~line 1048 | ScanCode Toolkit — licence (risky: GPL/AGPL/LGPL/SSPL/BUSL → WARN), CVE HIGH/CRITICAL → FAIL |

**Verdict helpers** (lines 29–70):
- `record_pass file` / `record_warn file msg` / `record_fail file msg`
- `FILE_STATUS[path]` → `PASS | WARN | FAIL`; `FINDINGS[path]` accumulates FAIL messages

**Output** (lines 1194–1295): `generate_report_json` + `generate_report_html` → JSON/HTML in `$WORK_DIR/reports/`; then `echo "$GLOBAL_VERDICT"` (consumed by `ai_transit.sh` via grep).

## WARN vs FAIL semantics

- **FAIL** → pipeline blocks; repo quarantined; no ZIP produced.
- **WARN** → logged, pipeline continues; ZIP produced; findings appear in reports. WARNs are degraded-mode signals (missing optional tool, risky licence, MEDIUM severity).

## Files with unknown extensions

`scan_pipeline.sh` classifies unknown extensions as binary-type by default (line ~971). They pass through L1/L2/L3/L4 (pattern-based) but are skipped by L5 per-type SAST. ScanCode (L6) still inspects them for licences.

## Adding or modifying a scan layer

1. Add a new function in `scan_pipeline.sh` following the `record_pass/warn/fail` pattern.
2. Call the function in the execution block near line 1286.
3. Update the `"standards"` array in `generate_report_json()` (~line 1223).
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
