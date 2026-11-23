# Moved out of scan_pipeline.sh (function generate_report_json) without changes to the code below.
# Builds the JSON report from the NUL-delimited streams and REPORT_* environment variables.
# Run by path from the bash engine; also importable by the Python engine. Standard library only.
import json, os, sys

def _read_nul(path):
    """Read a stream of NUL-terminated records, preserving empty ones.

    Every record is written with a trailing NUL, so splitting yields one
    trailing empty element that must be dropped -- but ONLY that one.
    Filtering all empties (`if p`) would silently drop files whose message is
    empty and shift every later element, attributing findings to the wrong
    file in the report.
    """
    if not os.path.exists(path):
        return []
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw:
        return []
    parts = raw.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    return [p.decode("utf-8", errors="replace") for p in parts]

# Structured findings: one JSON object per line, written by _emit_finding.
records = []
_fjl = os.environ.get("REPORT_FINDINGS_JL", "")
if _fjl and os.path.exists(_fjl):
    with open(_fjl, "r", encoding="utf-8", errors="replace") as fh:
        for _ln in fh:
            _ln = _ln.strip()
            if _ln:
                try:
                    records.append(json.loads(_ln))
                except json.JSONDecodeError:
                    pass

fk = _read_nul(sys.argv[1]); fv = _read_nul(sys.argv[2])
sk = _read_nul(sys.argv[3]); ss = _read_nul(sys.argv[4]); sm = _read_nul(sys.argv[5])
ck = _read_nul(sys.argv[6]); cv = _read_nul(sys.argv[7])
while len(sm) < len(sk):
    sm.append("")

findings_by_file = dict(zip(fk, fv))
file_results = {
    k: {"status": s, "message": m.rstrip(" | ")}
    for k, s, m in zip(sk, ss, sm)
}

coverage = dict(zip(ck, cv))
# A layer is "covered" when it ran in full. "partial" and "skipped" both mean
# the verdict rests on less analysis than it appears to.
incomplete = sorted(k for k, v in coverage.items() if not v.startswith("ran"))

# The decision a pipeline stage acts on, with the colours a dashboard shows it in.
approved = os.environ["REPORT_VERDICT"] == "PASS"

report = {
    "verdict":      os.environ["REPORT_VERDICT"],
    "decision":     "APPROVED" if approved else "REJECTED",
    "status_color":      "#198754" if approved else "#B02A37",
    "status_background": "#D1E7DD" if approved else "#F8D7DA",
    "scan_name":    os.environ["REPORT_SCANNING_NAME"],
    "source": {
        "directory": os.environ["REPORT_SCAN_DIR"],
        "sha256":    os.environ["REPORT_CONTENT_HASH"],
    },
    "coverage":           coverage,
    "coverage_complete":  not incomplete,
    "coverage_gaps":      incomplete,
    "timestamp":    os.environ["REPORT_TS"],
    "repo_input":   os.environ["REPORT_REPO_INPUT"],
    "directory":    os.environ["REPORT_SCAN_DIR"],
    "repo_hash":    os.environ["REPORT_HASH"],
    "standards":    ["OWASP-Top10-2021", "CWE-Top25", "CERT-Secure-Coding"]
                    + (["SCA-CVE"] if os.environ["REPORT_RUN_SCA"] == "true" else [])
                    + (["ScanCode-Licence-Copyright"] if os.environ["REPORT_RUN_SCANCODE"] == "true" else [])
                    + ["PDF-Active-Content", "Build-Script-Hardening",
                     "HTML-Active-Content", "XML-Build-Hardening", "Package-Manifest-Integrity", "Gradle-Build-Hardening", "Install-Time-Python", "Known-Credential-Formats", "PowerShell-Hardening", "Windows-Batch-Hardening", "Java-Archive-Hardening", "Office-Document-Hardening"],
    "summary":      {"pass": int(os.environ["REPORT_PASS"]),
                     "warn": int(os.environ["REPORT_WARN"]),
                     "fail": int(os.environ["REPORT_FAIL"])},
    # One record per FAIL (tool, category, severity, rule, file, line, message ...).
    "findings":     records,
    # The same FAIL messages grouped by file, which is what "findings" used to be.
    "findings_by_file": findings_by_file,
    "file_results": file_results,
}

# Written beside the report and renamed into place, so a failure cannot leave a truncated one.
_out = os.environ["REPORT_OUT"]
with open(_out + ".tmp", "w", encoding="utf-8") as fh:
    json.dump(report, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
os.replace(_out + ".tmp", _out)
