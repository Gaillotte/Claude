"""Tests of transit/report.py (WP-07): the JSON report, the HTML report, the two sidecars, the atomic write.

    python3 -I -m unittest discover -s tests/engine -p "test_report.py"

Oracles (docs/python_engine_design.md section 11):
  * ``build_report`` is compared with the BASH engine's writer, ``transit/report_json.py``, run as a subprocess on the same
    NUL-delimited streams and ``REPORT_*`` variables the bash engine gives it (it is a program, never imported);
  * every report built here, and every one rebuilt from a golden file of tests/conformance/golden, is run through
    ``tests/conformance/check_schema.py`` (schema + invariants);
  * ``html_escape`` is compared with the bash function ``_html_esc`` extracted from scan_pipeline.sh, on printable text.
A token-shaped credential is never written contiguously in this file (none is needed).
"""
from __future__ import annotations

import ast
import contextlib
import datetime as dt
import html.parser
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from transit import cli, config, console, files, findings, report  # noqa: E402
from transit.findings import Allowlist, FindingRecord, json_safe  # noqa: E402
from transit.verdict import Counters, Snapshot, Verdict  # noqa: E402

GOLDEN = ROOT / "tests" / "conformance" / "golden"
OLD_WRITER = ROOT / "transit" / "report_json.py"
SCHEMA_PATH = ROOT / "docs" / "report.schema.json"
SCAN = "/scan/repo"
NOW = dt.datetime(2026, 11, 13, 12, 34, 56)
NOW_LOCAL = "20261113_123456"
HASH_A = "a" * 64
HASH_B = "b" * 64
SOURCE = files.SourceHashes(sha256=HASH_A, repo_hash=HASH_B)

REQUIRED = ("L1_secrets_gitleaks", "L1_secrets_entropy", "L1_malware", "L2_owasp_cwe", "L3_dependency_cve",
            "L4_patterns", "L5_per_language_sast")
OPTIONAL = ("L1_ioc_yara", "L6_licence")
COVERAGE_SAMPLE = {
    "L1_secrets_gitleaks": "skipped:gitleaks not installed",
    "L1_secrets_entropy": "ran",
    "L1_malware": "skipped:clamav not installed",
    "L1_ioc_yara": "skipped:yara or rules directory missing",
    "L2_owasp_cwe": "partial:rulesets missing (secrets)",
    "L3_dependency_cve": "skipped:disabled (RUN_SCA is not true)",
    "L4_patterns": "ran",
    "L5_per_language_sast": "ran",
    "L6_licence": "skipped:disabled (RUN_SCANCODE is not true)",
}
CLEAN_COVERAGE = {layer: "ran" for layer in REQUIRED}


# ── helpers ────────────────────────────────────────────────────────────────────────────────────────────────────────
class FakeConsole:
    """The two methods ``Verdict`` is allowed to call."""

    def warn(self, text: str) -> None:
        pass

    def fail_line(self, text: str) -> None:
        pass


def new_verdict(scan_dir: str = SCAN) -> Verdict:
    return Verdict(scan_dir, Allowlist({}), threshold=3, min_severity="high", console=FakeConsole())


def set_coverage(v: Verdict, coverage: dict) -> None:
    for layer, state in coverage.items():
        v.record_layer(layer, state)


def mixed_snapshot(coverage: dict | None = None) -> Snapshot:
    """PASS, PASS then WARN (first writer: status PASS, message WARN), WARN, global WARN, a file with two FAILs, a FAIL then WARN."""
    v = new_verdict()
    set_coverage(v, COVERAGE_SAMPLE if coverage is None else coverage)
    v.record_warn("__global__", "gitleaks missing — secret scan skipped")
    v.record_warn("__global__", "clamscan missing")
    v.record_pass(SCAN + "/README.md")
    v.record_pass(SCAN + "/src/app.py")
    v.record_warn(SCAN + "/src/app.py", "bandit missing")
    v.record_warn(SCAN + "/run.sh", "shellcheck missing")
    v.record_fail(SCAN + "/src/db.py", "CWE-89:SQL_injection")
    v.record_fail(SCAN + "/src/db.py", "CWE-798:hardcoded_credential_pattern:line12")
    v.record_fail(SCAN + "/b.py", "CWE-95:dynamic_code_execution_eval_exec")
    v.record_warn(SCAN + "/b.py", "bandit missing")
    return v.snapshot()


def clean_snapshot() -> Snapshot:
    v = new_verdict()
    set_coverage(v, CLEAN_COVERAGE)
    v.record_pass(SCAN + "/README.md")
    v.record_pass(SCAN + "/src/app.py")
    v.record_warn("__global__", "gitleaks missing")
    return v.snapshot()


def make_snapshot(verdict: str, counters: Counters, status: dict, message: dict, fail: dict, records: tuple,
                  coverage: dict) -> Snapshot:
    ro = types.MappingProxyType
    return Snapshot(verdict=verdict, counters=counters, file_status=ro(dict(status)), file_message=ro(dict(message)),
                    fail_messages=ro(dict(fail)), findings=tuple(records), coverage=ro(dict(coverage)))


def build(snapshot: Snapshot, *, scan_dir: str = SCAN, scan_name: str = "n", repo_input: str = "", run_sca: bool = False,
          run_scancode: bool = False, now_utc: dt.datetime = NOW, source: files.SourceHashes = SOURCE,
          fix_d009: bool = False) -> dict:
    return report.build_report(snapshot, source, args=cli.Args(scan_dir=scan_dir, report_dir=None, scanning_name=None),
                               scan_name=scan_name, repo_input=repo_input, run_sca=run_sca, run_scancode=run_scancode,
                               now_utc=now_utc, fix_d009=fix_d009)


def make_cfg(work_dir: str, **env: str) -> config.Config:
    environ = {"WORK_DIR": work_dir}
    environ.update(env)
    return config.load_config(environ, now=dt.datetime(2026, 11, 13, 1, 2, 3))


def make_paths(base: str, *, report_dir: str | None = None, name: str | None = None) -> report.ReportPaths:
    cfg = make_cfg(os.path.join(base, "work"))
    return report.report_paths(cli.Args(scan_dir="/s", report_dir=report_dir, scanning_name=name), cfg)


def load_check_schema():
    spec = importlib.util.spec_from_file_location("conformance_check_schema", ROOT / "tests" / "conformance" / "check_schema.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECK = load_check_schema()
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def conformance_errors(rep: dict) -> list:
    return CHECK.check_report(rep, SCHEMA)


@contextlib.contextmanager
def umask(value: int):
    old = os.umask(value)
    try:
        yield
    finally:
        os.umask(old)


@contextlib.contextmanager
def spy_replace():
    """Record every ``os.replace`` (source, destination, whether the destination existed, the source content and mode)."""
    calls: list = []
    real = os.replace

    def spy(src, dst, *args, **kwargs):
        try:
            with open(src, "rb") as fh:
                content = fh.read()
            mode = stat.S_IMODE(os.stat(src).st_mode)
        except OSError:
            content, mode = None, None
        dst_before = None
        if os.path.exists(dst):
            with open(dst, "rb") as fh:
                dst_before = fh.read()
        calls.append({"src": os.fspath(src), "dst": os.fspath(dst), "src_content": content, "src_mode": mode,
                      "dst_before": dst_before})
        return real(src, dst, *args, **kwargs)

    with mock.patch("os.replace", spy):
        yield calls


@contextlib.contextmanager
def failing_remove(paths):
    """``os.remove`` / ``os.unlink`` raise PermissionError for the given paths and work for every other."""
    real_remove, real_unlink = os.remove, os.unlink
    blocked = {os.fspath(p) for p in paths}

    def guard(real):
        def inner(path, *args, **kwargs):
            if os.fspath(path) in blocked:
                raise PermissionError(13, "Permission denied", os.fspath(path))
            return real(path, *args, **kwargs)
        return inner

    with mock.patch("os.remove", guard(real_remove)), mock.patch("os.unlink", guard(real_unlink)):
        yield


def sanitised_message(text: str) -> str:
    return text[:-3] if text.endswith(" | ") else text


def run_old_writer(snapshot: Snapshot, *, scan_dir: str = SCAN, scan_name: str = "n", repo_input: str = "",
                   run_sca: bool = False, run_scancode: bool = False, now_utc: dt.datetime = NOW,
                   source: files.SourceHashes = SOURCE) -> dict:
    """The bash engine's writer, run on the streams bash would hand it. Returns the report it wrote."""
    tmp = tempfile.mkdtemp(prefix="old_writer_")
    try:
        def stream(name: str, items) -> str:
            path = os.path.join(tmp, name)
            with open(path, "wb") as fh:
                for item in items:
                    fh.write(os.fsencode(item) + b"\x00")
            return path

        fk = stream("fk", list(snapshot.fail_messages))
        fv = stream("fv", [sanitised_message(v) for v in snapshot.fail_messages.values()])
        sk = stream("sk", list(snapshot.file_status))
        ss = stream("ss", list(snapshot.file_status.values()))
        sm = stream("sm", [snapshot.file_message.get(p, "") for p in snapshot.file_status])
        ck = stream("ck", list(snapshot.coverage))
        cv = stream("cv", list(snapshot.coverage.values()))
        jl = os.path.join(tmp, "findings.jsonl")
        with open(jl, "w", encoding="utf-8") as fh:
            for rec in snapshot.findings:
                fh.write(json.dumps(rec.to_json(), ensure_ascii=False) + "\n")
        out = os.path.join(tmp, "out.json")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "REPORT_VERDICT": snapshot.verdict, "REPORT_TS": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "REPORT_REPO_INPUT": repo_input, "REPORT_SCAN_DIR": scan_dir, "REPORT_SCANNING_NAME": scan_name,
               "REPORT_HASH": source.repo_hash, "REPORT_CONTENT_HASH": source.sha256,
               "REPORT_RUN_SCA": "true" if run_sca else "false", "REPORT_RUN_SCANCODE": "true" if run_scancode else "false",
               "REPORT_PASS": str(snapshot.counters.pass_), "REPORT_WARN": str(snapshot.counters.warn),
               "REPORT_FAIL": str(snapshot.counters.fail), "REPORT_OUT": out, "REPORT_FINDINGS_JL": jl}
        proc = subprocess.run([sys.executable, "-I", str(OLD_WRITER), fk, fv, sk, ss, sm, ck, cv], env=env,
                              capture_output=True, timeout=60)
        if proc.returncode != 0:
            raise AssertionError("the old writer failed: %s" % proc.stderr.decode("utf-8", "replace"))
        with open(out, "r", encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def finding_key(rec: dict):
    return (rec["file"], rec["rule_id"], rec["line"] or 0, rec["message"])


def without_findings_order(rep: dict) -> dict:
    out = dict(rep)
    out["findings"] = sorted(rep["findings"], key=finding_key)
    return out


class _Page(html.parser.HTMLParser):
    """Collects the tags (with attributes), the title, the h1 and the table rows of an HTML report. References are decoded exactly
    as ``html_escape`` writes them (``html.unescape`` would drop ESC and BEL, which the HTML standard does too)."""

    NAMED = {"amp": "&", "lt": "<", "gt": ">", "quot": '"'}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.tags: list = []
        self.title = ""
        self.h1 = ""
        self.tables: list = []
        self._row = None
        self._cell = None
        self._in = None
        self.text: list = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "table":
            self.tables.append([])
        elif tag == "tr":
            self._row = []
        elif tag in ("td", "th"):
            self._cell = [tag, dict(attrs).get("class"), ""]
        elif tag in ("title", "h1"):
            self._in = tag

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(tuple(self._cell))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.tables[-1].append(self._row)
            self._row = None
        elif tag in ("title", "h1"):
            self._in = None

    def handle_data(self, data):
        self.text.append(data)
        if self._cell is not None:
            self._cell[2] += data
        elif self._in == "title":
            self.title += data
        elif self._in == "h1":
            self.h1 += data

    def handle_charref(self, name):
        self.handle_data(chr(int(name[1:], 16)) if name[:1] in ("x", "X") else chr(int(name)))

    def handle_entityref(self, name):
        self.handle_data(self.NAMED[name])        # a KeyError here is the finding: html_escape writes only these four


def parse_page(markup: str) -> _Page:
    page = _Page()
    page.feed(markup)
    page.close()
    return page


def file_rows(page: _Page) -> dict:
    """path -> (status class, status text, message) of the 'results' table (the last table)."""
    rows = {}
    for row in page.tables[-1]:
        if row and row[0][0] == "th":
            continue
        rows[row[0][2]] = (row[1][1], row[1][2], row[2][2])
    return rows


# ── report_paths ───────────────────────────────────────────────────────────────────────────────────────────────────
class ReportPathsTests(unittest.TestCase):
    def test_one_argument_usage_goes_to_work_dir_reports(self):
        paths = make_paths("/b")
        self.assertEqual(paths.json, "/b/work/reports/report_20261113_010203.json")
        self.assertEqual(paths.html, "/b/work/reports/report_20261113_010203.html")
        self.assertEqual(paths.scan_name, "20261113_010203")

    def test_three_argument_usage_uses_report_dir_and_name(self):
        paths = make_paths("/b", report_dir="/out", name="nightly")
        self.assertEqual(paths.json, "/out/report_scan_nightly.json")
        self.assertEqual(paths.html, "/out/report_scan_nightly.html")
        self.assertEqual(paths.scan_name, "nightly")

    def test_sidecars_are_in_work_dir_never_in_the_report_dir(self):
        for kwargs in ({}, {"report_dir": "/out", "name": "n"}, {"report_dir": "/out"}):
            paths = make_paths("/b", **kwargs)
            self.assertEqual(paths.verdict_sidecar, "/b/work/.scan_verdict")
            self.assertEqual(paths.report_sidecar, "/b/work/.scan_report_json")

    def test_report_dir_without_a_name_uses_the_timestamp_as_the_name(self):
        paths = make_paths("/b", report_dir="/out")
        self.assertEqual(paths.json, "/out/report_scan_20261113_010203.json")
        self.assertEqual(paths.scan_name, "20261113_010203")

    def test_a_name_without_a_report_dir_is_stored_but_not_used_in_the_file_name(self):
        paths = make_paths("/b", name="nightly")
        self.assertEqual(paths.json, "/b/work/reports/report_20261113_010203.json")
        self.assertEqual(paths.scan_name, "nightly")

    def test_a_name_with_a_space_is_kept(self):
        paths = make_paths("/b", report_dir="/out", name="my scan")
        self.assertEqual(paths.json, "/out/report_scan_my scan.json")
        self.assertEqual(paths.html, "/out/report_scan_my scan.html")

    def test_a_relative_report_dir_stays_relative(self):
        paths = make_paths("/b", report_dir="rel/dir", name="n")
        self.assertEqual(paths.json, "rel/dir/report_scan_n.json")
        self.assertEqual(paths.html, "rel/dir/report_scan_n.html")

    def test_a_relative_work_dir_stays_relative(self):
        cfg = make_cfg("rel/work")
        paths = report.report_paths(cli.Args(scan_dir="/s", report_dir=None, scanning_name=None), cfg)
        self.assertEqual(paths.json, "rel/work/reports/report_20261113_010203.json")
        self.assertEqual(paths.verdict_sidecar, "rel/work/.scan_verdict")

    def test_the_path_is_constructed_as_bash_does_a_trailing_slash_is_not_removed(self):
        # bash: "${REPORT_DIR}/report_scan_${SCANNING_NAME}.json"; the sidecar names the path "as constructed" (contract 3.3)
        paths = make_paths("/b", report_dir="/out/", name="n")
        self.assertEqual(paths.json, "/out//report_scan_n.json")

    def test_the_html_has_the_stem_of_the_json(self):
        for kwargs in ({}, {"report_dir": "/out", "name": "n"}):
            paths = make_paths("/b", **kwargs)
            self.assertEqual(paths.html, paths.json[:-len(".json")] + ".html")

    def test_pure_path_arithmetic_creates_nothing(self):
        with tempfile.TemporaryDirectory(prefix="rp_") as tmp:
            before = sorted(os.listdir(tmp))
            paths = make_paths(tmp)
            self.assertEqual(sorted(os.listdir(tmp)), before)
            self.assertFalse(os.path.exists(os.path.join(tmp, "work")))
            self.assertTrue(paths.json.startswith(tmp))

    def test_report_paths_is_frozen(self):
        paths = make_paths("/b")
        with self.assertRaises(Exception):
            paths.json = "/x"  # type: ignore[misc]


# ── standards and the D-009 helper ─────────────────────────────────────────────────────────────────────────────────
class StandardsTests(unittest.TestCase):
    def test_standards_lists(self):
        head, tail = list(config.STANDARDS_HEAD), list(config.STANDARDS_TAIL)
        self.assertEqual(report.standards(False, False), head + tail)
        self.assertEqual(report.standards(True, False), head + ["SCA-CVE"] + tail)
        self.assertEqual(report.standards(False, True), head + ["ScanCode-Licence-Copyright"] + tail)
        self.assertEqual(report.standards(True, True), head + ["SCA-CVE", "ScanCode-Licence-Copyright"] + tail)

    def test_standards_equal_the_bash_writers_list(self):
        for sca in (False, True):
            for scancode in (False, True):
                old = run_old_writer(clean_snapshot(), run_sca=sca, run_scancode=scancode)
                self.assertEqual(report.standards(sca, scancode), old["standards"], (sca, scancode))

    def test_standards_returns_a_fresh_list(self):
        first = report.standards(False, False)
        first.append("x")
        self.assertNotIn("x", report.standards(False, False))


class MessageStripTests(unittest.TestCase):
    def test_the_trailing_separator_is_removed(self):
        self.assertEqual(report.message_for_file_results("[WARN] a | "), "[WARN] a")
        self.assertEqual(report.message_for_file_results("[WARN] a | [FAIL] b | "), "[WARN] a | [FAIL] b")
        self.assertEqual(report.message_for_file_results(""), "")

    def test_it_is_a_character_set_strip_as_in_bash_d009_copied(self):
        # rstrip(" | ") removes every trailing space and pipe, also those of the message text itself
        self.assertEqual(report.message_for_file_results("[WARN] x | | "), "[WARN] x")
        self.assertEqual(report.message_for_file_results("[WARN] x|| "), "[WARN] x")
        self.assertEqual(report.message_for_file_results("[WARN] a  "), "[WARN] a")
        self.assertEqual(report.message_for_file_results(" | | "), "")
        self.assertEqual(report.message_for_file_results("a|b | "), "a|b")

    def test_it_equals_the_bash_writer(self):
        messages = ["", "[WARN] a | ", "[WARN] x | | ", "[WARN] a|| ", "[FAIL] a | [WARN] b | ", "ends with pipe| | "]
        for message in messages:
            snap = make_snapshot("PASS", Counters(1, 0, 0), {SCAN + "/f": "WARN"}, {SCAN + "/f": message}, {}, (), CLEAN_COVERAGE)
            old = run_old_writer(snap)
            self.assertEqual(report.message_for_file_results(message), old["file_results"][SCAN + "/f"]["message"], message)


# ── build_report: the oracle, the shape, the invariants ────────────────────────────────────────────────────────────
class BuildReportOracleTests(unittest.TestCase):
    """build_report equals the old transit/report_json.py on the same inputs (order of the findings apart, D-024)."""

    def assert_equals_old(self, snap: Snapshot, **kwargs) -> dict:
        new = build(snap, **kwargs)
        old = run_old_writer(snap, **kwargs)
        self.assertEqual(without_findings_order(new), without_findings_order(old))
        return new

    def test_mixed_scenario(self):
        self.assert_equals_old(mixed_snapshot())

    def test_clean_scenario(self):
        new = self.assert_equals_old(clean_snapshot())
        self.assertEqual(new["verdict"], "PASS")

    def test_every_combination_of_the_optional_layers(self):
        for sca in (False, True):
            for scancode in (False, True):
                self.assert_equals_old(mixed_snapshot(), run_sca=sca, run_scancode=scancode)

    def test_scan_name_repo_input_and_hashes(self):
        self.assert_equals_old(mixed_snapshot(), scan_name="my scan", repo_input="https://github.com/org/repo",
                               source=files.SourceHashes(sha256="1" * 64, repo_hash="2" * 64))

    def test_hostile_but_valid_names_and_messages(self):
        names = ["<img src=x onerror=1>.py", 'q"uote\'.py', "new\nline.py", "raw\x1b]0;pwned\x07.txt", "back\\slash.py",
                 "tab\tname.py", "pipe | name.py", "café 日本.py", "rtl‮evil.py", " sep.py"]
        v = new_verdict()
        set_coverage(v, COVERAGE_SAMPLE)
        for i, name in enumerate(names):
            path = SCAN + "/" + name
            if i % 3 == 0:
                v.record_fail(path, "CWE-95:dynamic_code_execution_eval_exec")
            elif i % 3 == 1:
                v.record_warn(path, "bandit missing <b>x</b> | pipe")
            else:
                v.record_pass(path)
        self.assert_equals_old(v.snapshot())

    def test_one_invalid_byte_name_without_a_collision(self):
        v = new_verdict()
        set_coverage(v, CLEAN_COVERAGE)
        v.record_fail(SCAN + "/bad\udcffname.py", "CWE-95:dynamic_code_execution_eval_exec")
        v.record_pass(SCAN + "/ok.py")
        new = self.assert_equals_old(v.snapshot())
        self.assertIn(SCAN + "/bad�name.py", new["file_results"])

    def test_a_file_without_a_message_entry_has_the_empty_message(self):
        snap = make_snapshot("PASS", Counters(1, 0, 0), {SCAN + "/f": "PASS"}, {}, {}, (), CLEAN_COVERAGE)
        new = self.assert_equals_old(snap)
        self.assertEqual(new["file_results"][SCAN + "/f"], {"status": "PASS", "message": ""})

    def test_the_whole_directory_and_global_entries(self):
        v = new_verdict()
        set_coverage(v, COVERAGE_SAMPLE)
        v.record_fail(SCAN, "gitleaks:secrets_detected")
        v.record_fail("__global__", "engine:nothing_scanned:transitignore", downgradable=False)
        v.record_warn("__global__", "x")
        self.assert_equals_old(v.snapshot())


class BuildReportShapeTests(unittest.TestCase):
    def test_the_keys_are_exactly_those_of_the_schema_and_sorted(self):
        rep = build(mixed_snapshot())
        self.assertEqual(sorted(rep), sorted(SCHEMA["required"]))
        self.assertEqual(list(rep), sorted(rep))

    def test_nested_objects_are_sorted_too(self):
        rep = build(mixed_snapshot())
        for key in ("coverage", "findings_by_file", "file_results", "source", "summary"):
            self.assertEqual(list(rep[key]), sorted(rep[key]), key)
        for entry in rep["file_results"].values():
            self.assertEqual(list(entry), ["message", "status"])

    def test_verdict_decision_and_colours(self):
        rep = build(mixed_snapshot())
        self.assertEqual((rep["verdict"], rep["decision"], rep["status_color"], rep["status_background"]),
                         ("FAIL", "REJECTED", "#B02A37", "#F8D7DA"))
        rep = build(clean_snapshot())
        self.assertEqual((rep["verdict"], rep["decision"], rep["status_color"], rep["status_background"]),
                         ("PASS", "APPROVED", "#198754", "#D1E7DD"))

    def test_scalars_come_from_their_sources(self):
        rep = build(mixed_snapshot(), scan_name="nm", repo_input="repo-in",
                    source=files.SourceHashes(sha256="1" * 64, repo_hash="2" * 64))
        self.assertEqual(rep["scan_name"], "nm")
        self.assertEqual(rep["repo_input"], "repo-in")
        self.assertEqual(rep["source"], {"directory": SCAN, "sha256": "1" * 64})
        self.assertEqual(rep["directory"], SCAN)
        self.assertEqual(rep["repo_hash"], "2" * 64)

    def test_summary_is_the_event_counters(self):
        snap = mixed_snapshot()
        rep = build(snap)
        self.assertEqual(rep["summary"], {"pass": snap.counters.pass_, "warn": snap.counters.warn, "fail": snap.counters.fail})
        self.assertEqual(rep["summary"]["fail"], len(rep["findings"]))

    def test_timestamp_is_utc_with_second_resolution(self):
        self.assertEqual(build(clean_snapshot(), now_utc=dt.datetime(2026, 1, 2, 3, 4, 5, 999999))["timestamp"], "2026-01-02T03:04:05Z")
        aware = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone(dt.timedelta(hours=2)))
        self.assertEqual(build(clean_snapshot(), now_utc=aware)["timestamp"], "2026-01-02T01:04:05Z")

    def test_coverage_gaps_and_complete(self):
        rep = build(mixed_snapshot())
        self.assertEqual(rep["coverage"], COVERAGE_SAMPLE)
        self.assertEqual(rep["coverage_gaps"], sorted(k for k, v in COVERAGE_SAMPLE.items() if not v.startswith("ran")))
        self.assertIn("L2_owasp_cwe", rep["coverage_gaps"])           # partial: is a gap
        self.assertIn("L1_malware", rep["coverage_gaps"])             # skipped: is a gap
        self.assertNotIn("L4_patterns", rep["coverage_gaps"])
        self.assertFalse(rep["coverage_complete"])
        rep = build(clean_snapshot())
        self.assertEqual(rep["coverage_gaps"], [])
        self.assertTrue(rep["coverage_complete"])

    def test_one_gap_alone_makes_the_coverage_incomplete(self):
        coverage = dict(CLEAN_COVERAGE)
        coverage["L5_per_language_sast"] = "partial:file(1) is not installed"
        rep = build(mixed_snapshot(coverage))
        self.assertEqual(rep["coverage_gaps"], ["L5_per_language_sast"])
        self.assertFalse(rep["coverage_complete"])

    def test_findings_are_sorted_and_are_the_records_as_json(self):
        v = new_verdict()
        set_coverage(v, CLEAN_COVERAGE)
        v.record_fail(SCAN + "/z.py", "CWE-95:dynamic_code_execution_eval_exec")
        v.record_fail(SCAN + "/a.py", "CWE-798:hardcoded_credential_pattern:line9")
        v.record_fail(SCAN + "/a.py", "CWE-798:hardcoded_credential_pattern:line2")
        v.record_fail(SCAN + "/a.py", "CWE-22:path_traversal_encoded")
        v.record_fail(SCAN + "/a.py", "CWE-89:SQL_injection")
        snap = v.snapshot()
        rep = build(snap)
        keys = [finding_key(r) for r in rep["findings"]]
        self.assertEqual(keys, sorted(keys))
        self.assertNotEqual([r.message for r in snap.findings], [r["message"] for r in rep["findings"]])   # the input was not sorted
        self.assertEqual(sorted(json.dumps(r, sort_keys=True) for r in rep["findings"]),
                         sorted(json.dumps(r.to_json(), sort_keys=True) for r in snap.findings))
        self.assertEqual(len(rep["findings"]), snap.counters.fail)
        for rec in rep["findings"]:
            self.assertEqual(sorted(rec), sorted(["tool", "category", "severity", "rule_id", "rule_name", "file", "line", "column",
                                                  "message", "references"]))

    def test_a_missing_line_sorts_as_zero(self):
        v = new_verdict()
        set_coverage(v, CLEAN_COVERAGE)
        v.record_fail(SCAN + "/a.py", "CWE-798:hardcoded_credential_pattern:line1")
        v.record_fail(SCAN + "/a.py", "CWE-798:hardcoded_credential_pattern")
        rep = build(v.snapshot())
        self.assertEqual([r["line"] for r in rep["findings"]], [None, 1])

    def test_findings_by_file_has_no_trailing_separator(self):
        rep = build(mixed_snapshot())
        self.assertEqual(rep["findings_by_file"][SCAN + "/src/db.py"],
                         "CWE-89:SQL_injection | CWE-798:hardcoded_credential_pattern:line12")
        self.assertEqual(rep["findings_by_file"][SCAN + "/b.py"], "CWE-95:dynamic_code_execution_eval_exec")
        self.assertEqual(sorted(rep["findings_by_file"]), [SCAN + "/b.py", SCAN + "/src/db.py"])

    def test_file_results_messages(self):
        rep = build(mixed_snapshot())
        self.assertEqual(rep["file_results"][SCAN + "/src/db.py"],
                         {"status": "FAIL", "message": "[FAIL] CWE-89:SQL_injection | [FAIL] CWE-798:hardcoded_credential_pattern:line12"})
        self.assertEqual(rep["file_results"][SCAN + "/README.md"], {"status": "PASS", "message": ""})
        self.assertEqual(rep["file_results"][SCAN + "/src/app.py"], {"status": "PASS", "message": "[WARN] bandit missing"})
        self.assertEqual(rep["file_results"][SCAN + "/b.py"]["message"], "[FAIL] CWE-95:dynamic_code_execution_eval_exec | [WARN] bandit missing")
        self.assertEqual(rep["file_results"]["__global__"]["status"], "WARN")

    def test_d009_switch_removes_exactly_one_separator(self):
        snap = make_snapshot("PASS", Counters(0, 1, 0), {SCAN + "/f": "WARN"}, {SCAN + "/f": "[WARN] x | | "}, {}, (), CLEAN_COVERAGE)
        self.assertEqual(build(snap)["file_results"][SCAN + "/f"]["message"], "[WARN] x")          # copied from bash
        self.assertEqual(build(snap, fix_d009=True)["file_results"][SCAN + "/f"]["message"], "[WARN] x |")
        snap = make_snapshot("PASS", Counters(0, 1, 0), {SCAN + "/f": "WARN"}, {SCAN + "/f": "[WARN] a  | "}, {}, (), CLEAN_COVERAGE)
        self.assertEqual(build(snap, fix_d009=True)["file_results"][SCAN + "/f"]["message"], "[WARN] a ")
        snap = make_snapshot("PASS", Counters(1, 0, 0), {SCAN + "/f": "PASS"}, {SCAN + "/f": ""}, {}, (), CLEAN_COVERAGE)
        self.assertEqual(build(snap, fix_d009=True)["file_results"][SCAN + "/f"]["message"], "")

    def test_the_snapshot_is_not_changed(self):
        snap = mixed_snapshot()
        before = (dict(snap.file_status), dict(snap.file_message), dict(snap.fail_messages), snap.findings, dict(snap.coverage))
        build(snap)
        self.assertEqual(before, (dict(snap.file_status), dict(snap.file_message), dict(snap.fail_messages), snap.findings,
                                  dict(snap.coverage)))

    def test_the_result_is_a_plain_json_value(self):
        rep = build(mixed_snapshot())
        self.assertEqual(json.loads(json.dumps(rep)), rep)
        self.assertIs(type(rep["summary"]["pass"]), int)

    def test_the_report_conforms_to_the_schema_and_the_invariants(self):
        for snap in (mixed_snapshot(), clean_snapshot()):
            for sca in (False, True):
                self.assertEqual(conformance_errors(build(snap, run_sca=sca, run_scancode=sca)), [])


class StrictJsonTests(unittest.TestCase):
    """S4: every string goes through json_safe, so the JSON is always strict UTF-8."""

    def snapshot_with_invalid_bytes(self) -> Snapshot:
        v = new_verdict(SCAN + "\udcfe")
        set_coverage(v, CLEAN_COVERAGE)
        v.record_fail(SCAN + "\udcfe/dir\udcff/a\udcfe.py", "CWE-95:dynamic_code_execution_eval_exec on \udcfe")
        v.record_warn(SCAN + "\udcfe/b\udcff.py", "bandit \udcfe missing")
        v.record_warn("__global__", "global \udcff note")
        return v.snapshot()

    def test_no_lone_surrogate_survives_anywhere(self):
        rep = build(self.snapshot_with_invalid_bytes(), scan_dir=SCAN + "\udcfe", scan_name="n\udcfe", repo_input="r\udcff")
        data = json.dumps(rep, ensure_ascii=False)
        data.encode("utf-8")                                  # strict: raises on a lone surrogate
        self.assertNotRegex(data, "[\ud800-\udfff]")
        self.assertIn(SCAN + "�/dir�/a�.py", rep["file_results"])
        self.assertEqual(rep["directory"], SCAN + "�")
        self.assertEqual(rep["source"]["directory"], SCAN + "�")
        self.assertEqual(rep["scan_name"], "n�")
        self.assertEqual(rep["repo_input"], "r�")
        self.assertEqual(rep["findings"][0]["file"], "dir�/a�.py")
        self.assertIn("on �", rep["findings"][0]["message"])
        self.assertEqual(conformance_errors(rep), [])

    def test_the_text_matches_json_safe(self):
        rep = build(self.snapshot_with_invalid_bytes(), scan_dir=SCAN + "\udcfe")
        self.assertIn(json_safe(SCAN + "\udcfe/b\udcff.py"), rep["file_results"])
        self.assertEqual(rep["file_results"]["__global__"]["message"], "[WARN] global � note")

    def test_control_characters_are_json_escaped_in_the_written_text(self):
        v = new_verdict()
        set_coverage(v, CLEAN_COVERAGE)
        v.record_fail(SCAN + "/raw\x1b]0;pwned\x07.txt", "CWE-95:dynamic_code_execution_eval_exec")
        text = json.dumps(build(v.snapshot()), ensure_ascii=False, indent=2)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\u001b", text)


class CollisionTests(unittest.TestCase):
    """R-12 / D-045: two names that map to one key after json_safe are merged, never overwritten."""

    A = SCAN + "/x\udcfe.py"
    B = SCAN + "/x\udcff.py"
    KEY = SCAN + "/x�.py"

    def snap(self, first, second) -> Snapshot:
        v = new_verdict()
        set_coverage(v, CLEAN_COVERAGE)
        for path, action in (first, second):
            action(v, path)
        return v.snapshot()

    @staticmethod
    def fail(message="CWE-95:dynamic_code_execution_eval_exec"):
        return lambda v, p: v.record_fail(p, message)

    @staticmethod
    def passed():
        return lambda v, p: v.record_pass(p)

    @staticmethod
    def warn(message="bandit missing"):
        return lambda v, p: v.record_warn(p, message)

    def test_a_clean_file_cannot_overwrite_the_fail_whatever_the_order(self):
        for first, second in (((self.A, self.fail()), (self.B, self.passed())),
                              ((self.A, self.passed()), (self.B, self.fail())),
                              ((self.B, self.fail()), (self.A, self.passed())),
                              ((self.B, self.passed()), (self.A, self.fail()))):
            rep = build(self.snap(first, second))
            self.assertEqual(rep["file_results"][self.KEY]["status"], "FAIL", (first, second))
            self.assertIn("[FAIL] CWE-95:dynamic_code_execution_eval_exec", rep["file_results"][self.KEY]["message"])
            self.assertEqual(rep["findings_by_file"][self.KEY], "CWE-95:dynamic_code_execution_eval_exec")
            self.assertEqual(rep["summary"]["fail"], 1)
            self.assertEqual(len(rep["findings"]), 1)
            self.assertEqual(conformance_errors(rep), [], (first, second))

    def test_a_fail_beats_a_warn_and_a_warn_beats_a_pass(self):
        rep = build(self.snap((self.A, self.warn()), (self.B, self.fail())))
        self.assertEqual(rep["file_results"][self.KEY]["status"], "FAIL")
        rep = build(self.snap((self.A, self.passed()), (self.B, self.warn())))
        self.assertEqual(rep["file_results"][self.KEY]["status"], "WARN")
        rep = build(self.snap((self.B, self.warn()), (self.A, self.passed())))
        self.assertEqual(rep["file_results"][self.KEY]["status"], "WARN")
        rep = build(self.snap((self.A, self.passed()), (self.B, self.passed())))
        self.assertEqual(rep["file_results"][self.KEY], {"status": "PASS", "message": ""})
        self.assertEqual(conformance_errors(rep), [])

    def test_the_messages_of_both_are_kept_in_snapshot_order(self):
        rep = build(self.snap((self.A, self.warn("first note")), (self.B, self.warn("second note"))))
        self.assertEqual(rep["file_results"][self.KEY]["message"], "[WARN] first note | [WARN] second note")
        rep = build(self.snap((self.B, self.warn("second note")), (self.A, self.warn("first note"))))
        self.assertEqual(rep["file_results"][self.KEY]["message"], "[WARN] second note | [WARN] first note")

    def test_two_fails_keep_both_messages_and_both_records(self):
        snap = self.snap((self.A, self.fail("CWE-95:dynamic_code_execution_eval_exec")),
                         (self.B, self.fail("CWE-89:SQL_injection")))
        rep = build(snap)
        self.assertEqual(rep["findings_by_file"][self.KEY], "CWE-95:dynamic_code_execution_eval_exec | CWE-89:SQL_injection")
        self.assertEqual(rep["file_results"][self.KEY],
                         {"status": "FAIL", "message": "[FAIL] CWE-95:dynamic_code_execution_eval_exec | [FAIL] CWE-89:SQL_injection"})
        self.assertEqual(len(rep["findings"]), 2)
        self.assertEqual({r["file"] for r in rep["findings"]}, {"x�.py"})
        self.assertEqual(rep["summary"]["fail"], 2)               # event counters do not change
        self.assertEqual(conformance_errors(rep), [])

    def test_the_other_entries_are_untouched(self):
        v = new_verdict()
        set_coverage(v, CLEAN_COVERAGE)
        v.record_pass(SCAN + "/ok.py")
        v.record_fail(self.A, "CWE-95:dynamic_code_execution_eval_exec")
        v.record_pass(self.B)
        rep = build(v.snapshot())
        self.assertEqual(sorted(rep["file_results"]), sorted([SCAN + "/ok.py", self.KEY]))
        self.assertEqual(rep["file_results"][SCAN + "/ok.py"], {"status": "PASS", "message": ""})

    def test_a_directory_collision_merges_in_the_same_way(self):
        v = new_verdict()
        set_coverage(v, CLEAN_COVERAGE)
        v.record_fail(SCAN + "/d\udcfe/a.py", "CWE-95:dynamic_code_execution_eval_exec")
        v.record_pass(SCAN + "/d\udcff/a.py")
        rep = build(v.snapshot())
        self.assertEqual(rep["file_results"][SCAN + "/d�/a.py"]["status"], "FAIL")
        self.assertEqual(conformance_errors(rep), [])

    def test_the_checkers_invariant_findings_by_file_keys_are_fail_files(self):
        rep = build(self.snap((self.A, self.fail()), (self.B, self.passed())))
        for key in rep["findings_by_file"]:
            self.assertEqual(rep["file_results"][key]["status"], "FAIL")


class GoldenReplayTests(unittest.TestCase):
    """Rebuild a Snapshot from each golden report (the shape the bash engine produced), build_report it again, compare."""

    @staticmethod
    def pieces(text: str) -> list:
        return sorted(p.strip() for p in (text or "").split(" | ") if p.strip())

    @staticmethod
    def snapshot_from_golden(rep: dict) -> Snapshot:
        def key(k: str) -> str:
            return k if k == "__global__" else SCAN if k == "." else SCAN + "/" + k

        status, message, fail = {}, {}, {}
        for k, entry in rep["file_results"].items():
            status[key(k)] = entry["status"]
            parts = entry["messages"]
            message[key(k)] = "".join(p + " | " for p in parts)
        for k, parts in rep["findings_by_file"].items():
            fail[key(k)] = "".join(p + " | " for p in parts)
        records = tuple(FindingRecord(tool=r["tool"], category=r["category"], severity=r["severity"], rule_id=r["rule_id"],
                                      rule_name=r["rule_name"], file=r["file"], line=r["line"], column=None, message=r["message"],
                                      references=tuple(r["references"])) for r in rep["findings"])
        s = rep["summary"]
        return make_snapshot(rep["verdict"], Counters(s["pass"], s["warn"], s["fail"]), status, message, fail, records,
                             rep["coverage"])

    def normalised(self, rep: dict) -> dict:
        def rel(k):
            return k if k == "__global__" else "." if k == SCAN else k[len(SCAN) + 1:] if k.startswith(SCAN + "/") else k

        return {
            "verdict": rep["verdict"], "decision": rep["decision"], "colours": (rep["status_color"], rep["status_background"]),
            "scan_name": rep["scan_name"], "sha256": rep["source"]["sha256"], "coverage": rep["coverage"],
            "gaps": sorted(rep["coverage_gaps"]), "complete": rep["coverage_complete"], "standards": set(rep["standards"]),
            "summary": rep["summary"],
            "file_results": {rel(k): (v["status"], self.pieces(v["message"])) for k, v in rep["file_results"].items()},
            "findings_by_file": {rel(k): self.pieces(v) for k, v in rep["findings_by_file"].items()},
            "findings": sorted(({f: r[f] for f in ("tool", "category", "severity", "rule_id", "rule_name", "file", "line",
                                                   "message", "references")} for r in rep["findings"]), key=finding_key,
                               )}

    def test_every_golden_report_is_reproduced(self):
        names = sorted(p.name for p in GOLDEN.glob("*.json"))
        self.assertGreaterEqual(len(names), 20)
        replayed = 0
        for name in names:
            golden = json.loads((GOLDEN / name).read_text(encoding="utf-8"))
            gold = golden.get("report")
            if not gold:
                continue
            replayed += 1
            standards = set(gold["standards"])
            built = build(self.snapshot_from_golden(gold), scan_name=gold["scan_name"],
                          source=files.SourceHashes(sha256=gold["source"]["sha256"], repo_hash=HASH_B),
                          run_sca="SCA-CVE" in standards, run_scancode="ScanCode-Licence-Copyright" in standards)
            self.assertEqual(self.normalised(built), self.normalised(self.golden_with_message(gold)), name)
            self.assertEqual(conformance_errors(built), [], name)
        self.assertGreaterEqual(replayed, 20)

    def golden_with_message(self, gold: dict) -> dict:
        """The golden file stores the pieces; give them back the shape of a raw report so that both sides are normalised alike."""
        out = dict(gold)
        out["file_results"] = {k: {"status": v["status"], "message": " | ".join(v["messages"])}
                               for k, v in gold["file_results"].items()}
        out["findings_by_file"] = {k: " | ".join(v) for k, v in gold["findings_by_file"].items()}
        return out


# ── html_escape and render_html ────────────────────────────────────────────────────────────────────────────────────
def bash_html_esc(text: str) -> str | None:
    """The bash function _html_esc of scan_pipeline.sh, run on ``text`` (None when it cannot be extracted or bash is missing)."""
    bash = shutil.which("bash")
    if not bash:
        return None
    lines = (ROOT / "scan_pipeline.sh").read_text(encoding="utf-8").splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("_html_esc() {")), None)
    if start is None:
        return None
    end = next(i for i in range(start, len(lines)) if lines[i] == "}")
    script = "\n".join(lines[start:end + 1]) + '\n_html_esc "$1"\nprintf %s "$ESC"\n'
    proc = subprocess.run([bash, "-c", script, "_", text], capture_output=True, env={"PATH": os.environ.get("PATH", ""),
                                                                                        "LC_ALL": "C.UTF-8"}, timeout=30)
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8")


class HtmlEscapeTests(unittest.TestCase):
    def test_the_five_markup_characters(self):
        self.assertEqual(report.html_escape("&"), "&amp;")
        self.assertEqual(report.html_escape("<"), "&lt;")
        self.assertEqual(report.html_escape(">"), "&gt;")
        self.assertEqual(report.html_escape('"'), "&quot;")
        self.assertEqual(report.html_escape("'"), "&#39;")
        self.assertEqual(report.html_escape("<img src=x onerror=1>"), "&lt;img src=x onerror=1&gt;")

    def test_ampersand_is_escaped_first_nothing_is_escaped_twice(self):
        self.assertEqual(report.html_escape("&lt;"), "&amp;lt;")
        self.assertEqual(report.html_escape("&amp;"), "&amp;amp;")
        self.assertEqual(report.html_escape("&#39;"), "&amp;#39;")
        self.assertEqual(report.html_escape("a&b<c"), "a&amp;b&lt;c")
        self.assertEqual(report.html_escape("'&'"), "&#39;&amp;&#39;")

    def test_plain_text_is_unchanged(self):
        for text in ("", "plain.py", "src/app.py", "café 日本", "emoji \U0001F600", "�", "back\\slash",
                     r"literal \033 text", "a b", "a|b", "~!@#$%^*()_+-=[]{};:,./?`"):
            self.assertEqual(report.html_escape(text), text)

    def test_every_c0_control_tab_and_lf_included_is_a_character_reference(self):
        for code in range(0x20):
            self.assertEqual(report.html_escape(chr(code)), "&#x%02X;" % code, code)
        self.assertEqual(report.html_escape("a\nb\tc"), "a&#x0A;b&#x09;c")
        self.assertEqual(report.html_escape("\x1b]0;x\x07"), "&#x1B;]0;x&#x07;")
        self.assertEqual(report.html_escape("\r\n"), "&#x0D;&#x0A;")

    def test_del_and_every_c1_control(self):
        self.assertEqual(report.html_escape("\x7f"), "&#x7F;")
        for code in range(0x80, 0xA0):
            self.assertEqual(report.html_escape(chr(code)), "&#x%02X;" % code, code)
        self.assertEqual(report.html_escape("\u009b"), "&#x9B;")
        self.assertEqual(report.html_escape(" "), " ")      # NBSP is not a control

    def test_every_bidi_control_is_a_character_reference(self):
        expected = [0x061C, 0x200E, 0x200F] + list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
        self.assertEqual(sorted(ord(c) for c in console.BIDI_CONTROLS), sorted(expected))
        for code in expected:
            self.assertEqual(report.html_escape(chr(code)), "&#x%04X;" % code, hex(code))
        self.assertEqual(report.html_escape("invoice‮txt.exe"), "invoice&#x202E;txt.exe")
        self.assertEqual(report.html_escape("‮x"), "&#x202E;x")

    def test_the_bidi_set_is_read_from_the_console_module(self):
        # report must follow console.BIDI_CONTROLS and not keep a copy of its own: every member of the set is covered
        for ch in console.BIDI_CONTROLS:
            self.assertNotIn(ch, report.html_escape("a" + ch + "b"))

    def test_lone_surrogates_become_u_fffd(self):
        self.assertEqual(report.html_escape("a\udcffb"), "a�b")
        self.assertEqual(report.html_escape("\udcfe\udcff"), "��")
        self.assertEqual(report.html_escape("\ud800"), "�")

    def test_nothing_dangerous_survives_for_any_code_point(self):
        everything = "".join(map(chr, range(0x110000)))
        out = report.html_escape(everything)
        bad = [c for c in set(out) if ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F or c in console.BIDI_CONTROLS
               or 0xD800 <= ord(c) <= 0xDFFF or c in "<>\"'"]
        self.assertEqual(bad, [])
        # '&' only ever starts a reference
        self.assertNotRegex(out, "&(?!(amp|lt|gt|quot|#39|#x[0-9A-F]{2,4});)")

    def test_it_equals_the_bash_html_esc_on_printable_text(self):
        samples = ["", "plain", "<img src=x onerror=1>.py", "a&b", "&amp;", "&lt;&gt;", "&#39;", "'\"<>&", "&&&", "x'y\"z",
                   "back\\slash", "\\'", "<a href=\"x\">&nbsp;</a>", "café 日本", "a b  c", "&amp;amp;", "100%",
                   "${HOME}", "$(x)", "`x`", "a\\&b"]
        for sample in samples:
            expected = bash_html_esc(sample)
            if expected is None:
                self.skipTest("bash or _html_esc not available")
            self.assertEqual(report.html_escape(sample), expected, sample)

    def test_a_str_subclass_cannot_change_the_result(self):
        class Sneaky(str):
            def translate(self, table):  # noqa: D401
                return "SNEAKY"

            def replace(self, *args):
                return "SNEAKY"

        self.assertEqual(report.html_escape(Sneaky("<x>")), "&lt;x&gt;")


def hostile_report() -> dict:
    """A report whose file names, messages and directory are hostile (the two S3 names of the contract and more)."""
    scan = SCAN + "/<b>dir</b>"
    v = new_verdict(scan)
    set_coverage(v, COVERAGE_SAMPLE)
    names = ["<img src=x onerror=1>.py", "\"><script>alert(1)</script>.js", "a'b\"c&d.py", "invoice‮txt.exe",
             "line\nbreak.txt", "raw\x1b]0;pwned\x07.txt", "⁦iso⁩.py", "x</td><td class=pass>PASS.py"]
    for i, name in enumerate(names):
        path = scan + "/" + name
        if i % 2 == 0:
            v.record_fail(path, "CWE-95:dynamic_code_execution_eval_exec <script>alert(1)</script>")
        else:
            v.record_warn(path, "bandit missing <iframe src=//evil></iframe> & more")
    v.record_warn("__global__", "global <b>note</b>")
    snap = v.snapshot()
    return build(snap, scan_dir=scan)


class RenderHtmlTests(unittest.TestCase):
    def render(self, rep=None, ts="20261113_123456") -> str:
        return report.render_html(rep if rep is not None else build(mixed_snapshot()), timestamp_local=ts)

    def test_title_h1_directory_and_counters(self):
        rep = build(mixed_snapshot())
        page = parse_page(self.render(rep))
        self.assertEqual(page.title, "AI Transit Report - 20261113_123456")
        self.assertEqual(page.h1, "Verdict: FAIL")
        text = "".join(page.text)
        self.assertIn(SCAN, text)
        self.assertIn("20261113_123456", text)
        counters = rep["summary"]
        spans = {a.get("class"): None for tag, a in page.tags if tag == "span"}
        self.assertTrue({"pass", "warn", "fail"} <= set(spans))
        for label, n in (("PASS", counters["pass"]), ("WARN", counters["warn"]), ("FAIL", counters["fail"])):
            self.assertIn("%s: " % label, text)
            self.assertIn(str(n), text)

    def test_pass_verdict(self):
        page = parse_page(self.render(build(clean_snapshot())))
        self.assertEqual(page.h1, "Verdict: PASS")

    def test_one_row_for_every_file_results_entry(self):
        rep = build(mixed_snapshot())
        page = parse_page(self.render(rep))
        rows = file_rows(page)
        self.assertEqual(sorted(rows), sorted(rep["file_results"]))
        self.assertEqual(len(page.tables[-1]) - 1, len(rep["file_results"]))          # one header row
        for path, entry in rep["file_results"].items():
            cls, status, message = rows[path]
            self.assertEqual(status, entry["status"])
            self.assertEqual(cls, entry["status"].lower())
            self.assertEqual(message, entry["message"])

    def test_pass_rows_are_listed_too(self):
        rep = build(clean_snapshot())
        rows = file_rows(parse_page(self.render(rep)))
        self.assertEqual(rows[SCAN + "/README.md"][:2], ("pass", "PASS"))
        self.assertEqual(len(rows), len(rep["file_results"]))

    def test_the_coverage_table_lists_every_layer_with_its_state(self):
        rep = build(mixed_snapshot())
        page = parse_page(self.render(rep))
        coverage = {row[0][2]: row[1][2] for row in page.tables[0] if row[0][0] != "th"}
        self.assertEqual(coverage, rep["coverage"])

    def test_the_file_table_is_in_sorted_order(self):
        rep = build(mixed_snapshot())
        paths = [row[0][2] for row in parse_page(self.render(rep)).tables[-1] if row[0][0] != "th"]
        self.assertEqual(paths, sorted(rep["file_results"]))

    def test_no_script_and_no_external_resource(self):
        for rep in (build(mixed_snapshot()), build(clean_snapshot())):
            out = self.render(rep)
            low = out.lower()
            for forbidden in ("<script", "<link", "<img", "<iframe", "<object", "<embed", "<form", "<a ", "src=", "href=",
                              "url(", "@import", "javascript:"):
                self.assertNotIn(forbidden, low, forbidden)
            for tag, attrs in parse_page(out).tags:
                self.assertFalse([a for a in attrs if a.startswith("on")], (tag, attrs))

    def test_hostile_names_are_escaped_s3(self):
        rep = hostile_report()
        out = self.render(rep)
        low = out.lower()
        for raw in ("<img", "<script", "<iframe", "</td><td class=pass>", "<b>dir</b>", "<b>note</b>", "onerror=1>"):
            self.assertNotIn(raw, low, raw)
        self.assertIn("&lt;img src=x onerror=1&gt;.py", out)
        self.assertIn("&lt;b&gt;dir&lt;/b&gt;", out)
        self.assertIn("a&#39;b&quot;c&amp;d.py", out)
        page = parse_page(out)
        tags = {tag for tag, _ in page.tags}
        self.assertEqual(tags - {"html", "head", "meta", "title", "style", "body", "h1", "h2", "p", "code", "span", "table",
                                 "tr", "th", "td"}, set())
        for tag, attrs in page.tags:
            if tag in ("td", "th", "span", "html"):
                self.assertTrue(set(attrs) <= {"class", "lang"}, (tag, attrs))
                self.assertTrue(all(v in (None, "pass", "warn", "fail", "ran", "tag", "owasp", "cwe", "cert", "en") for v in attrs.values()),
                                (tag, attrs))

    def test_the_escaping_is_lossless_for_the_hostile_names(self):
        rep = hostile_report()
        rows = file_rows(parse_page(self.render(rep)))
        self.assertEqual(sorted(rows), sorted(rep["file_results"]))
        for path, entry in rep["file_results"].items():
            self.assertEqual(rows[path][2], entry["message"])

    def test_a_u202e_name_is_written_as_a_character_reference_r14(self):
        out = self.render(hostile_report())
        self.assertIn("invoice&#x202E;txt.exe", out)
        self.assertNotIn("‮", out)
        self.assertNotIn("⁦", out)
        self.assertIn("&#x2066;iso&#x2069;.py", out)

    def test_no_raw_control_character_is_written(self):
        out = self.render(hostile_report())
        bad = [c for c in set(out) if (ord(c) < 0x20 and c != "\n") or 0x7F <= ord(c) <= 0x9F or c in console.BIDI_CONTROLS]
        self.assertEqual(bad, [])
        self.assertIn("line&#x0A;break.txt", out)
        self.assertIn("raw&#x1B;]0;pwned&#x07;.txt", out)

    def test_every_interpolated_value_is_escaped(self):
        rep = build(clean_snapshot())
        rep["verdict"] = "PASS<i>"
        rep["directory"] = "/d<i>"
        rep["source"] = {"directory": "/d<i>", "sha256": HASH_A}
        rep["summary"] = {"pass": "1<i>", "warn": "2<i>", "fail": "3<i>"}
        rep["coverage"] = {"L4<i>": "ran<i>"}
        rep["file_results"] = {"/d<i>/p<i>": {"status": "FAIL<i>", "message": "m<i>"}}
        rep["standards"] = ["S<i>"]
        out = report.render_html(rep, timestamp_local="ts<i>")
        self.assertNotIn("<i>", out)
        for fragment in ("PASS&lt;i&gt;", "/d&lt;i&gt;", "1&lt;i&gt;", "2&lt;i&gt;", "3&lt;i&gt;", "L4&lt;i&gt;", "ran&lt;i&gt;",
                         "p&lt;i&gt;", "FAIL&lt;i&gt;", "m&lt;i&gt;", "ts&lt;i&gt;", "S&lt;i&gt;"):
            self.assertIn(fragment, out)

    def test_a_status_outside_the_vocabulary_cannot_become_a_class(self):
        rep = build(clean_snapshot())
        rep["file_results"] = {SCAN + "/f": {"status": "x' onclick='alert(1)", "message": ""}}
        out = report.render_html(rep, timestamp_local="t")
        for tag, attrs in parse_page(out).tags:
            self.assertFalse([a for a in attrs if a.startswith("on")], (tag, attrs))
        self.assertIn("x&#39; onclick=&#39;alert(1)", out)

    def test_colours_come_from_the_verdict_not_from_the_report_dict(self):
        rep = build(clean_snapshot())
        rep["status_color"] = "red;}</style><script>alert(1)</script>"
        rep["status_background"] = "x"
        out = report.render_html(rep, timestamp_local="t")
        self.assertNotIn("alert(1)", out)
        self.assertNotIn("</style><script>", out)

    def test_a_report_with_missing_parts_still_renders(self):
        out = report.render_html({"verdict": "FAIL"}, timestamp_local="t")
        self.assertEqual(parse_page(out).h1, "Verdict: FAIL")

    def test_a_large_report_is_rendered_quickly(self):
        rep = build(clean_snapshot())
        rep["file_results"] = {"%s/f%06d.py" % (SCAN, i): {"status": "PASS", "message": ""} for i in range(60000)}
        started = dt.datetime.now()
        out = report.render_html(rep, timestamp_local="t")
        self.assertLess((dt.datetime.now() - started).total_seconds(), 10)
        self.assertEqual(out.count("<tr>") - 1 - len(rep["coverage"]) - 1, 60000)


# ── write_atomic ───────────────────────────────────────────────────────────────────────────────────────────────────
class WriteAtomicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wa_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, "out.json")

    def test_writes_the_bytes(self):
        report.write_atomic(self.path, b"hello\n")
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), b"hello\n")
        self.assertEqual(os.listdir(self.tmp), ["out.json"])          # no temporary file is left

    def test_writes_an_empty_file(self):
        report.write_atomic(self.path, b"")
        self.assertEqual(os.path.getsize(self.path), 0)

    def test_the_mode_is_requested_mode_and_not_umask(self):
        for mask, mode, expected in ((0o022, 0o666, 0o644), (0o077, 0o666, 0o600), (0o000, 0o666, 0o666), (0o022, 0o600, 0o600),
                                     (0o077, 0o640, 0o600), (0o022, 0o777, 0o755)):
            with umask(mask):
                report.write_atomic(self.path, b"x", mode=mode)
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), expected, (oct(mask), oct(mode)))
            os.remove(self.path)

    def test_default_mode_is_0666_minus_umask(self):
        with umask(0o022):
            report.write_atomic(self.path, b"x")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)

    def test_replaces_an_existing_file_without_a_message(self):
        with open(self.path, "wb") as fh:
            fh.write(b"old content that is longer than the new one")
        old_inode = os.stat(self.path).st_ino
        report.write_atomic(self.path, b"new")
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), b"new")
        self.assertNotEqual(os.stat(self.path).st_ino, old_inode)      # a new file was renamed into place

    def test_the_temporary_file_is_in_the_same_directory_complete_and_unpredictable(self):
        with spy_replace() as calls:
            report.write_atomic(self.path, b"payload-1")
            report.write_atomic(self.path, b"payload-2")
        self.assertEqual(len(calls), 2)
        for call, payload in zip(calls, (b"payload-1", b"payload-2")):
            self.assertEqual(os.path.dirname(call["src"]), self.tmp)
            self.assertEqual(call["dst"], self.path)
            self.assertEqual(call["src_content"], payload)             # complete before it is renamed into place
            self.assertNotEqual(call["src"], self.path)
        self.assertNotEqual(calls[0]["src"], calls[1]["src"])
        self.assertEqual(calls[1]["dst_before"], b"payload-1")         # the old report is whole until the rename

    def test_the_temporary_file_is_private_until_the_end_and_has_the_final_mode_at_the_rename(self):
        with umask(0o022), spy_replace() as calls:
            report.write_atomic(self.path, b"x", mode=0o666)
        self.assertEqual(calls[0]["src_mode"], 0o644)

    def test_a_failing_replace_leaves_the_old_file_and_no_temporary_file(self):
        report.write_atomic(self.path, b"OLD")
        with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                report.write_atomic(self.path, b"NEW")
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), b"OLD")
        self.assertEqual(os.listdir(self.tmp), ["out.json"])

    def test_a_failing_replace_creates_no_file_where_there_was_none(self):
        with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                report.write_atomic(self.path, b"NEW")
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_failing_fsync_leaves_no_partial_file(self):
        with mock.patch("os.fsync", side_effect=OSError(5, "I/O error")):
            with self.assertRaises(OSError):
                report.write_atomic(self.path, b"NEW")
        self.assertEqual(os.listdir(self.tmp), [])

    def test_the_data_is_synced_before_the_rename(self):
        order: list = []
        real_fsync, real_replace = os.fsync, os.replace
        with mock.patch("os.fsync", lambda fd: (order.append("fsync"), real_fsync(fd))[1]), \
                mock.patch("os.replace", lambda a, b: (order.append("replace"), real_replace(a, b))[1]):
            report.write_atomic(self.path, b"x")
        self.assertIn("fsync", order)
        self.assertLess(order.index("fsync"), order.index("replace"))

    def test_a_missing_directory_raises_and_creates_nothing(self):
        target = os.path.join(self.tmp, "no", "such", "dir", "out.json")
        with self.assertRaises(OSError):
            report.write_atomic(target, b"x")
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_directory_in_the_way_raises_and_leaves_no_temporary_file(self):
        os.mkdir(self.path)
        with self.assertRaises(OSError):
            report.write_atomic(self.path, b"x")
        self.assertEqual(os.listdir(self.tmp), ["out.json"])
        self.assertTrue(os.path.isdir(self.path))

    def test_not_bytes_is_refused_and_creates_nothing(self):
        with self.assertRaises(TypeError):
            report.write_atomic(self.path, "text")          # type: ignore[arg-type]
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_symlink_at_the_target_is_replaced_not_followed(self):
        victim = os.path.join(self.tmp, "victim")
        with open(victim, "wb") as fh:
            fh.write(b"keep")
        os.symlink(victim, self.path)
        report.write_atomic(self.path, b"new")
        with open(victim, "rb") as fh:
            self.assertEqual(fh.read(), b"keep")
        self.assertFalse(os.path.islink(self.path))
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), b"new")

    def test_a_relative_path_without_a_directory_part(self):
        old = os.getcwd()
        os.chdir(self.tmp)
        try:
            report.write_atomic("rel.json", b"x")
        finally:
            os.chdir(old)
        self.assertEqual(sorted(os.listdir(self.tmp)), ["rel.json"])

    def test_a_large_payload_is_written_whole(self):
        data = bytes(range(256)) * 40000
        report.write_atomic(self.path, data)
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), data)

    def test_a_non_utf8_file_name(self):
        path = os.path.join(self.tmp, "r\udcffep.json")
        report.write_atomic(path, b"x")
        self.assertEqual(os.listdir(self.tmp), [os.fsdecode(b"r\xffep.json")])


# ── write_reports ──────────────────────────────────────────────────────────────────────────────────────────────────
class WriteReportsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wr_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.mkdir(os.path.join(self.tmp, "out"))
        self.paths = report.ReportPaths(json=os.path.join(self.tmp, "out", "report_scan_n.json"),
                                        html=os.path.join(self.tmp, "out", "report_scan_n.html"), scan_name="n",
                                        verdict_sidecar=os.path.join(self.tmp, ".scan_verdict"),
                                        report_sidecar=os.path.join(self.tmp, ".scan_report_json"))

    def test_both_files_are_written(self):
        rep = build(mixed_snapshot())
        report.write_reports(rep, self.paths, timestamp_local="20261113_123456")
        raw = Path(self.paths.json).read_bytes()
        self.assertEqual(json.loads(raw.decode("utf-8")), rep)
        self.assertTrue(raw.endswith(b"}\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        html_text = Path(self.paths.html).read_text(encoding="utf-8")
        self.assertTrue(html_text.startswith("<!DOCTYPE html>"))
        self.assertEqual(html_text, report.render_html(rep, timestamp_local="20261113_123456"))
        self.assertEqual(sorted(os.listdir(os.path.join(self.tmp, "out"))), ["report_scan_n.html", "report_scan_n.json"])

    def test_the_json_is_indented_by_two_and_not_ascii_escaped(self):
        v = new_verdict()
        set_coverage(v, CLEAN_COVERAGE)
        v.record_warn(SCAN + "/café.py", "note — x")
        rep = build(v.snapshot())
        report.write_reports(rep, self.paths, timestamp_local="t")
        raw = Path(self.paths.json).read_bytes().decode("utf-8")
        self.assertEqual(raw, json.dumps(rep, ensure_ascii=False, indent=2) + "\n")
        self.assertIn("café.py", raw)
        self.assertIn("\n  \"", raw)

    def test_json_first_then_html(self):
        with spy_replace() as calls:
            report.write_reports(build(clean_snapshot()), self.paths, timestamp_local="t")
        self.assertEqual([c["dst"] for c in calls], [self.paths.json, self.paths.html])

    def test_existing_reports_are_replaced_without_a_message(self):
        Path(self.paths.json).write_bytes(b"old json")
        Path(self.paths.html).write_bytes(b"old html")
        report.write_reports(build(clean_snapshot()), self.paths, timestamp_local="t")
        self.assertNotEqual(Path(self.paths.json).read_bytes(), b"old json")
        self.assertNotEqual(Path(self.paths.html).read_bytes(), b"old html")

    def test_nothing_is_written_when_the_json_cannot_be_encoded(self):
        rep = build(clean_snapshot())
        rep["repo_input"] = "lone \udcff surrogate"        # json_safe was bypassed: strict UTF-8 must refuse, and write nothing
        with self.assertRaises(UnicodeEncodeError):
            report.write_reports(rep, self.paths, timestamp_local="t")
        self.assertEqual(os.listdir(os.path.join(self.tmp, "out")), [])

    def test_a_failing_json_write_leaves_no_html_and_no_partial_json(self):
        with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                report.write_reports(build(clean_snapshot()), self.paths, timestamp_local="t")
        self.assertEqual(os.listdir(os.path.join(self.tmp, "out")), [])

    def test_the_report_files_follow_the_umask(self):
        with umask(0o027):
            report.write_reports(build(clean_snapshot()), self.paths, timestamp_local="t")
        self.assertEqual(stat.S_IMODE(os.stat(self.paths.json).st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(os.stat(self.paths.html).st_mode), 0o640)

    def test_the_report_argument_is_not_changed(self):
        rep = build(mixed_snapshot())
        before = json.dumps(rep, sort_keys=True)
        report.write_reports(rep, self.paths, timestamp_local="t")
        self.assertEqual(json.dumps(rep, sort_keys=True), before)

    def test_hostile_names_end_up_as_strict_utf8_json_and_escaped_html(self):
        rep = hostile_report()
        report.write_reports(rep, self.paths, timestamp_local="t")
        loaded = json.loads(Path(self.paths.json).read_bytes().decode("utf-8"))      # strict decode
        self.assertEqual(loaded, rep)
        self.assertEqual(conformance_errors(loaded), [])
        html_text = Path(self.paths.html).read_text(encoding="utf-8")
        self.assertNotIn("<img", html_text.lower())
        self.assertNotIn("<script", html_text.lower())
        self.assertIn("&#x202E;", html_text)


# ── sidecars ───────────────────────────────────────────────────────────────────────────────────────────────────────
class SidecarTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sc_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(os.path.join(self.work, "reports"))
        self.paths = make_paths(self.tmp)

    def read(self, path) -> bytes:
        with open(path, "rb") as fh:
            return fh.read()

    # write_sidecars
    def test_pass_and_fail_sidecars(self):
        for verdict in ("PASS", "FAIL"):
            report.write_sidecars(self.paths, verdict)
            self.assertEqual(self.read(self.paths.verdict_sidecar), verdict.encode() + b"\n")
            self.assertEqual(self.read(self.paths.report_sidecar), self.paths.json.encode() + b"\n")

    def test_both_sidecars_are_in_work_dir_even_with_a_report_dir(self):
        out = os.path.join(self.tmp, "out")
        os.mkdir(out)
        paths = make_paths(self.tmp, report_dir=out, name="n")
        report.write_sidecars(paths, "FAIL")
        self.assertEqual(sorted(os.listdir(self.work)), [".scan_report_json", ".scan_verdict", "reports"])
        self.assertEqual(os.listdir(out), [])
        self.assertEqual(self.read(paths.report_sidecar), os.path.join(out, "report_scan_n.json").encode() + b"\n")

    def test_the_verdict_sidecar_is_written_first_then_the_report_path(self):
        # contract 3.3: JSON report, HTML report, .scan_verdict, .scan_report_json
        with spy_replace() as calls:
            report.write_sidecars(self.paths, "PASS")
        self.assertEqual([c["dst"] for c in calls], [self.paths.verdict_sidecar, self.paths.report_sidecar])

    def test_an_invalid_verdict_raises_and_writes_nothing(self):
        for bad in ("WARN", "pass", "fail", "", "PASS\n", " PASS", "PASS FAIL", None, 1, b"PASS"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                report.write_sidecars(self.paths, bad)       # type: ignore[arg-type]
        self.assertEqual(sorted(os.listdir(self.work)), ["reports"])

    def test_sidecars_replace_earlier_ones_and_leave_no_temporary_file(self):
        Path(self.paths.verdict_sidecar).write_bytes(b"PASS\n")
        Path(self.paths.report_sidecar).write_bytes(b"/old/report.json\n")
        report.write_sidecars(self.paths, "FAIL")
        self.assertEqual(self.read(self.paths.verdict_sidecar), b"FAIL\n")
        self.assertEqual(sorted(os.listdir(self.work)), [".scan_report_json", ".scan_verdict", "reports"])

    def test_a_failed_first_write_leaves_no_report_sidecar(self):
        with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                report.write_sidecars(self.paths, "PASS")
        self.assertEqual(sorted(os.listdir(self.work)), ["reports"])

    def test_the_report_path_keeps_its_original_bytes(self):
        out = os.path.join(self.tmp, "o\udcffut")
        os.mkdir(out)
        paths = make_paths(self.tmp, report_dir=out, name="n")
        report.write_sidecars(paths, "PASS")
        self.assertEqual(self.read(paths.report_sidecar), os.fsencode(paths.json) + b"\n")
        self.assertIn(b"o\xffut", self.read(paths.report_sidecar))

    def test_the_sidecar_modes_follow_the_umask(self):
        with umask(0o027):
            report.write_sidecars(self.paths, "PASS")
        self.assertEqual(stat.S_IMODE(os.stat(self.paths.verdict_sidecar).st_mode), 0o640)

    # clear_sidecars
    def test_clear_removes_both(self):
        Path(self.paths.verdict_sidecar).write_bytes(b"PASS\n")
        Path(self.paths.report_sidecar).write_bytes(b"/old/report.json\n")
        report.clear_sidecars(self.paths)
        self.assertEqual(os.listdir(self.work), ["reports"])

    def test_clear_with_nothing_there_is_fine_and_idempotent(self):
        report.clear_sidecars(self.paths)
        report.clear_sidecars(self.paths)
        self.assertEqual(os.listdir(self.work), ["reports"])

    def test_clear_removes_one_when_only_one_exists(self):
        Path(self.paths.verdict_sidecar).write_bytes(b"PASS\n")
        report.clear_sidecars(self.paths)
        self.assertEqual(os.listdir(self.work), ["reports"])
        Path(self.paths.report_sidecar).write_bytes(b"x\n")
        report.clear_sidecars(self.paths)
        self.assertEqual(os.listdir(self.work), ["reports"])

    def test_clear_never_touches_the_reports_or_other_files(self):
        stale_json = os.path.join(self.work, "reports", "report_20260101_000000.json")
        Path(stale_json).write_bytes(b"{}")
        Path(self.paths.json).write_bytes(b"{}")
        Path(self.paths.html).write_bytes(b"<html>")
        diff = os.path.join(self.work, ".diff_files")
        Path(diff).write_bytes(b"a\0")
        Path(self.paths.verdict_sidecar).write_bytes(b"PASS\n")
        report.clear_sidecars(self.paths)
        self.assertEqual(sorted(os.listdir(os.path.join(self.work, "reports"))),
                         sorted([os.path.basename(stale_json), os.path.basename(self.paths.json), os.path.basename(self.paths.html)]))
        self.assertTrue(os.path.exists(diff))

    def test_clear_does_not_follow_a_symlink(self):
        victim = os.path.join(self.tmp, "victim")
        Path(victim).write_bytes(b"keep")
        os.symlink(victim, self.paths.verdict_sidecar)
        report.clear_sidecars(self.paths)
        self.assertFalse(os.path.lexists(self.paths.verdict_sidecar))
        self.assertEqual(self.read(victim), b"keep")

    def test_a_sidecar_that_cannot_be_removed_is_overwritten_with_fail_and_an_empty_line(self):
        Path(self.paths.verdict_sidecar).write_bytes(b"PASS\n")
        Path(self.paths.report_sidecar).write_bytes(b"/old/report.json\n")
        with failing_remove([self.paths.verdict_sidecar, self.paths.report_sidecar]):
            report.clear_sidecars(self.paths)
        self.assertEqual(self.read(self.paths.verdict_sidecar), b"FAIL\n")
        self.assertEqual(self.read(self.paths.report_sidecar), b"\n")

    def test_each_sidecar_is_handled_on_its_own(self):
        Path(self.paths.verdict_sidecar).write_bytes(b"PASS\n")
        Path(self.paths.report_sidecar).write_bytes(b"/old/report.json\n")
        with failing_remove([self.paths.verdict_sidecar]):
            report.clear_sidecars(self.paths)
        self.assertEqual(self.read(self.paths.verdict_sidecar), b"FAIL\n")
        self.assertFalse(os.path.exists(self.paths.report_sidecar))
        Path(self.paths.verdict_sidecar).write_bytes(b"PASS\n")
        Path(self.paths.report_sidecar).write_bytes(b"/old/report.json\n")
        with failing_remove([self.paths.report_sidecar]):
            report.clear_sidecars(self.paths)
        self.assertFalse(os.path.exists(self.paths.verdict_sidecar))
        self.assertEqual(self.read(self.paths.report_sidecar), b"\n")

    def test_a_stale_pass_never_survives(self):
        Path(self.paths.verdict_sidecar).write_bytes(b"PASS\n")
        with failing_remove([self.paths.verdict_sidecar]):
            report.clear_sidecars(self.paths)
        self.assertNotEqual(self.read(self.paths.verdict_sidecar), b"PASS\n")

    def test_an_error_other_than_missing_is_not_swallowed_when_the_overwrite_fails_too(self):
        os.mkdir(self.paths.verdict_sidecar)                       # neither removable (a directory) nor writable
        with self.assertRaises(OSError):
            report.clear_sidecars(self.paths)
        self.assertTrue(os.path.isdir(self.paths.verdict_sidecar))

    def test_the_overwrite_does_not_follow_a_symlink(self):
        victim = os.path.join(self.tmp, "victim")
        Path(victim).write_bytes(b"keep")
        os.symlink(victim, self.paths.verdict_sidecar)
        with failing_remove([self.paths.verdict_sidecar]):
            try:
                report.clear_sidecars(self.paths)
            except OSError:
                pass
        self.assertEqual(self.read(victim), b"keep")

    def test_a_missing_work_dir_is_fine(self):
        paths = make_paths(os.path.join(self.tmp, "nowhere"))
        report.clear_sidecars(paths)


# ── the module itself ──────────────────────────────────────────────────────────────────────────────────────────────
class ModuleRulesTests(unittest.TestCase):
    """What the design says report.py may and may not do (section 3.2, 9, 5.1)."""

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "transit" / "report.py").read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def imports(self) -> set:
        found = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                found.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                found.add(node.module or "")
        return found

    def test_only_the_modules_of_the_layering_are_imported(self):
        engine = {m for m in self.imports() if m.startswith("transit")}
        self.assertLessEqual(engine, {"transit.cli", "transit.config", "transit.console", "transit.files", "transit.findings",
                                      "transit.verdict"})

    def test_no_regex_no_process_no_eval_no_print(self):
        self.assertNotIn("re", self.imports())
        self.assertNotIn("subprocess", self.imports())
        calls = {(n.func.id if isinstance(n.func, ast.Name) else n.func.attr if isinstance(n.func, ast.Attribute) else "")
                 for n in ast.walk(self.tree) if isinstance(n, ast.Call)}
        self.assertFalse(calls & {"eval", "exec", "system", "popen", "print"}, calls & {"eval", "exec", "system", "popen", "print"})
        self.assertNotIn("shell=True", self.source)

    def test_the_old_helper_program_is_not_imported(self):
        self.assertFalse([m for m in self.imports() if "report_json" in m])

    def test_no_python_311_feature_is_used(self):
        ast.parse(self.source, feature_version=(3, 10))

    def test_nothing_is_written_at_import(self):
        proc = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r); import transit.report" % str(ROOT)],
                              capture_output=True, timeout=60)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, b"", b""))


if __name__ == "__main__":
    unittest.main()
