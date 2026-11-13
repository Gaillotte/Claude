"""Tests of transit/verdict.py (WP-02): the run state. Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_verdict.py"

``Verdict`` is driven through a fake console (it only needs ``warn`` and ``fail_line``) and through the event sequences of
the golden reports in tests/conformance/golden, so the counters, statuses and messages are compared with what the bash
engine produced. A token-shaped credential is never written contiguously in this file.
"""
from __future__ import annotations

import ast
import collections.abc
import dataclasses
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from transit import findings as findings_module  # noqa: E402
from transit import verdict as verdict_module  # noqa: E402
from transit.findings import Allowlist, FindingRecord, classify_severity, parse_allowlist  # noqa: E402
from transit.verdict import GLOBAL_FILE, Counters, Outcome, Snapshot, Verdict  # noqa: E402

GOLDEN = ROOT / "tests" / "conformance" / "golden"
FIXTURES = ROOT / "tests" / "fixtures"
SCAN = "/s"

REQUIRED = ("L1_secrets_gitleaks", "L1_secrets_entropy", "L1_malware", "L2_owasp_cwe", "L3_dependency_cve",
            "L4_patterns", "L5_per_language_sast")
OPTIONAL = ("L1_ioc_yara", "L6_licence")
ALL_LAYERS = tuple(sorted(REQUIRED + OPTIONAL))


class FakeConsole:
    """The two methods ``Verdict`` is allowed to call. Any other call is a bug of the caller."""

    def __init__(self) -> None:
        self.calls: list = []

    def warn(self, text: str) -> None:
        self.calls.append(("warn", text))

    def fail_line(self, text: str) -> None:
        self.calls.append(("fail_line", text))

    def __getattr__(self, name: str):
        raise AssertionError("Verdict called console.%s" % name)


class ExplodingConsole(FakeConsole):
    def warn(self, text: str) -> None:
        raise RuntimeError("console failed")

    def fail_line(self, text: str) -> None:
        raise RuntimeError("console failed")


def make(allow: "Allowlist | None" = None, *, threshold: int = 3, min_severity: str = "high",
         console: "FakeConsole | None" = None, **kwargs):
    console = console if console is not None else FakeConsole()
    v = Verdict(SCAN, allow if allow is not None else Allowlist({}), threshold=threshold, min_severity=min_severity,
                console=console, **kwargs)
    return v, console


def path(rel: str) -> str:
    return SCAN + "/" + rel


def pieces(message: str) -> list:
    """The conformance normaliser's view of a message: the ``" | "``-separated parts, without the trailing separator."""
    return message[:-3].split(" | ") if message else []


def golden(name: str) -> dict:
    return json.loads((GOLDEN / (name + ".json")).read_text(encoding="utf-8"))["report"]


def golden_global_warnings(report: dict) -> list:
    return [m[len("[WARN] "):] for m in report["file_results"]["__global__"]["messages"] if m.startswith("[WARN] ")]


def relative(snapshot_path: str) -> str:
    return snapshot_path[len(SCAN) + 1:] if snapshot_path.startswith(SCAN + "/") else snapshot_path


def real_console_works() -> bool:
    try:
        from transit.console import Console
        c = Console("normal", out=io.BytesIO(), err=io.BytesIO(), err_is_tty=False)
        c.warn("probe")
        c.fail_line("probe")
        return True
    except Exception:
        return False


# ── 6.1: the three states, first writer, counters ──────────────────────────────────────────────────────────────────────
STEP = {
    "pass": lambda v, f: v.record_pass(f),
    "warn": lambda v, f: v.record_warn(f, "w"),
    "fail": lambda v, f: v.record_fail(f, "CWE-1:f"),
}
TEXT = {"pass": "", "warn": "[WARN] w | ", "fail": "[FAIL] CWE-1:f | "}

#: (events on one file, status when the first writer wins, status under D-012 where the worst event wins)
FIRST_WRITER = [
    (("pass",), "PASS", "PASS"),
    (("warn",), "WARN", "WARN"),
    (("fail",), "FAIL", "FAIL"),
    (("pass", "pass"), "PASS", "PASS"),
    (("pass", "warn"), "PASS", "WARN"),          # A12: a PASS that later carries a WARN message stays PASS
    (("warn", "pass"), "WARN", "WARN"),
    (("warn", "warn"), "WARN", "WARN"),
    (("pass", "fail"), "FAIL", "FAIL"),
    (("warn", "fail"), "FAIL", "FAIL"),
    (("fail", "pass"), "FAIL", "FAIL"),
    (("fail", "warn"), "FAIL", "FAIL"),          # a WARN never overwrites a FAIL
    (("fail", "fail"), "FAIL", "FAIL"),
    (("pass", "warn", "fail"), "FAIL", "FAIL"),
    (("pass", "pass", "warn"), "PASS", "WARN"),
    (("warn", "pass", "fail", "warn", "pass"), "FAIL", "FAIL"),
    (("fail", "pass", "warn"), "FAIL", "FAIL"),
]


class StatesTests(unittest.TestCase):
    def test_initial_state(self):
        v, console = make()
        self.assertEqual(v.verdict, "PASS")
        self.assertEqual(v.counters, Counters(0, 0, 0))
        self.assertEqual(v.events, 0)
        self.assertIsNone(v.status_of(path("a.py")))
        self.assertIsNone(v.coverage_state("L4_patterns"))
        snap = v.snapshot()
        self.assertEqual((snap.verdict, snap.counters, dict(snap.file_status), dict(snap.coverage), snap.findings),
                         ("PASS", Counters(0, 0, 0), {}, {}, ()))
        self.assertEqual(console.calls, [])

    def test_first_writer_table_of_e12(self):
        for steps, first_writer_status, _ in FIRST_WRITER:
            with self.subTest(steps=steps):
                v, _ = make()
                for step in steps:
                    STEP[step](v, path("a.py"))
                self.assertEqual(v.status_of(path("a.py")), first_writer_status)
                snap = v.snapshot()
                self.assertEqual(snap.file_status[path("a.py")], first_writer_status)
                self.assertEqual(snap.file_message[path("a.py")], "".join(TEXT[s] for s in steps))
                self.assertEqual(v.events, len(steps))
                self.assertEqual(v.counters, Counters(steps.count("pass"), steps.count("warn"), steps.count("fail")))

    def test_worst_event_wins_under_d012(self):
        for steps, _, worst_status in FIRST_WRITER:
            with self.subTest(steps=steps):
                v, _ = make(first_writer=False)
                for step in steps:
                    STEP[step](v, path("a.py"))
                self.assertEqual(v.status_of(path("a.py")), worst_status)
                self.assertEqual(v.snapshot().file_message[path("a.py")], "".join(TEXT[s] for s in steps))
                self.assertEqual(v.counters, Counters(steps.count("pass"), steps.count("warn"), steps.count("fail")))

    def test_record_pass_adds_no_message_and_keeps_an_existing_one(self):
        v, _ = make()
        v.record_warn(path("a"), "w")
        v.record_pass(path("a"))
        self.assertEqual(v.snapshot().file_message[path("a")], "[WARN] w | ")
        v.record_pass(path("b"))
        self.assertEqual(v.snapshot().file_message[path("b")], "")

    def test_record_pass_without_a_file_counts_and_touches_nothing(self):
        for arg in (None, ""):
            v, _ = make()
            v.record_pass(arg)
            self.assertEqual(v.counters, Counters(1, 0, 0))
            self.assertEqual(v.events, 1)
            self.assertEqual(dict(v.snapshot().file_status), {})
        v, _ = make()
        v.record_pass()
        self.assertEqual(v.counters.pass_, 1)

    def test_a_warn_without_a_file_is_global(self):
        for arg in (None, ""):
            v, _ = make()
            v.record_warn(arg, "gitleaks missing")
            self.assertEqual(v.status_of(GLOBAL_FILE), "WARN")
            self.assertEqual(v.snapshot().file_message[GLOBAL_FILE], "[WARN] gitleaks missing | ")
        self.assertEqual(GLOBAL_FILE, "__global__")

    def test_messages_accumulate_in_order_with_the_separator(self):
        v, _ = make()
        v.record_warn(path("a"), "one")
        v.record_fail(path("a"), "CWE-1:two")
        v.record_warn(path("a"), "three")
        v.record_fail(path("a"), "CWE-2:four")
        snap = v.snapshot()
        self.assertEqual(snap.file_message[path("a")], "[WARN] one | [FAIL] CWE-1:two | [WARN] three | [FAIL] CWE-2:four | ")
        self.assertEqual(snap.fail_messages[path("a")], "CWE-1:two | CWE-2:four | ")

    def test_counters_count_events_not_files(self):
        v, _ = make()
        for _ in range(6):
            v.record_pass(path("same.py"))
        v.record_warn(path("same.py"), "w")
        v.record_warn(path("same.py"), "w")
        v.record_fail(path("same.py"), "CWE-1:a")
        v.record_fail(path("same.py"), "CWE-1:a")
        v.record_fail(path("same.py"), "CWE-1:a")
        self.assertEqual(v.counters, Counters(6, 2, 3))
        self.assertEqual(v.snapshot().counters, Counters(6, 2, 3))
        self.assertEqual(v.events, 11)

    def test_a_pass_after_a_fail_still_counts(self):
        v, _ = make()
        v.record_fail(path("a"), "CWE-1:a")
        v.record_pass(path("a"))
        self.assertEqual((v.counters.pass_, v.counters.fail), (1, 1))

    def test_the_verdict_flips_once_and_never_back(self):
        v, _ = make()
        v.record_warn(path("a"), "w")
        v.record_pass(path("a"))
        self.assertEqual(v.verdict, "PASS")
        v.record_fail(path("b"), "CWE-1:a")
        self.assertEqual(v.verdict, "FAIL")
        v.record_pass(path("c"))
        v.record_warn(path("c"), "w")
        v.record_layer("L4_patterns", "ran")
        self.assertEqual(v.verdict, "FAIL")
        self.assertEqual(v.snapshot().verdict, "FAIL")

    def test_an_allowed_or_low_severity_finding_does_not_flip_the_verdict(self):
        v, _ = make(Allowlist({("CWE-1", "a"): "why"}))
        self.assertEqual(v.record_fail(path("a"), "CWE-1:x"), Outcome.ALLOWED)
        self.assertEqual(v.record_fail(path("b"), "x:LOW:y"), Outcome.LOW_SEV)
        self.assertEqual(v.verdict, "PASS")
        self.assertEqual(v.counters, Counters(0, 2, 0))

    def test_the_counters_are_a_frozen_value(self):
        c = Counters(1, 2, 3)
        self.assertEqual((c.pass_, c.warn, c.fail), (1, 2, 3))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            c.warn = 5                                                           # type: ignore[misc]


# ── the clean scenario and the golden replays ──────────────────────────────────────────────────────────────────────────
class GoldenScenarioTests(unittest.TestCase):
    def compare(self, v: Verdict, report: dict) -> None:
        snap = v.snapshot()
        self.assertEqual(snap.verdict, report["verdict"])
        self.assertEqual({"pass": snap.counters.pass_, "warn": snap.counters.warn, "fail": snap.counters.fail},
                         report["summary"])
        self.assertEqual({relative(k): s for k, s in snap.file_status.items()},
                         {k: r["status"] for k, r in report["file_results"].items()})
        for key, result in report["file_results"].items():
            full = key if key == "__global__" else path(key)
            self.assertEqual(sorted(pieces(snap.file_message[full])), sorted(result["messages"]), key)
        self.assertEqual(len(snap.findings), len(report["findings"]))

    def test_clean_scenario_gives_pass_4_and_warn_7(self):
        report = golden("clean")
        v, _ = make()
        for message in golden_global_warnings(report):
            v.record_warn(None, message)
        v.record_pass(path("README.md"))
        v.record_pass(path("requirements.txt"))
        for name, message in (("src/app.py", "bandit missing"), ("src/setup.sh", "shellcheck missing")):
            v.record_warn(path(name), message)                  # the family scanner warns, then records its pass
            v.record_pass(path(name))
        self.assertEqual(v.counters, Counters(4, 7, 0))
        self.compare(v, report)

    def test_allowlisted_scenario(self):
        report = golden("allowlisted")
        allow, notes = parse_allowlist((FIXTURES / "allowlisted" / ".transit-allow.json").read_bytes())
        self.assertEqual(notes, ())
        v, _ = make(allow)
        for message in golden_global_warnings(report):
            v.record_warn(None, message)
        v.record_pass(path(".transit-allow.json"))
        self.assertEqual(v.record_fail(path("src/db.py"), "CWE-89:SQL_injection_query_built_by_string_interpolation"),
                         Outcome.ALLOWED)
        v.record_warn(path("src/db.py"), "bandit missing")
        self.compare(v, report)
        self.assertEqual(v.verdict, "PASS")

    def test_minsev_critical_scenario(self):
        report = golden("minsev_critical")
        v, _ = make(threshold=4, min_severity="critical")
        for message in golden_global_warnings(report):
            v.record_warn(None, message)
        v.record_pass(path("README.md"))
        self.assertEqual(v.record_fail(path("src/db.py"), "CWE-89:SQL_injection_query_built_by_string_interpolation"),
                         Outcome.LOW_SEV)
        v.record_warn(path("src/db.py"), "bandit missing")
        self.compare(v, report)

    def test_vulnerable_scenario(self):
        report = golden("vulnerable")
        v, _ = make()
        for message in golden_global_warnings(report):
            v.record_warn(None, message)
        v.record_pass(path("README.md"))
        self.assertEqual(v.record_fail(path("src/db.py"), "CWE-89:SQL_injection_query_built_by_string_interpolation"),
                         Outcome.FAILED)
        v.record_warn(path("src/db.py"), "bandit missing")
        self.compare(v, report)
        snap = v.snapshot()
        self.assertEqual(snap.findings[0].to_json(), dict(report["findings"][0], column=None))
        self.assertEqual(snap.fail_messages[path("src/db.py")], "CWE-89:SQL_injection_query_built_by_string_interpolation | ")

    def test_hard_failure_scenario_of_the_transitignore_golden(self):
        report = golden("transitignore_everything")
        v, _ = make()
        for message in golden_global_warnings(report):
            v.record_warn(None, message)
        self.assertEqual(v.record_fail(GLOBAL_FILE, "engine:nothing_scanned", downgradable=False), Outcome.FAILED)
        self.compare(v, report)
        self.assertEqual(v.snapshot().findings[0].file, "__global__")

    def test_every_golden_finding_is_decided_by_the_same_severity_as_its_record(self):
        total = 0
        for path_ in sorted(GOLDEN.glob("*.json")):
            report = json.loads(path_.read_text(encoding="utf-8")).get("report")
            if not report:
                continue
            for f in report["findings"]:
                file = SCAN if f["file"] == "." else f["file"] if f["file"] == "__global__" else path(f["file"])
                number = findings_module.SEVERITY_NUMBER[f["severity"]]
                at_bar, _ = make(threshold=number)
                self.assertEqual(at_bar.record_fail(file, f["message"]), Outcome.FAILED, f["message"])
                self.assertEqual(at_bar.snapshot().findings[0].to_json(), dict(f, column=None))
                total += 1
                above, _ = make(threshold=number + 1)
                if f["message"].startswith("engine:"):                  # an engine message is never below the bar
                    self.assertEqual(above.record_fail(file, f["message"]), Outcome.FAILED, f["message"])
                elif number < 4:
                    self.assertEqual(above.record_fail(file, f["message"]), Outcome.LOW_SEV, f["message"])
                    self.assertEqual(above.verdict, "PASS")
        self.assertGreater(total, 300)

    def test_all_golden_findings_in_one_run(self):
        v, _ = make(threshold=1)
        expected = []
        for path_ in sorted(GOLDEN.glob("*.json")):
            report = json.loads(path_.read_text(encoding="utf-8")).get("report")
            for f in (report or {}).get("findings", []):
                file = SCAN if f["file"] == "." else f["file"] if f["file"] == "__global__" else path(f["file"])
                v.record_fail(file, f["message"])
                expected.append(dict(f, column=None))
        snap = v.snapshot()
        self.assertEqual([r.to_json() for r in snap.findings], expected)          # in the order recorded
        self.assertEqual(snap.counters.fail, len(expected))


# ── 6.2: record_fail ───────────────────────────────────────────────────────────────────────────────────────────────────
class RecordFailTests(unittest.TestCase):
    def test_outcome_values(self):
        self.assertEqual({o.name: o.value for o in Outcome},
                         {"FAILED": "failed", "ALLOWED": "allowed", "LOW_SEV": "low_sev"})

    def test_a_plain_fail(self):
        v, console = make()
        outcome = v.record_fail(path("src/a.py"), "CWE-798:hardcoded_credential")
        self.assertIs(outcome, Outcome.FAILED)
        snap = v.snapshot()
        self.assertEqual(v.verdict, "FAIL")
        self.assertEqual(snap.file_status[path("src/a.py")], "FAIL")
        self.assertEqual(snap.file_message[path("src/a.py")], "[FAIL] CWE-798:hardcoded_credential | ")
        self.assertEqual(snap.fail_messages[path("src/a.py")], "CWE-798:hardcoded_credential | ")
        self.assertEqual(snap.counters, Counters(0, 0, 1))
        self.assertEqual(console.calls, [("fail_line", "[%s] CWE-798:hardcoded_credential" % path("src/a.py"))])
        record = snap.findings[0]
        self.assertIsInstance(record, FindingRecord)
        self.assertEqual((record.tool, record.category, record.severity, record.rule_id, record.file),
                         ("grep-pattern", "cwe", "HIGH", "CWE-798", "src/a.py"))

    def test_allowlist_downgrades_to_a_warn_with_the_reason(self):
        v, console = make(Allowlist({("CWE-798", "src/a.py"): "test fixture only"}))
        outcome = v.record_fail(path("src/a.py"), "CWE-798:hardcoded_credential")
        self.assertIs(outcome, Outcome.ALLOWED)
        text = "ALLOWED:CWE-798:hardcoded_credential (reason: test fixture only)"
        snap = v.snapshot()
        self.assertEqual(snap.file_message[path("src/a.py")], "[WARN] " + text + " | ")
        self.assertEqual(snap.file_status[path("src/a.py")], "WARN")
        self.assertEqual(snap.counters, Counters(0, 1, 0))
        self.assertEqual(snap.findings, ())
        self.assertNotIn(path("src/a.py"), snap.fail_messages)
        self.assertEqual(v.verdict, "PASS")
        self.assertEqual(console.calls, [("warn", text)])
        self.assertEqual(v.events, 1)

    def test_allowlist_matches_the_path_relative_to_the_scan_directory(self):
        v, _ = make(Allowlist({("CWE-798", "src/a.py"): "r"}))
        self.assertIs(v.record_fail(path("src/a.py"), "CWE-798:x"), Outcome.ALLOWED)
        self.assertIs(v.record_fail(path("src/b.py"), "CWE-798:x"), Outcome.FAILED)
        self.assertIs(v.record_fail(path("other/src/a.py"), "CWE-798:x"), Outcome.FAILED)
        self.assertIs(v.record_fail("/elsewhere/src/a.py", "CWE-798:x"), Outcome.FAILED)

    def test_threshold_downgrades_to_a_warn_that_quotes_min_severity_as_typed(self):
        v, console = make(threshold=4, min_severity="Critical")
        outcome = v.record_fail(path("src/a.py"), "CWE-89:SQL_injection")
        self.assertIs(outcome, Outcome.LOW_SEV)
        text = "LOW_SEV(below --min-severity Critical):CWE-89:SQL_injection"
        self.assertEqual(v.snapshot().file_message[path("src/a.py")], "[WARN] " + text + " | ")
        self.assertEqual(console.calls, [("warn", text)])
        self.assertEqual(v.snapshot().counters, Counters(0, 1, 0))
        self.assertEqual(v.verdict, "PASS")
        self.assertEqual(v.snapshot().findings, ())

    def test_threshold_boundaries(self):
        cases = [
            (1, "x:INFO:y", Outcome.FAILED), (1, "x:LOW:y", Outcome.FAILED),
            (2, "x:LOW:y", Outcome.LOW_SEV), (2, "x:MEDIUM:y", Outcome.FAILED),
            (3, "x:MEDIUM:y", Outcome.LOW_SEV), (3, "CWE-1:no marker", Outcome.FAILED), (3, "x:HIGH:y", Outcome.FAILED),
            (4, "CWE-1:no marker", Outcome.LOW_SEV), (4, "x:CRITICAL:y", Outcome.FAILED),
            (4, "gitleaks:generic-api-key:line1", Outcome.FAILED), (4, "clamav:malware_detected", Outcome.FAILED),
            (3, "semgrep[p/x]:r:line1:INFO:m", Outcome.LOW_SEV), (3, "semgrep[p/x]:r:line1:ERROR:m", Outcome.FAILED),
            (2, "semgrep[p/x]:r:line1:WARNING:m", Outcome.FAILED), (3, "semgrep[p/x]:r:line1:WARNING:m", Outcome.LOW_SEV),
        ]
        for threshold, message, expected in cases:
            with self.subTest(threshold=threshold, message=message):
                v, _ = make(threshold=threshold)
                self.assertIs(v.record_fail(path("a"), message), expected)

    def test_a_producer_severity_decides_the_threshold_and_the_record(self):
        v, _ = make(threshold=3)
        self.assertIs(v.record_fail(path("a"), "CWE-1:no marker", severity="LOW"), Outcome.LOW_SEV)
        v, _ = make(threshold=1)
        self.assertIs(v.record_fail(path("a"), "CWE-1:no marker", severity="LOW"), Outcome.FAILED)
        self.assertEqual(v.snapshot().findings[0].severity, "LOW")
        v, _ = make(threshold=4)
        self.assertIs(v.record_fail(path("a"), "x:LOW:y", severity="CRITICAL"), Outcome.FAILED)
        self.assertEqual(v.snapshot().findings[0].severity, "CRITICAL")
        v, _ = make(threshold=3)
        self.assertIs(v.record_fail(path("a"), "CWE-1:x", severity="bogus"), Outcome.FAILED)   # unknown: classified

    def test_allowlist_is_consulted_before_the_threshold(self):
        # E21: an allowlisted Semgrep INFO finding gets ALLOWED:, not LOW_SEV(...)
        message = "semgrep[p/x]:CWE-78:line1:INFO:m"
        v, _ = make(Allowlist({("CWE-78", "a.py"): "ok"}))
        self.assertIs(v.record_fail(path("a.py"), message), Outcome.ALLOWED)
        self.assertEqual(v.snapshot().file_message[path("a.py")], "[WARN] ALLOWED:%s (reason: ok) | " % message)
        v, _ = make()
        self.assertIs(v.record_fail(path("a.py"), message), Outcome.LOW_SEV)
        self.assertIn("LOW_SEV(below --min-severity high):", v.snapshot().file_message[path("a.py")])

    def test_an_engine_message_is_never_downgraded(self):
        class Always(Allowlist):                                   # an allowlist that would match anything
            def lookup(self, message, rel_path):
                return "everything is fine"

        for allow in (Allowlist({("engine", "__global__"): "x", ("nothing_scanned", "__global__"): "x"}),
                      Always({}), None):
            for message in ("engine:nothing_scanned", "engine:internal_error:RecursionError", "engine:scan_incomplete:a:time_budget"):
                with self.subTest(message=message, allow=type(allow).__name__):
                    v, console = make(allow, threshold=4, min_severity="critical")
                    self.assertIs(v.record_fail("__global__", message), Outcome.FAILED)
                    self.assertEqual(v.verdict, "FAIL")
                    self.assertEqual(v.snapshot().findings[0].tool, "engine")
                    self.assertEqual(console.calls, [("fail_line", "[__global__] " + message)])

    def test_the_engine_exemption_is_the_exact_prefix(self):
        v, _ = make(Allowlist({("ENGINE", "a"): "x"}), threshold=4)
        self.assertIs(v.record_fail(path("a"), "ENGINE:x"), Outcome.ALLOWED)
        self.assertIs(v.record_fail(path("a"), "enginex:y"), Outcome.LOW_SEV)

    def test_downgradable_false_skips_both_steps(self):
        class Always(Allowlist):
            def lookup(self, message, rel_path):
                return "everything is fine"

        v, _ = make(Always({}), threshold=4)
        self.assertIs(v.record_fail(path("a"), "CWE-1:x", downgradable=False), Outcome.FAILED)
        self.assertIs(v.record_fail(path("a"), "CWE-1:x", downgradable=True), Outcome.ALLOWED)
        v, _ = make(threshold=4)
        self.assertIs(v.record_fail(path("a"), "CWE-1:x", downgradable=False), Outcome.FAILED)
        self.assertEqual(v.snapshot().findings[0].message, "CWE-1:x")

    def test_whole_directory_finding_and_d011(self):
        message = "clamav:malware_detected"
        # the spelling bash knows: the scan directory string as typed
        v, _ = make(Allowlist({("clamav", SCAN): "why"}))
        self.assertIs(v.record_fail(SCAN, message), Outcome.ALLOWED)
        # "." only with the D-011 switch
        v, _ = make(Allowlist({("clamav", "."): "why"}))
        self.assertIs(v.record_fail(SCAN, message), Outcome.FAILED)
        v, _ = make(Allowlist({("clamav", "."): "why"}), dot_matches_directory=True)
        self.assertIs(v.record_fail(SCAN, message), Outcome.ALLOWED)
        self.assertIn("(reason: why)", v.snapshot().file_message[SCAN])
        # the old spelling keeps working with the switch on
        v, _ = make(Allowlist({("clamav", SCAN): "old"}), dot_matches_directory=True)
        self.assertIs(v.record_fail(SCAN, message), Outcome.ALLOWED)
        self.assertIn("(reason: old)", v.snapshot().file_message[SCAN])
        # "." never matches an ordinary file, with or without the switch
        for switch in (False, True):
            v, _ = make(Allowlist({("clamav", "."): "why"}), dot_matches_directory=switch)
            self.assertIs(v.record_fail(path("a.py"), message), Outcome.FAILED)
        # the finding record of a whole-directory FAIL says "."
        v, _ = make()
        v.record_fail(SCAN, message)
        self.assertEqual(v.snapshot().findings[0].file, ".")
        self.assertEqual(v.snapshot().file_status[SCAN], "FAIL")

    def test_a_relative_scan_directory(self):
        v = Verdict("repo", Allowlist({("CWE-1", "a.py"): "r", ("gitleaks", "repo"): "dir"}), threshold=3,
                    min_severity="high", console=FakeConsole(), dot_matches_directory=True)
        self.assertIs(v.record_fail("repo/a.py", "CWE-1:x"), Outcome.ALLOWED)
        self.assertIs(v.record_fail("repo", "gitleaks:secrets_detected"), Outcome.ALLOWED)

    def test_the_record_is_built_from_the_original_message_and_file(self):
        v, _ = make()
        v.record_fail(path("sub dir/a b.py"), "semgrep[p/x]:r:line4:ERROR:m")
        record = v.snapshot().findings[0]
        self.assertEqual((record.file, record.line, record.severity, record.tool), ("sub dir/a b.py", 4, "HIGH", "semgrep"))

    def test_a_message_with_hostile_text_is_recorded_not_interpreted(self):
        hostile = ["CWE-1:x\x1b]0;pwned\x07", "CWE-1:‮", "CWE-1:" + "x" * 1_000_000, "\x00", "", ":", "a|b | c",
                   "CWE-1:\ud800", "CWE-1:" + os_name_with_surrogate()]
        v, _ = make(threshold=1)
        for message in hostile:
            self.assertIs(v.record_fail(path("a"), message), Outcome.FAILED)
            v.record_warn(path("a"), message)
        self.assertEqual(v.snapshot().counters, Counters(0, len(hostile), len(hostile)))


def os_name_with_surrogate() -> str:
    import os
    return os.fsdecode(b"bad\xfe\xffname")


# ── record_warn_once, events, set_allowlist ────────────────────────────────────────────────────────────────────────────
class OnceAndEventsTests(unittest.TestCase):
    def test_record_warn_once_records_once_per_key_and_counts_one_event(self):
        v, console = make()
        self.assertTrue(v.record_warn_once("tool_not_ported:bandit", path("a.py"), "engine:tool_not_ported:bandit"))
        self.assertFalse(v.record_warn_once("tool_not_ported:bandit", path("a.py"), "engine:tool_not_ported:bandit"))
        self.assertFalse(v.record_warn_once("tool_not_ported:bandit", path("b.py"), "engine:tool_not_ported:bandit"))
        self.assertEqual(v.events, 1)
        self.assertEqual(v.counters, Counters(0, 1, 0))
        self.assertEqual(console.calls, [("warn", "engine:tool_not_ported:bandit")])
        self.assertEqual(v.snapshot().file_message[path("a.py")], "[WARN] engine:tool_not_ported:bandit | ")
        self.assertIsNone(v.status_of(path("b.py")))
        self.assertTrue(v.record_warn_once("tool_not_ported:shellcheck", path("b.py"), "other"))
        self.assertEqual(v.events, 2)
        self.assertEqual(v.status_of(path("b.py")), "WARN")

    def test_record_warn_once_without_a_file_is_global(self):
        v, _ = make()
        self.assertTrue(v.record_warn_once("k", None, "m"))
        self.assertEqual(v.status_of(GLOBAL_FILE), "WARN")

    def test_the_memory_of_record_warn_once_belongs_to_the_verdict(self):
        first, _ = make()
        second, _ = make()
        self.assertTrue(first.record_warn_once("k", None, "m"))
        self.assertTrue(second.record_warn_once("k", None, "m"))       # not a module global (R-22)
        self.assertFalse(first.record_warn_once("k", None, "m"))

    def test_events_count_every_record_call(self):
        v, _ = make(Allowlist({("CWE-1", "a"): "r"}), threshold=3)
        steps = [
            (lambda: v.record_pass(path("a")), 1),
            (lambda: v.record_pass(None), 1),
            (lambda: v.record_warn(path("a"), "w"), 1),
            (lambda: v.record_warn_once("k", None, "w"), 1),
            (lambda: v.record_warn_once("k", None, "w"), 0),
            (lambda: v.record_fail(path("a"), "CWE-1:x"), 1),             # ALLOWED
            (lambda: v.record_fail(path("b"), "x:LOW:y"), 1),             # LOW_SEV
            (lambda: v.record_fail(path("c"), "CWE-2:z"), 1),             # FAILED
            (lambda: v.record_layer("L4_patterns", "ran"), 0),
            (lambda: v.note_incomplete("L5_per_language_sast", "r"), 0),
            (lambda: v.snapshot(), 0),
            (lambda: v.status_of(path("a")), 0),
        ]
        total = 0
        for step, delta in steps:
            before = v.events
            step()
            self.assertEqual(v.events - before, delta)
            total += delta
        self.assertEqual(v.events, total)

    def test_set_allowlist_installs_the_allowlist(self):
        v, _ = make()
        v.set_allowlist(Allowlist({("CWE-1", "a"): "r"}))
        self.assertIs(v.record_fail(path("a"), "CWE-1:x"), Outcome.ALLOWED)

    def test_set_allowlist_replaces_the_allowlist_given_to_the_constructor(self):
        v, _ = make(Allowlist({("CWE-1", "a"): "old"}))
        v.set_allowlist(Allowlist({("CWE-2", "a"): "new"}))
        self.assertIs(v.record_fail(path("a"), "CWE-1:x"), Outcome.FAILED)
        self.assertIs(v.record_fail(path("a"), "CWE-2:x"), Outcome.ALLOWED)

    def test_set_allowlist_after_an_event_is_a_programming_error(self):
        events = {
            "pass": lambda v: v.record_pass(path("a")),
            "pass_none": lambda v: v.record_pass(None),
            "warn": lambda v: v.record_warn(None, "w"),
            "warn_once": lambda v: v.record_warn_once("k", None, "w"),
            "fail": lambda v: v.record_fail(path("a"), "CWE-1:x"),
            "abort": lambda v: v.abort("Boom"),
        }
        for name, event in events.items():
            with self.subTest(event=name):
                v, _ = make()
                event(v)
                with self.assertRaises(RuntimeError):
                    v.set_allowlist(Allowlist({("CWE-1", "a"): "r"}))
                self.assertIs(v.record_fail(path("a"), "CWE-1:x"), Outcome.FAILED)    # and nothing was installed

    def test_set_allowlist_is_legal_after_coverage_calls_and_only_once(self):
        v, _ = make()
        v.record_layer("L4_patterns", "ran")
        v.note_incomplete("L5_per_language_sast", "reason")
        v.snapshot()
        v.set_allowlist(Allowlist({}))
        with self.assertRaises(RuntimeError):
            v.set_allowlist(Allowlist({("CWE-1", "a"): "r"}))

    def test_the_constructor_allowlist_is_not_modified_by_events(self):
        allow = Allowlist({("CWE-1", "a"): "r"})
        v, _ = make(allow)
        v.record_fail(path("a"), "CWE-1:x")
        self.assertEqual(dict(allow.entries), {("CWE-1", "a"): "r"})


# ── coverage ───────────────────────────────────────────────────────────────────────────────────────────────────────────
class CoverageTests(unittest.TestCase):
    def test_the_layer_ids_are_the_nine_of_the_configuration(self):
        from transit import config
        self.assertEqual(tuple(sorted(verdict_module._COVERAGE_LAYERS)), tuple(config.COVERAGE_LAYERS))
        self.assertEqual(tuple(verdict_module._COVERAGE_REQUIRED), tuple(config.COVERAGE_REQUIRED))
        self.assertEqual(tuple(sorted(verdict_module._COVERAGE_LAYERS)), ALL_LAYERS)

    def test_record_layer_and_coverage_state(self):
        v, _ = make()
        for layer in ALL_LAYERS:
            self.assertIsNone(v.coverage_state(layer))
        v.record_layer("L4_patterns", "ran")
        v.record_layer("L2_owasp_cwe", "skipped:semgrep not installed")
        v.record_layer("L1_malware", "partial:something")
        self.assertEqual(v.coverage_state("L4_patterns"), "ran")
        self.assertEqual(v.coverage_state("L2_owasp_cwe"), "skipped:semgrep not installed")
        self.assertEqual(v.coverage_state("L1_malware"), "partial:something")
        self.assertEqual(dict(v.snapshot().coverage), {"L4_patterns": "ran", "L2_owasp_cwe": "skipped:semgrep not installed",
                                                       "L1_malware": "partial:something"})

    def test_all_nine_layers_are_accepted(self):
        v, _ = make()
        for layer in ALL_LAYERS:
            v.record_layer(layer, "ran")
        self.assertEqual(set(v.snapshot().coverage), set(ALL_LAYERS))

    def test_an_unknown_layer_id_is_refused(self):
        v, _ = make()
        for layer in ("L7_other", "", "l4_patterns", "L4_patterns ", "L4", "__global__", "L5_per_language_sast\n", None):
            with self.subTest(layer=layer):
                with self.assertRaises(ValueError):
                    v.record_layer(layer, "ran")                                  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    v.note_incomplete(layer, "reason")                            # type: ignore[arg-type]
        self.assertEqual(dict(v.snapshot().coverage), {})                         # a mistyped id did not create a tenth layer

    def test_a_malformed_state_is_refused(self):
        v, _ = make()
        for state in ("", "Ran", "ran ", " ran", "ran:x", "skipped", "skipped:", "partial", "partial:", "bogus", "SKIPPED:x",
                      "skipped:a\nb", "skipped:a\rb", "partial: x", "partial:x ", None, 5):
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    v.record_layer("L4_patterns", state)                          # type: ignore[arg-type]
        self.assertIsNone(v.coverage_state("L4_patterns"))
        for state in ("ran", "skipped:x", "partial:x", "skipped: ", "skipped:a:b:c", "partial:rulesets missing (a b)"):
            v.record_layer("L4_patterns", state)

    def test_overwrite_false_keeps_the_earlier_state(self):
        v, _ = make()
        v.record_layer("L4_patterns", "skipped:first")
        v.record_layer("L4_patterns", "ran", overwrite=False)
        self.assertEqual(v.coverage_state("L4_patterns"), "skipped:first")
        v.record_layer("L4_patterns", "ran")                                      # overwrite is the default
        self.assertEqual(v.coverage_state("L4_patterns"), "ran")
        v.record_layer("L5_per_language_sast", "ran", overwrite=False)            # nothing to keep: it is set
        self.assertEqual(v.coverage_state("L5_per_language_sast"), "ran")

    def test_an_invalid_state_with_overwrite_false_is_still_refused(self):
        v, _ = make()
        v.record_layer("L4_patterns", "ran")
        with self.assertRaises(ValueError):
            v.record_layer("L4_patterns", "bogus", overwrite=False)

    def test_note_incomplete_turns_ran_into_partial_with_sorted_unique_reasons(self):
        v, _ = make()
        v.record_layer("L5_per_language_sast", "ran")
        v.note_incomplete("L5_per_language_sast", "z tool not ported")
        v.note_incomplete("L5_per_language_sast", "a scanner not ported")
        v.note_incomplete("L5_per_language_sast", "z tool not ported")
        self.assertEqual(v.snapshot().coverage["L5_per_language_sast"], "partial:a scanner not ported; z tool not ported")
        self.assertEqual(v.coverage_state("L5_per_language_sast"), "ran")           # the base state is not folded

    def test_note_incomplete_order_does_not_matter(self):
        a, _ = make()
        b, _ = make()
        a.record_layer("L4_patterns", "ran")
        a.note_incomplete("L4_patterns", "one")
        b.note_incomplete("L4_patterns", "one")
        b.record_layer("L4_patterns", "ran")                                       # recorded after the note
        self.assertEqual(a.snapshot().coverage["L4_patterns"], "partial:one")
        self.assertEqual(b.snapshot().coverage["L4_patterns"], "partial:one")

    def test_a_skipped_layer_stays_skipped(self):
        v, _ = make()
        v.record_layer("L3_dependency_cve", "skipped:disabled (RUN_SCA is not true)")
        v.note_incomplete("L3_dependency_cve", "reason")
        self.assertEqual(v.snapshot().coverage["L3_dependency_cve"], "skipped:disabled (RUN_SCA is not true)")

    def test_a_partial_layer_keeps_its_own_reason_and_gains_the_notes(self):
        v, _ = make()
        v.record_layer("L2_owasp_cwe", "partial:rulesets missing (secrets)")
        v.note_incomplete("L2_owasp_cwe", "another")
        self.assertEqual(v.snapshot().coverage["L2_owasp_cwe"], "partial:another; rulesets missing (secrets)")

    def test_notes_without_a_base_state_are_not_lost(self):
        v, _ = make()
        v.note_incomplete("L4_patterns", "no state yet")
        self.assertEqual(v.snapshot().coverage["L4_patterns"], "partial:no state yet")
        self.assertIsNone(v.coverage_state("L4_patterns"))
        self.assertNotIn("L5_per_language_sast", v.snapshot().coverage)

    def test_the_reasons_are_cut_to_300_characters(self):
        v, _ = make()
        v.record_layer("L4_patterns", "ran")
        for i in range(40):
            v.note_incomplete("L4_patterns", "reason number %02d is fairly long" % i)
        state = v.snapshot().coverage["L4_patterns"]
        self.assertTrue(state.startswith("partial:reason number 00 is fairly long; reason number 01"))
        self.assertEqual(len(state), len("partial:") + 300)
        v, _ = make()
        v.record_layer("L4_patterns", "ran")
        v.note_incomplete("L4_patterns", "x" * 300)
        self.assertEqual(v.snapshot().coverage["L4_patterns"], "partial:" + "x" * 300)

    def test_a_bad_note_is_refused(self):
        v, _ = make()
        for reason in ("", "a\nb", "a\rb", None):
            with self.subTest(reason=reason):
                with self.assertRaises(ValueError):
                    v.note_incomplete("L4_patterns", reason)                       # type: ignore[arg-type]

    def test_a_folded_state_is_a_valid_state(self):
        v, _ = make()
        v.record_layer("L4_patterns", "ran")
        v.note_incomplete("L4_patterns", "per-file time budget reached")
        w, _ = make()
        w.record_layer("L4_patterns", v.snapshot().coverage["L4_patterns"])        # accepted by the validator

    def test_the_snapshot_is_the_same_object_state_each_time(self):
        v, _ = make()
        v.record_layer("L4_patterns", "ran")
        v.note_incomplete("L4_patterns", "r")
        self.assertEqual(v.snapshot(), v.snapshot())
        self.assertEqual(v.snapshot().coverage["L4_patterns"], "partial:r")


# ── abort ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
class AbortTests(unittest.TestCase):
    def test_abort_before_any_other_event(self):
        v, console = make()
        v.abort("RecursionError")
        snap = v.snapshot()
        self.assertEqual(v.verdict, "FAIL")
        message = "engine:internal_error:RecursionError"
        self.assertEqual(snap.file_status[GLOBAL_FILE], "FAIL")
        self.assertEqual(snap.file_message[GLOBAL_FILE], "[FAIL] %s | " % message)
        self.assertEqual(snap.fail_messages[GLOBAL_FILE], message + " | ")
        self.assertEqual(snap.counters, Counters(0, 0, 1))
        self.assertEqual(len(snap.findings), 1)
        self.assertEqual(snap.findings[0].to_json(), {
            "tool": "engine", "category": "security", "severity": "HIGH", "rule_id": "internal_error",
            "rule_name": message, "file": "__global__", "line": None, "column": None, "message": message,
            "references": []})
        self.assertEqual(console.calls, [("fail_line", "[__global__] " + message)])
        for layer in REQUIRED:
            self.assertEqual(snap.coverage[layer], "skipped:engine aborted (RecursionError)", layer)
        for layer in OPTIONAL:
            self.assertNotIn(layer, snap.coverage)

    def test_abort_keeps_the_states_that_exist_and_fills_the_rest(self):
        v, _ = make()
        v.record_layer("L4_patterns", "ran")
        v.record_layer("L1_malware", "skipped:clamav not installed")
        v.record_layer("L6_licence", "ran")
        v.note_incomplete("L4_patterns", "r")
        v.abort("MemoryError")
        cov = v.snapshot().coverage
        self.assertEqual(cov["L4_patterns"], "partial:r")
        self.assertEqual(cov["L1_malware"], "skipped:clamav not installed")
        self.assertEqual(cov["L6_licence"], "ran")
        self.assertEqual(cov["L5_per_language_sast"], "skipped:engine aborted (MemoryError)")
        self.assertNotIn("L1_ioc_yara", cov)

    def test_abort_cannot_be_downgraded_by_the_allowlist_or_the_threshold(self):
        v, _ = make(Allowlist({("engine", "__global__"): "x", ("internal_error", "__global__"): "x"}), threshold=4,
                    min_severity="critical")
        v.abort("ValueError")
        self.assertEqual(v.verdict, "FAIL")
        self.assertEqual(v.counters.fail, 1)

    def test_abort_after_other_events_and_twice(self):
        v, _ = make()
        v.record_pass(path("a"))
        v.record_warn(None, "w")
        v.abort("KeyError")
        v.abort("KeyError")
        snap = v.snapshot()
        self.assertEqual(snap.counters, Counters(1, 1, 2))
        self.assertEqual(snap.file_status[GLOBAL_FILE], "FAIL")
        self.assertEqual(snap.file_message[GLOBAL_FILE],
                         "[WARN] w | [FAIL] engine:internal_error:KeyError | [FAIL] engine:internal_error:KeyError | ")

    def test_the_reason_is_made_safe(self):
        v, _ = make()
        v.abort("Bad\nName\x1b[31m‮")
        snap = v.snapshot()
        message = snap.findings[0].message
        self.assertTrue(message.startswith("engine:internal_error:Bad?Name"))
        for text in (message, snap.coverage["L4_patterns"]):
            self.assertEqual([c for c in text if c < " " or c == "\x7f" or c == "‮"], [])
        w, _ = make()
        w.record_layer("L4_patterns", snap.coverage["L4_patterns"])                # still a valid state
        v, _ = make()
        v.abort("")
        self.assertEqual(v.snapshot().findings[0].message, "engine:internal_error:unknown")
        v, _ = make()
        v.abort("X" * 5000)
        self.assertLess(len(v.snapshot().findings[0].message), 200)

    def test_abort_state_is_recorded_even_if_the_console_fails(self):
        v, _ = make(console=ExplodingConsole())
        with self.assertRaises(RuntimeError):
            v.abort("Boom")
        self.assertEqual(v.verdict, "FAIL")
        self.assertEqual(v.snapshot().coverage["L4_patterns"], "skipped:engine aborted (Boom)")
        self.assertEqual(len(v.snapshot().findings), 1)


# ── snapshot ───────────────────────────────────────────────────────────────────────────────────────────────────────────
class SnapshotTests(unittest.TestCase):
    def busy(self):
        v, _ = make()
        v.record_pass(path("a"))
        v.record_warn(path("b"), "w")
        v.record_fail(path("c"), "CWE-1:x")
        v.record_layer("L4_patterns", "ran")
        v.note_incomplete("L4_patterns", "r")
        return v

    def test_idempotent(self):
        v = self.busy()
        self.assertEqual(v.snapshot(), v.snapshot())
        before = (v.counters, v.events, v.verdict, v.coverage_state("L4_patterns"))
        v.snapshot()
        self.assertEqual(before, (v.counters, v.events, v.verdict, v.coverage_state("L4_patterns")))

    def test_the_snapshot_is_a_frozen_value_made_of_read_only_views(self):
        snap = self.busy().snapshot()
        self.assertIsInstance(snap, Snapshot)
        for name in ("file_status", "file_message", "fail_messages", "coverage"):
            mapping = getattr(snap, name)
            self.assertIsInstance(mapping, collections.abc.Mapping)
            self.assertNotIsInstance(mapping, dict, name)
            with self.assertRaises(TypeError):
                mapping["x"] = "y"                                                  # type: ignore[index]
            with self.assertRaises(TypeError):
                del mapping[next(iter(mapping))]                                    # type: ignore[attr-defined]
        self.assertIsInstance(snap.findings, tuple)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snap.verdict = "PASS"                                                   # type: ignore[misc]

    def test_later_events_do_not_change_an_earlier_snapshot(self):
        v = self.busy()
        earlier = v.snapshot()
        copy = (dict(earlier.file_status), dict(earlier.file_message), dict(earlier.fail_messages),
                dict(earlier.coverage), earlier.findings, earlier.counters, earlier.verdict)
        v.record_pass(path("a"))
        v.record_warn(path("b"), "more")
        v.record_fail(path("c"), "CWE-2:y")
        v.record_fail(path("d"), "CWE-3:z")
        v.record_layer("L5_per_language_sast", "ran")
        v.note_incomplete("L4_patterns", "another")
        after = (dict(earlier.file_status), dict(earlier.file_message), dict(earlier.fail_messages), dict(earlier.coverage),
                 earlier.findings, earlier.counters, earlier.verdict)
        self.assertEqual(copy, after)
        self.assertNotEqual(v.snapshot(), earlier)

    def test_contents(self):
        snap = self.busy().snapshot()
        self.assertEqual(snap.verdict, "FAIL")
        self.assertEqual(snap.counters, Counters(1, 1, 1))
        self.assertEqual(dict(snap.file_status), {path("a"): "PASS", path("b"): "WARN", path("c"): "FAIL"})
        self.assertEqual(dict(snap.file_message), {path("a"): "", path("b"): "[WARN] w | ", path("c"): "[FAIL] CWE-1:x | "})
        self.assertEqual(dict(snap.fail_messages), {path("c"): "CWE-1:x | "})
        self.assertEqual(dict(snap.coverage), {"L4_patterns": "partial:r"})
        self.assertEqual([r.message for r in snap.findings], ["CWE-1:x"])

    def test_findings_are_in_the_order_recorded(self):
        v, _ = make()
        for i in (3, 1, 2):
            v.record_fail(path("f%d" % i), "CWE-%d:m" % i)
        self.assertEqual([r.rule_id for r in v.snapshot().findings], ["CWE-3", "CWE-1", "CWE-2"])


# ── the console and the module itself ──────────────────────────────────────────────────────────────────────────────────
class ConsoleAndStructureTests(unittest.TestCase):
    def test_what_is_printed(self):
        v, console = make(Allowlist({("CWE-1", "a"): "r"}))
        v.record_pass(path("a"))
        v.record_warn(path("a"), "a warning")
        v.record_fail(path("a"), "CWE-1:allowed")
        v.record_fail(path("b"), "x:LOW:low")
        v.record_fail(path("c"), "CWE-2:real")
        v.record_warn_once("k", None, "once")
        v.record_warn_once("k", None, "once")
        self.assertEqual(console.calls, [
            ("warn", "a warning"),
            ("warn", "ALLOWED:CWE-1:allowed (reason: r)"),
            ("warn", "LOW_SEV(below --min-severity high):x:LOW:low"),
            ("fail_line", "[%s] CWE-2:real" % path("c")),
            ("warn", "once"),
        ])

    def test_state_is_recorded_before_the_console_is_asked(self):
        # a console that fails must not make a FAIL disappear from the report
        v, _ = make(console=ExplodingConsole())
        with self.assertRaises(RuntimeError):
            v.record_fail(path("a"), "CWE-1:x")
        self.assertEqual(v.verdict, "FAIL")
        self.assertEqual(v.counters.fail, 1)
        self.assertEqual(v.snapshot().findings[0].message, "CWE-1:x")
        self.assertEqual(v.snapshot().file_status[path("a")], "FAIL")
        with self.assertRaises(RuntimeError):
            v.record_warn(path("b"), "w")
        self.assertEqual(v.counters.warn, 1)
        self.assertEqual(v.snapshot().file_message[path("b")], "[WARN] w | ")

    @unittest.skipUnless(real_console_works(), "transit.console is not implemented yet")
    def test_with_the_real_console(self):
        from transit.console import Console
        out, err = io.BytesIO(), io.BytesIO()
        v = Verdict(SCAN, Allowlist({}), threshold=3, min_severity="high",
                    console=Console("normal", out=out, err=err, err_is_tty=False))
        v.record_warn(None, "a warning\x1b]0;x\x07")
        v.record_fail(path("a"), "CWE-1:bad\x1b")
        self.assertEqual(out.getvalue(), b"")
        text = err.getvalue().decode("utf-8")
        self.assertIn("a warning", text)
        self.assertIn("CWE-1:bad", text)
        self.assertNotIn("\x07", text)

    def test_imports_only_the_console_and_the_findings_module(self):
        tree = ast.parse((ROOT / "transit" / "verdict.py").read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module)
        engine_imports = {n for n in names if n == "transit" or n.startswith("transit.")}
        self.assertLessEqual(engine_imports, {"transit.console", "transit.findings"})
        for forbidden in ("re", "subprocess", "os", "sys", "threading"):
            self.assertNotIn(forbidden, {n.split(".")[0] for n in names})
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"print", "eval", "exec", "open", "compile"})

    def test_no_module_level_mutable_state(self):
        from transit import console as console_module
        for name, value in vars(verdict_module).items():
            if name.startswith("__") or any(getattr(m, name, None) is value for m in (findings_module, console_module)):
                continue                                                          # a name imported from another module
            self.assertNotIsInstance(value, (list, dict, set), name)


if __name__ == "__main__":
    unittest.main()
