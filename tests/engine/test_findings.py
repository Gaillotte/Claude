"""Tests of transit/findings.py (WP-02): the severity classifier, the finding record, the allowlist, json_safe and
neutralise_detail. Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_findings.py"

Where the bash engine is the oracle (docs/python_engine_design.md section 11) the functions of scan_pipeline.sh itself
(``_classify_severity``, ``_emit_finding`` and the allowlist loader) are cut out of the script and run by real bash, so the
table of expected values cannot drift from what the reference engine does. A token-shaped credential is never written
contiguously in this file.
"""
from __future__ import annotations

import ast
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from transit import findings  # noqa: E402
from transit.findings import (  # noqa: E402
    Allowlist, FindingRecord, Severity, allowlist_tokens, build_record, classify_severity, join_scan_path,
    json_safe, neutralise_detail, parse_allowlist, relative_to_scan_dir)

BASH = shutil.which("bash")
SCRIPT = ROOT / "scan_pipeline.sh"
GOLDEN = ROOT / "tests" / "conformance" / "golden"
HAVE_ORACLE = bool(BASH) and SCRIPT.exists()
ORACLE_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}


# ── the bash oracle ────────────────────────────────────────────────────────────────────────────────────────────────
def _script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _bash_severity_functions() -> str:
    """``_classify_severity``, ``_write_finding`` and ``_emit_finding`` exactly as scan_pipeline.sh defines them."""
    text = _script_text()
    start = text.index("_classify_severity() {")
    end = text.index("\nrecord_fail() {", start)
    return text[start:end]


def bash_severities(messages: list[str]) -> list[str]:
    script = "set -u\n" + _bash_severity_functions() + (
        '\nfor m in "$@"; do _classify_severity "$m"; printf \'%s\\0\' "$_MSG_SEV_NAME"; done\n')
    out = subprocess.run([BASH, "-c", script, "oracle", *messages], capture_output=True, env=ORACLE_ENV, timeout=300)
    if out.returncode != 0:
        raise AssertionError("oracle failed: %r" % out.stderr[-400:])
    return [part.decode() for part in out.stdout.split(b"\0")[:-1]]


def bash_records(pairs: list[tuple[str, str]], scan_dir: str) -> list[dict]:
    """The JSON object ``_emit_finding`` writes for each (file, message), one per pair."""
    script = "set -u\nSCAN_DIR=\"$1\"; FINDINGS_JL=\"$2\"; shift 2\n" + _bash_severity_functions() + (
        '\nwhile [ "$#" -ge 2 ]; do _emit_finding "$1" "$2"; shift 2; done\n')
    with tempfile.TemporaryDirectory() as tmp:
        jl = os.path.join(tmp, "findings.jl")
        Path(jl).write_bytes(b"")
        args = [a for pair in pairs for a in pair]
        out = subprocess.run([BASH, "-c", script, "oracle", scan_dir, jl, *args], capture_output=True,
                             env=ORACLE_ENV, timeout=600)
        if out.returncode != 0:
            raise AssertionError("oracle failed: %r" % out.stderr[-400:])
        lines = Path(jl).read_bytes().decode("utf-8").splitlines()
    return [json.loads(line) for line in lines]


def bash_allowlist(raw: bytes) -> dict[bytes, bytes]:
    """ALLOW_MAP as the loader of scan_pipeline.sh builds it, key ``rule::path`` -> reason (empty reasons dropped)."""
    text = _script_text()
    start = text.index("declare -A ALLOW_MAP=()")
    end = text.index('info "Allowlist: ${#ALLOW_MAP[@]} exception(s) loaded"')
    script = ("set -u\ninfo() { :; }\n" + text[start:end] +
              '\nfi\nfor k in "${!ALLOW_MAP[@]}"; do printf "%s\\0%s\\0" "$k" "${ALLOW_MAP[$k]}"; done\n')
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, ".transit-allow.json").write_bytes(raw)
        out = subprocess.run([BASH, "-c", script], capture_output=True, timeout=60,
                             env=dict(ORACLE_ENV, SCAN_DIR=tmp))
    parts = out.stdout.split(b"\0")[:-1]
    return {parts[i]: parts[i + 1] for i in range(0, len(parts), 2) if parts[i + 1]}


def python_allowlist_keys(al: Allowlist) -> dict[bytes, bytes]:
    return {(rule + "::" + path).encode("utf-8", "surrogateescape"): reason.encode("utf-8", "surrogateescape")
            for (rule, path), reason in al.entries.items() if reason}


# ── corpora ────────────────────────────────────────────────────────────────────────────────────────────────────────
#: The 23 messages of E6 (contract 6.3), written from the rules of the contract. The oracle re-runs all of them.
SEVERITY_CASES = [
    ("gitleaks:generic-api-key:line3", "CRITICAL"),
    ("gitleaks:secrets_detected:LOW:", "CRITICAL"),
    ("clamav:malware_detected", "CRITICAL"),
    ("clamav:x:INFO:", "CRITICAL"),
    ("semgrep[p/owasp-top-ten]:python.lang.eval:line12:ERROR:Eval detected", "HIGH"),
    ("semgrep[p/owasp-top-ten]:python.lang.eval:line12:WARNING:Eval detected", "MEDIUM"),
    ("semgrep[p/owasp-top-ten]:python.lang.eval:line12:INFO:Eval detected", "INFO"),
    ("semgrep[p/owasp-top-ten]:python.lang.eval:line12:CRITICAL:Eval detected", "CRITICAL"),
    ("semgrep[p/owasp-top-ten]:python.lang.eval:line12:BOGUS:Eval detected", "HIGH"),
    ("semgrep[p/x]:rule:line3:ERROR:quoted :LOW: from the repository", "HIGH"),
    ("semgrep[p/x]:rule:line3:WARNING:tail :CRITICAL:", "MEDIUM"),
    ("semgrep[p/x]:rule:INFO:no line field, so the fixed position does not match", "HIGH"),
    ("semgrep[p/x]:rule:ABCD:INFO:m", "HIGH"),                           # the field after the rule must be line<N>
    ("semgrep[p/x:rule:line3:INFO:the bracket never closes", "HIGH"),
    ("semgrep[p/x]rule:line3:INFO:no colon after the bracket", "HIGH"),
    ("semgrep[p/x]:rule:line3:INFO", "HIGH"),
    ("semgrep[p/x]:rule:line:INFO:digits are optional", "INFO"),
    ("semgrep[a]:r:line1:INFO:txt]:r:line2:ERROR:", "INFO"),            # the first "]" closes the ruleset
    ("semgrep[a]:r:line1:ERROR:txt]:r:line2:INFO:", "HIGH"),
    ("semgrep[p/x]:r:line\u0663:INFO:m", "HIGH"),                        # [0-9], not any Unicode digit
    ("CWE-798:hardcoded_credential", "HIGH"),
    ("OWASP-A09:logging_failure", "HIGH"),
    ("x:LOW:and:CRITICAL:", "LOW"),
    ("a:INFO:b:LOW:c", "INFO"),
    ("a:medium:b", "MEDIUM"),
    ("a:Warning:b", "MEDIUM"),
    ("a:ERROR:b", "HIGH"),
    ("a:critical:b", "CRITICAL"),
    ("a:medium:b:high:c", "MEDIUM"),
    ("a:high:b:warning:c", "MEDIUM"),
    ("bandit:Severity: MEDIUM:B602", "HIGH"),
    ("bandit:Severity: HIGH:B602", "HIGH"),
    ("foo:[HIGH]:bar", "HIGH"),
    ("foo:[LOW]:bar", "HIGH"),
    ("a: LOW:b", "HIGH"),
    ("a:LOW b", "HIGH"),
    ("a:CRITICAL", "HIGH"),
    (":critical:", "CRITICAL"),
    ("scancode_vuln:CVE-2021-1[HIGH] in pkg==1.0", "HIGH"),
    ("scancode_vuln:CVE-2021-1[LOW] in pkg==1.0", "HIGH"),
    ("GITLEAKS:upper_case_prefix", "HIGH"),
    ("gitleaks", "HIGH"),
    ("", "HIGH"),
    ("a:\u0130NFO:b", "HIGH"),
]

#: The 26 messages of E6 for the record builder: (message, tool, category, rule_id, rule_name or None for "the message",
#: references, line). ``None`` rule_name means the whole message.
RECORD_CASES = [
    ("semgrep[p/owasp-top-ten]:python.lang.eval:line12:ERROR:Eval detected", "semgrep", "sast", "python.lang.eval",
     None, (), 12),
    ("semgrep[/opt/rules/x.yaml]:CWE-78:line7:WARNING:cmd", "semgrep", "sast", "CWE-78", None, (), 7),
    ("semgrep[no-rule-part", "semgrep", "sast", "semgrep[no-rule-part", None, (), None),
    ("detect-secrets:2_high_entropy_string(s)", "detect-secrets", "secret", "high_entropy_string",
     "High Entropy String", ("CWE-798",), None),
    ("clamav:malware_detected", "clamav", "malware", "malware_detected", "Malware Detected", (), None),
    ("gitleaks:generic-api-key:line3", "gitleaks", "secret", "generic-api-key", "Secret Detected", ("CWE-798",), 3),
    ("gitleaks:secrets_detected", "gitleaks", "secret", "secrets_detected", "Secret Detected", ("CWE-798",), None),
    ("gitleaks:more_leaks_not_listed_12", "gitleaks", "secret", "more_leaks_not_listed_12", "Secret Detected",
     ("CWE-798",), None),
    ("yara:ioc_match:rule1.yar", "yara", "ioc", "ioc_match:rule1.yar", "IOC Match", (), None),
    ("bandit:Severity: HIGH:B602", "bandit", "sast", " HIGH:B602", "Bandit Finding", (), None),
    ("bandit:abc", "bandit", "sast", "bandit:abc", "Bandit Finding", (), None),
    ("cppcheck:error: Null pointer dereference", "cppcheck", "sast", "error: Null pointer dereference",
     "Cppcheck Finding", (), None),
    ("shellcheck:warnings", "shellcheck", "sast", "warnings", "ShellCheck Finding", (), None),
    ("CWE-798:hardcoded_credential", "grep-pattern", "cwe", "CWE-798", "hardcoded_credential", ("CWE-798",), None),
    ("CWE-22:jar_entry_path_traversal_zip_slip(1: ../x)", "grep-pattern", "cwe", "CWE-22",
     "jar_entry_path_traversal_zip_slip(1: ../x)", ("CWE-22",), None),
    ("CWE-89:SQL_injection:line9", "grep-pattern", "cwe", "CWE-89", "SQL_injection:line9", ("CWE-89",), 9),
    ("OWASP-A09:logging_failure", "grep-pattern", "owasp", "OWASP-A09", "logging_failure", (), None),
    ("jar:vendored_compiled_code_not_reviewable", "jar", "security", "vendored_compiled_code_not_reviewable", None,
     (), None),
    ("trivy:3_vulnerable_dependencies", "trivy", "security", "3_vulnerable_dependencies", None, (), None),
    ("powershell:x:y", "powershell", "security", "x", None, (), None),
    ("CVE-2021-44228:Log4Shell_JNDI_injection", "unknown", "security", "", None, (), None),
    ("gitleaks missing \u2014 secret scan skipped", "unknown", "security", "", None, (), None),
    ("x:y", "unknown", "security", "", None, (), None),
    ("CWE-123 and no colon", "unknown", "security", "", None, (), None),
    ("OWASP-A09 and no colon", "unknown", "security", "", None, (), None),
    ("Upper:case", "unknown", "security", "", None, (), None),
    ("engine:nothing_scanned", "engine", "security", "nothing_scanned", None, (), None),
    ("engine:scan_incomplete:universal:time_budget", "engine", "security", "scan_incomplete", None, (), None),
    ("engine:internal_error:RecursionError", "engine", "security", "internal_error", None, (), None),
]


def corpus_golden_findings() -> list[dict]:
    out = []
    for path in sorted(GOLDEN.glob("*.json")):
        report = json.loads(path.read_text(encoding="utf-8")).get("report")
        if report:
            out.extend(report["findings"])
    return out


def message_fuzz(count: int, seed: int) -> list[str]:
    rnd = random.Random(seed)
    pieces = [":", ":", ":", "info", "INFO", "low", "LOW", "Warning", "medium", "error", "high", "HIGH", "critical",
              "semgrep[", "]", "]:", "line", "12", "x", " ", "gitleaks:", "clamav:", "\n", "\u00e9", "\u0130", "CWE-1:",
              "bandit:", "[", "WARNING", "ERROR", "_", "p/o"]
    out = []
    for _ in range(count):
        out.append("".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 14))))
    return out


# ── classify_severity ──────────────────────────────────────────────────────────────────────────────────────────────
class ClassifySeverityTests(unittest.TestCase):
    def test_table_of_e6(self):
        for message, expected in SEVERITY_CASES:
            with self.subTest(message=message):
                got = classify_severity(message)
                self.assertIsInstance(got, Severity)
                self.assertEqual(got.name, expected)
                self.assertEqual(got.number, findings.SEVERITY_NUMBER[expected])

    def test_numbers(self):
        self.assertEqual(dict(findings.SEVERITY_NUMBER),
                         {"INFO": 1, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4})

    def test_first_hit_wins_in_the_documented_order(self):
        # INFO, then LOW, then WARNING/MEDIUM, then ERROR/HIGH, then CRITICAL.
        order = ["info", "low", "warning", "error", "critical"]
        expected = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for i, word in enumerate(order):
            later = "".join(":%s:" % w for w in order[i + 1:])
            with self.subTest(word=word):
                self.assertEqual(classify_severity("m" + later + ":%s:" % word).name, expected[i])

    def test_semgrep_is_read_from_the_fixed_position_only(self):
        base = "semgrep[p/x]:rule:line3:%s:"
        for word, expected in [("ERROR", "HIGH"), ("HIGH", "HIGH"), ("WARNING", "MEDIUM"), ("INFO", "INFO"),
                               ("CRITICAL", "CRITICAL"), ("error", "HIGH"), ("Info", "INFO"), ("ODD", "HIGH")]:
            for tail in ("", "text", "text :LOW: :INFO: :CRITICAL:", ":LOW:"):
                with self.subTest(word=word, tail=tail):
                    self.assertEqual(classify_severity(base % word + tail).name, expected)

    def test_prefix_beats_a_marker(self):
        for message in ("gitleaks:a:LOW:b", "clamav:a:INFO:", "gitleaks:", "clamav:"):
            self.assertEqual(classify_severity(message).name, "CRITICAL")

    def test_matches_the_bash_function(self):
        if not HAVE_ORACLE:
            self.skipTest("bash or scan_pipeline.sh not available")
        messages = [m for m, _ in SEVERITY_CASES] + message_fuzz(500, 20261113) + [
            f["message"] for f in corpus_golden_findings()[:60]]
        expected = bash_severities(messages)
        for message, want in zip(messages, expected):
            with self.subTest(message=message):
                self.assertEqual(classify_severity(message).name, want)

    def test_linear_time_on_hostile_input(self):
        hostile = [":" * 2_000_000, "semgrep[" + "]" * 1_000_000, "semgrep[x]:" + ":line1" * 300_000,
                   "semgrep[x]:r:line" + "9" * 1_000_000, ":low" * 400_000, "x" * 3_000_000]
        for message in hostile:
            started = time.monotonic()
            classify_severity(message)
            self.assertLess(time.monotonic() - started, 2.0, message[:20])


# ── relative_to_scan_dir / join_scan_path ──────────────────────────────────────────────────────────────────────────
class PathHelperTests(unittest.TestCase):
    def test_relative_to_scan_dir(self):
        cases = [
            ("/x/repo/a/b.py", "/x/repo", "a/b.py"),
            ("/x/repo", "/x/repo", "/x/repo"),             # a whole-directory finding stays the directory string
            ("/x/repository/a.py", "/x/repo", "/x/repository/a.py"),  # the prefix needs the slash
            ("/elsewhere/a.py", "/x/repo", "/elsewhere/a.py"),
            ("__global__", "/x/repo", "__global__"),
            ("repo/a.py", "repo", "a.py"),
            ("/x/repo/", "/x/repo", ""),
            ("/a/b", "/", "/a/b"),                         # bash: ${file#"//"} does not strip "/a/b"
            ("", "/x", ""),
        ]
        for file, scan_dir, expected in cases:
            with self.subTest(file=file, scan_dir=scan_dir):
                self.assertEqual(relative_to_scan_dir(file, scan_dir), expected)

    def test_join_scan_path(self):
        self.assertEqual(join_scan_path("/x/repo", "a/b.py"), "/x/repo/a/b.py")
        self.assertEqual(join_scan_path("repo", "a"), "repo/a")
        self.assertEqual(join_scan_path("/", "a/b"), "/a/b")
        self.assertEqual(join_scan_path("/", ""), "/")
        self.assertEqual(join_scan_path("/x", ""), "/x/")

    def test_join_then_relative_round_trips(self):
        for scan_dir in ("/x/repo", "repo", "/tmp//odd"):
            for rel in ("a", "a/b c/d.py", "-n.txt", "x\u00e9"):
                with self.subTest(scan_dir=scan_dir, rel=rel):
                    self.assertEqual(relative_to_scan_dir(join_scan_path(scan_dir, rel), scan_dir), rel)


# ── allowlist_tokens ───────────────────────────────────────────────────────────────────────────────────────────────
class AllowlistTokenTests(unittest.TestCase):
    def test_tokens(self):
        cases = {
            "CWE-798:hardcoded_credential": ("CWE-798", "hardcoded_credential"),
            "gitleaks:generic-api-key:line3": ("gitleaks", "generic-api-key"),
            "semgrep[p/x]:CWE-78:line1:ERROR:m": ("semgrep[p/x]", "CWE-78"),
            "a:b:c:d": ("a", "b"),
            "a:": ("a", ""),
            ":b": ("", "b"),
            ":": ("", ""),
            "no colon at all": ("no colon at all", "no colon at all"),
            "": ("", ""),
            "bandit:Severity: HIGH:B602": ("bandit", "Severity"),
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(allowlist_tokens(message), expected)


# ── build_record ───────────────────────────────────────────────────────────────────────────────────────────────────
class BuildRecordTests(unittest.TestCase):
    SCAN = "/scan/dir"

    def test_the_messages_of_e6(self):
        for message, tool, category, rule_id, rule_name, refs, line in RECORD_CASES:
            with self.subTest(message=message):
                rec = build_record(self.SCAN + "/src/a.py", message, self.SCAN)
                self.assertIsInstance(rec, FindingRecord)
                self.assertEqual(
                    (rec.tool, rec.category, rec.rule_id, rec.rule_name, rec.references, rec.line),
                    (tool, category, rule_id, rule_name if rule_name is not None else message, refs, line))
                self.assertEqual((rec.file, rec.message, rec.column), ("src/a.py", message, None))
                self.assertEqual(rec.severity, classify_severity(message).name)

    def test_file_field(self):
        cases = [
            (self.SCAN + "/src/a.py", self.SCAN, "src/a.py"),
            (self.SCAN, self.SCAN, "."),                      # a whole-directory finding
            ("/etc/passwd", self.SCAN, "/etc/passwd"),         # not under the scan directory: unchanged (E7)
            ("__global__", self.SCAN, "__global__"),
            ("/", "/", "."),
            ("repo/a", "repo", "a"),
            # a file called like the scan directory string is a file, not the directory
            ("repo/repo", "repo", "repo"),
        ]
        for file, scan_dir, expected in cases:
            with self.subTest(file=file, scan_dir=scan_dir):
                self.assertEqual(build_record(file, "CWE-1:x", scan_dir).file, expected)

    def test_line_is_the_first_line_marker_followed_by_digits(self):
        cases = {
            "x:line5": 5, "x:line007": 7, "x:line:y:line5": 5, "x:lines3": None, "x:line": None, "line5": None,
            "x:line1:line2": 1, "a:line99999999999:b": 99999999999, "x:lineA:line4z": 4,
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(build_record("/s/a", message, "/s").line, expected)

    def test_absurd_line_number_does_not_raise(self):
        # int() refuses 4300+ digits on Python 3.11+; a line number of more than 18 digits is not a line number
        for digits in (6000, 19):
            rec = build_record("/s/a", "x:line" + "9" * digits, "/s")
            self.assertIsNone(rec.line)
        self.assertEqual(build_record("/s/a", "x:line" + "9" * 18, "/s").line, 10 ** 18 - 1)

    def test_severity_override_is_used_only_for_a_known_name(self):
        message = "CWE-1:no_marker"
        self.assertEqual(build_record("/s/a", message, "/s").severity, "HIGH")
        self.assertEqual(build_record("/s/a", message, "/s", severity="LOW").severity, "LOW")
        self.assertEqual(build_record("/s/a", message, "/s", severity="critical").severity, "CRITICAL")
        self.assertEqual(build_record("/s/a", message, "/s", severity="WARNING").severity, "MEDIUM")
        self.assertEqual(build_record("/s/a", message, "/s", severity="ERROR").severity, "HIGH")
        self.assertEqual(build_record("/s/a", message, "/s", severity="bogus").severity, "HIGH")
        # an override replaces the classifier even against a marker in the message
        self.assertEqual(build_record("/s/a", "x:LOW:y", "/s", severity="CRITICAL").severity, "CRITICAL")
        self.assertEqual(build_record("/s/a", "x:LOW:y", "/s").severity, "LOW")

    def test_engine_message_with_an_empty_segment(self):
        rec = build_record("__global__", "engine:", "/s")
        self.assertEqual((rec.tool, rec.category, rec.rule_id), ("engine", "security", ""))
        rec = build_record("__global__", "engine::x", "/s")
        self.assertEqual((rec.tool, rec.rule_id), ("engine", ""))

    def test_prefix_length_bounds(self):
        self.assertEqual(build_record("/s/a", "a" * 31 + ":x", "/s").tool, "a" * 31)
        self.assertEqual(build_record("/s/a", "a" * 32 + ":x", "/s").tool, "unknown")
        self.assertEqual(build_record("/s/a", "ab:x", "/s").tool, "ab")
        self.assertEqual(build_record("/s/a", "a:x", "/s").tool, "unknown")
        self.assertEqual(build_record("/s/a", "ab:", "/s").tool, "unknown")      # the detail must be non-empty
        self.assertEqual(build_record("/s/a", "ab::c", "/s").tool, "unknown")

    def test_to_json_has_exactly_the_ten_fields(self):
        rec = build_record("/s/a.py", "CWE-798:hardcoded_credential", "/s")
        data = rec.to_json()
        self.assertEqual(set(data), {"tool", "category", "severity", "rule_id", "rule_name", "file", "line", "column",
                                     "message", "references"})
        self.assertEqual(data["references"], ["CWE-798"])
        self.assertIsInstance(data["references"], list)
        self.assertIsNone(data["line"])
        self.assertIsNone(data["column"])
        self.assertIn(data["category"], findings.CATEGORIES)

    def test_to_json_is_strict_utf8_for_a_hostile_name(self):
        name = os.fsdecode(b"bad\xfe\xffname\x1b]0;x\x07.py")
        rec = build_record(self.SCAN + "/" + name, "CWE-78:OS_command_injection_risk", self.SCAN)
        data = rec.to_json()
        self.assertEqual(data["file"], "bad\ufffd\ufffdname\x1b]0;x\x07.py")
        json.dumps(data, ensure_ascii=False).encode("utf-8")        # must not raise
        self.assertNotEqual(rec.file, data["file"])                  # the record itself is not changed

    def test_every_golden_finding_is_reproduced(self):
        golden = corpus_golden_findings()
        self.assertGreater(len(golden), 300)
        for f in golden:
            file = self.SCAN if f["file"] == "." else f["file"] if f["file"] == "__global__" else self.SCAN + "/" + f["file"]
            rec = build_record(file, f["message"], self.SCAN)
            self.assertEqual(rec.to_json(), dict(f, column=None), f["message"])   # the goldens drop the column
            self.assertEqual(classify_severity(f["message"]).name, f["severity"], f["message"])

    def test_matches_the_bash_function(self):
        if not HAVE_ORACLE:
            self.skipTest("bash or scan_pipeline.sh not available")
        scan = "/scan/dir"
        pairs = [(scan + "/src/a.py", c[0]) for c in RECORD_CASES]
        pairs += [(scan, "clamav:malware_detected"), ("/etc/passwd", "CWE-1:x:line4"), (scan + "/a b/\u00e9.py", "x:y")]
        pairs += [(scan + "/" + os.fsdecode(b"bad\xfe\xffname.py"), "CWE-78:OS_command_injection_risk")]
        pairs += [(scan + "/f.py", m) for m in message_fuzz(60, 77) if m]
        pairs += [(scan + "/f.py", f["message"]) for f in corpus_golden_findings()[:30]]
        expected = bash_records(pairs, scan)
        self.assertEqual(len(expected), len(pairs))
        for (file, message), want in zip(pairs, expected):
            with self.subTest(message=message, file=file):
                self.assertEqual(build_record(file, message, scan).to_json(), want)

    def test_linear_time_on_hostile_messages(self):
        hostile = [":line" * 300_000, "semgrep[" + "]" * 500_000, "CWE-" + ":" * 500_000, "a" * 2_000_000 + ":x",
                   "bandit:" + "b" * 1_000_000, "x:line" + "1" * 3000]
        for message in hostile:
            started = time.monotonic()
            build_record("/s/a", message, "/s")
            self.assertLess(time.monotonic() - started, 2.0, message[:20])


# ── Allowlist and parse_allowlist ──────────────────────────────────────────────────────────────────────────────────
def entry(rule="CWE-798", path="a.py", reason="r") -> dict:
    return {"rule": rule, "path": path, "reason": reason}


def dump(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


#: The 14 variants of E3. (name, raw bytes, probe message, probe path, expected reason with bash semantics,
#: expected reason with D-010 strict semantics)
E3 = [
    ("rule", dump([entry()]), "CWE-798:hardcoded_credential", "a.py", "r", "r"),
    ("second_token", dump([entry(rule="hardcoded_credential")]), "CWE-798:hardcoded_credential", "a.py", "r", "r"),
    ("empty_reason", dump([entry(reason="")]), "CWE-798:hardcoded_credential", "a.py", None, None),
    ("missing_reason", dump([{"rule": "CWE-798", "path": "a.py"}]), "CWE-798:hardcoded_credential", "a.py", None,
     None),
    ("dot_slash_path", dump([entry(path="./a.py")]), "CWE-798:hardcoded_credential", "a.py", None, None),
    ("absolute_path", dump([entry(path="/tmp/x/a.py")]), "CWE-798:hardcoded_credential", "a.py", None, None),
    ("not_a_list", dump({"rule": "CWE-798", "path": "a.py", "reason": "r"}), "CWE-798:x", "a.py", None, None),
    ("bad_json", b"[{not json", "CWE-798:x", "a.py", None, None),
    ("numeric_rule_first", dump([entry(rule=5, path="z"), entry()]), "CWE-798:x", "a.py", None, "r"),
    ("upper_case_rule", dump([entry(rule="cwe-798")]), "CWE-798:x", "a.py", None, None),
    ("glob_path", dump([entry(path="*.py")]), "CWE-798:x", "a.py", None, None),
    ("newline_in_reason", dump([entry(reason="line1\nline2")]), "CWE-798:x", "a.py", "line1", "line1\nline2"),
    ("numeric_reason_first", dump([entry(reason=7, path="z"), entry()]), "CWE-798:x", "a.py", None, "r"),
    ("null_path_first", dump([entry(path=None, rule="Q"), entry()]), "CWE-798:x", "a.py", None, "r"),
]


class AllowlistLookupTests(unittest.TestCase):
    def test_exact_match_on_either_token(self):
        al = Allowlist({("CWE-798", "a.py"): "first", ("hardcoded_credential", "b.py"): "second"})
        self.assertEqual(len(al), 2)
        self.assertEqual(al.lookup("CWE-798:hardcoded_credential", "a.py"), "first")
        self.assertEqual(al.lookup("CWE-798:hardcoded_credential", "b.py"), "second")
        self.assertIsNone(al.lookup("CWE-798:hardcoded_credential", "c.py"))
        self.assertIsNone(al.lookup("cwe-798:hardcoded_credential", "a.py"))   # case-sensitive
        self.assertIsNone(al.lookup("CWE-798:hardcoded_credential", "./a.py"))
        self.assertIsNone(al.lookup("CWE-798:hardcoded_credential", "A.py"))

    def test_first_token_wins_and_an_empty_reason_falls_through(self):
        al = Allowlist({("CWE-798", "a.py"): "one", ("hardcoded_credential", "a.py"): "two"})
        self.assertEqual(al.lookup("CWE-798:hardcoded_credential", "a.py"), "one")
        al = Allowlist({("CWE-798", "a.py"): "", ("hardcoded_credential", "a.py"): "two"})
        self.assertEqual(al.lookup("CWE-798:hardcoded_credential", "a.py"), "two")
        al = Allowlist({("CWE-798", "a.py"): "", ("hardcoded_credential", "a.py"): ""})
        self.assertIsNone(al.lookup("CWE-798:hardcoded_credential", "a.py"))

    def test_whole_message_when_there_is_no_colon(self):
        al = Allowlist({("bandit missing", "a.py"): "why"})
        self.assertEqual(al.lookup("bandit missing", "a.py"), "why")

    def test_semgrep_second_token_is_the_check_id(self):
        al = Allowlist({("CWE-78", "a.py"): "why"})
        self.assertEqual(al.lookup("semgrep[p/x]:CWE-78:line1:INFO:m", "a.py"), "why")

    def test_an_engine_message_never_matches(self):
        al = Allowlist({("engine", "__global__"): "x", ("internal_error", "__global__"): "x",
                        ("engine:internal_error", "__global__"): "x", ("nothing_scanned", "/s"): "x"})
        for message in ("engine:internal_error:RecursionError", "engine:nothing_scanned", "engine:x"):
            self.assertIsNone(al.lookup(message, "__global__"))
            self.assertIsNone(al.lookup(message, "/s"))
        # the exemption is the prefix and nothing else
        self.assertEqual(Allowlist({("Engine", "p"): "x"}).lookup("Engine:x", "p"), "x")
        self.assertEqual(Allowlist({("enginex", "p"): "x"}).lookup("enginex:y", "p"), "x")

    def test_the_dataclass_is_frozen_and_the_parsed_mapping_read_only(self):
        al, _ = parse_allowlist(dump([entry()]))
        with self.assertRaises(Exception):
            al.entries = {}                                       # frozen dataclass
        with self.assertRaises(TypeError):
            al.entries[("x", "y")] = "z"                          # read-only mapping

    def test_empty_allowlist(self):
        self.assertEqual(len(Allowlist({})), 0)
        self.assertIsNone(Allowlist({}).lookup("CWE-1:x", "a"))


class ParseAllowlistTests(unittest.TestCase):
    def test_the_14_variants_of_e3(self):
        for name, raw, message, path, bash_reason, strict_reason in E3:
            with self.subTest(name=name, mode="bash"):
                al, _ = parse_allowlist(raw)
                self.assertEqual(al.lookup(message, path), bash_reason)
            with self.subTest(name=name, mode="strict"):
                al, _ = parse_allowlist(raw, strict=True)
                self.assertEqual(al.lookup(message, path), strict_reason)

    def test_bash_mode_equals_the_bash_loader(self):
        if not HAVE_ORACLE:
            self.skipTest("bash or scan_pipeline.sh not available")
        samples = [raw for _, raw, *_ in E3] + [
            dump([entry(rule="A", path="p", reason="x"), entry(rule="A", path="p", reason="")]),     # a later empty wins
            dump([entry(rule="A", path="p", reason="x"), entry(rule="A", path="p", reason="y")]),
            dump([entry(rule="", path="p"), entry(rule="B", path="q")]),
            dump([1, "a", None, [], entry(rule="B", path="q")]),
            dump([entry(rule="B", path=" sp ace/\u00e9.py", reason="  keep  me  ")]),
            dump([{"rule": "B", "path": "q"}, {"rule": "C", "path": "q", "reason": "x"}]),
            dump([{"rule": "B", "reason": "x"}]),
            dump([entry(rule=True, path="z"), entry(rule="B")]),
            dump([entry(reason=None, path="z"), entry(rule="B")]),
            dump([entry(reason=["l"], path="z"), entry(rule="B")]),
            dump([entry(reason=1.5), entry(rule="B")]),
            b'[{"rule":"B","path":"p","reason":"x"},]',
            b'[{"rule":"B","path":"p","reason":"x"}] junk',
            b'[{"rule":"B","rule":"C","path":"p","reason":"x"}]',
            b'\xef\xbb\xbf[{"rule":"B","path":"p","reason":"x"}]',
            b'[{"rule":"B","path":"p","reason":"\\u00e9\\ud83d\\ude00"}]',
            b'[{"rule":"B","path":"\\udcff","reason":"x"}, {"rule":"C","path":"p","reason":"x"}]',
            b'[{"rule":"B","path":"\\ud800","reason":"x"}, {"rule":"C","path":"p","reason":"x"}]',
            b"\xff\xfe[]", b"", b"null", b"[]", b"{}", b"  [ ]  ", b"[NaN, 1e999]",
            dump([entry(rule="B", path="p", reason="cr\r")]),
            dump([entry(rule="B", path="p", reason="tab\tsep")]),
            dump([entry(rule="B", path="p", reason="  ")]),
            dump([entry(rule="B", path="p", reason="\nnothing before")]),
        ]
        for raw in samples:
            with self.subTest(raw=raw[:80]):
                al, _ = parse_allowlist(raw)
                self.assertEqual(python_allowlist_keys(al), bash_allowlist(raw))

    def test_bash_mode_drops_what_bash_splits_on(self):
        # U+0001 in a rule or a path: bash splits on it and would build an entry the file does not state.
        raw = dump([entry(rule="A\x01B", path="p", reason="x"), entry(rule="C", path="p\x01q", reason="x"),
                    entry(rule="D", path="p", reason="x")])
        al, _ = parse_allowlist(raw)
        self.assertEqual(dict(al.entries), {("D", "p"): "x"})
        # a newline in a rule or path would make bash read a second, invented entry
        raw = dump([entry(rule="A\nB", path="p", reason="x"), entry(rule="C", path="p\nq", reason="x"),
                    entry(rule="D", path="p", reason="x")])
        al, _ = parse_allowlist(raw)
        self.assertEqual(dict(al.entries), {("D", "p"): "x"})

    def test_a_newline_in_a_reason_cannot_inject_an_entry(self):
        raw = dump([entry(rule="R", path="p", reason="ok\nX\x01Y\x01Z")])
        al, _ = parse_allowlist(raw)
        self.assertEqual(dict(al.entries), {("R", "p"): "ok"})        # bash would also have created ("X", "Y")

    def test_a_reason_that_is_only_a_newline_is_empty_so_never_honoured(self):
        al, _ = parse_allowlist(dump([entry(reason="\nabc")]))
        self.assertIsNone(al.lookup("CWE-798:x", "a.py"))

    def test_invalid_utf8_and_a_byte_order_mark_are_not_repaired(self):
        for raw in (b'[{"rule":"A","path":"p\xff","reason":"x"}]', b'\xef\xbb\xbf[{"rule":"A","path":"p","reason":"x"}]',
                    b'[{"rule":"A","path":"p","reason":"x\xc3"}]'):
            for strict in (False, True):
                al, _ = parse_allowlist(raw, strict=strict)
                self.assertEqual(len(al), 0, raw)

    def test_a_malformed_member_stops_the_loop_in_bash_mode_only(self):
        for bad in ({"rule": 5}, {"path": None}, {"reason": 7}, {"rule": ["a"]}, {"reason": True}, {"path": {}}):
            raw = dump([entry(rule="A", path="p"), dict(entry(rule="B", path="p"), **bad), entry(rule="C", path="p")])
            with self.subTest(bad=bad):
                al, _ = parse_allowlist(raw)
                self.assertEqual({r for r, _ in al.entries}, {"A"})
                al, notes = parse_allowlist(raw, strict=True)
                self.assertEqual({r for r, _ in al.entries}, {"A", "C"})
                self.assertEqual(len(notes), 1)

    def test_a_non_object_entry_is_skipped_in_both_modes(self):
        raw = dump([1, "x", None, [], True, entry(rule="B", path="q")])
        for strict in (False, True):
            al, _ = parse_allowlist(raw, strict=strict)
            self.assertEqual(dict(al.entries), {("B", "q"): "r"})

    def test_a_lone_surrogate_that_cannot_become_a_name_stops_bash_mode(self):
        raw = b'[{"rule":"B","path":"\\ud800","reason":"x"}, {"rule":"C","path":"p","reason":"x"}]'
        al, _ = parse_allowlist(raw)
        self.assertEqual(len(al), 0)
        al, notes = parse_allowlist(raw, strict=True)
        self.assertEqual(dict(al.entries), {("C", "p"): "x"})
        self.assertEqual(len(notes), 1)
        # a surrogate that stands for an undecodable file name byte is a legitimate way to name such a file
        raw = b'[{"rule":"B","path":"bad\\udcfe.py","reason":"x"}]'
        al, _ = parse_allowlist(raw)
        self.assertEqual(al.lookup("B:y", "bad" + os.fsdecode(b"\xfe") + ".py"), "x")

    def test_a_later_entry_for_the_same_key_replaces_the_earlier_one(self):
        for strict in (False, True):
            al, _ = parse_allowlist(dump([entry(reason="old"), entry(reason="new")]), strict=strict)
            self.assertEqual(al.lookup("CWE-798:x", "a.py"), "new")
            al, _ = parse_allowlist(dump([entry(reason="old"), entry(reason="")]), strict=strict)
            self.assertIsNone(al.lookup("CWE-798:x", "a.py"))        # an empty reason can only take away

    def test_a_reason_is_never_empty_in_the_parsed_entries(self):
        raw = dump([entry(rule="A", reason=""), {"rule": "B", "path": "p"}, entry(rule="C", reason="ok")])
        for strict in (False, True):
            al, _ = parse_allowlist(raw, strict=strict)
            self.assertEqual({r for r, _ in al.entries}, {"C"})
            self.assertEqual(len(al), 1)

    def test_strict_mode_keeps_the_reason_whole_and_reports_each_skipped_entry(self):
        raw = dump([entry(rule="A", reason="two\nlines"), 5, {"path": "p", "reason": "x"},
                    {"rule": "B", "path": "p"}, {"rule": "C", "reason": "x"}, entry(rule=1), entry(path=1),
                    entry(reason=1), entry(rule="D", path="q", reason="fine")])
        al, notes = parse_allowlist(raw, strict=True)
        self.assertEqual(dict(al.entries), {("A", "a.py"): "two\nlines", ("D", "q"): "fine"})
        self.assertEqual(len(notes), 7)
        for index in (1, 2, 3, 4, 5, 6, 7):
            self.assertTrue(any(("[%d]" % index) in n for n in notes), (index, notes))
        for note in notes:
            self.assertIn(".transit-allow.json", note)
            self.assertNotIn("\n", note)

    def test_strict_mode_explains_a_file_it_cannot_use(self):
        for raw in (b"\xff", b"{bad", b'{"a": 1}', b"3"):
            al, notes = parse_allowlist(raw, strict=True)
            self.assertEqual(len(al), 0)
            self.assertEqual(len(notes), 1, raw)
            self.assertIn(".transit-allow.json", notes[0])

    def test_bash_mode_is_silent_about_a_file_it_cannot_use(self):
        for raw in (b"\xff", b"{bad", b'{"a": 1}', b"3", b"", b"[]"):
            al, notes = parse_allowlist(raw)
            self.assertEqual(len(al), 0)
            self.assertEqual(notes, ())

    def test_notes_never_carry_text_from_the_file(self):
        hostile = "EVIL\x1b]0;pwned\x07\u202e"
        raw = dump([{"rule": hostile, "path": hostile}, {"rule": 5, "path": hostile, "reason": hostile},
                    {"rule": hostile, "path": hostile, "reason": 5}, "str" + hostile])
        _, notes = parse_allowlist(raw, strict=True)
        self.assertTrue(notes)
        for note in notes:
            self.assertNotIn("EVIL", note)
            self.assertNotIn("\x1b", note)

    def test_deeply_nested_document_does_not_raise(self):
        # json.loads raises RecursionError here, which is not a ValueError (F16).
        raw = b"[" * 400_000 + b"]" * 400_000
        for strict in (False, True):
            al, notes = parse_allowlist(raw, strict=strict)
            self.assertEqual(len(al), 0)
            self.assertEqual(notes, (".transit-allow.json ignored: RecursionError",))

    def test_a_memory_error_is_an_empty_allowlist_and_a_note(self):
        for strict in (False, True):
            with mock.patch("json.loads", side_effect=MemoryError):
                al, notes = parse_allowlist(dump([entry()]), strict=strict)
            self.assertEqual(len(al), 0)
            self.assertEqual(notes, (".transit-allow.json ignored: MemoryError",))

    def test_any_exception_class_is_named_but_nothing_else_of_it(self):
        class Odd(Exception):
            pass
        with mock.patch("json.loads", side_effect=Odd("secret detail /etc/passwd")):
            al, notes = parse_allowlist(dump([entry()]))
        self.assertEqual(len(al), 0)
        self.assertEqual(notes, (".transit-allow.json ignored: Odd",))

    def test_a_base_exception_is_not_swallowed(self):
        for exc in (KeyboardInterrupt, SystemExit):
            with mock.patch("json.loads", side_effect=exc):
                with self.assertRaises(exc):
                    parse_allowlist(dump([entry()]))

    def test_never_raises_on_arbitrary_bytes(self):
        rnd = random.Random(5)
        for _ in range(300):
            raw = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 40)))
            for strict in (False, True):
                al, notes = parse_allowlist(raw, strict=strict)
                self.assertIsInstance(al, Allowlist)
                self.assertIsInstance(notes, tuple)
        tokens = ['[', ']', '{', '}', '"rule"', '"path"', '"reason"', ':', ',', '"x"', '5', 'null', '"\\ud800"']
        for _ in range(300):
            raw = "".join(rnd.choice(tokens) for _ in range(rnd.randint(0, 25))).encode()
            for strict in (False, True):
                parse_allowlist(raw, strict=strict)

    def test_huge_number_literals_do_not_raise(self):
        raw = b'[{"rule":"A","path":"p","reason":"x"}, ' + b"9" * 6000 + b"]"
        for strict in (False, True):
            parse_allowlist(raw, strict=strict)

    def test_the_result_never_has_more_entries_than_the_strict_reading(self):
        # fail closed: whatever bash mode honours, strict mode (which only drops the malformed entry) honours too
        for _, raw, *_ in E3:
            bash_al, _ = parse_allowlist(raw)
            strict_al, _ = parse_allowlist(raw, strict=True)
            for key, reason in bash_al.entries.items():
                self.assertIn(key, strict_al.entries)


# ── json_safe ──────────────────────────────────────────────────────────────────────────────────────────────────────
class JsonSafeTests(unittest.TestCase):
    def test_plain_text_is_unchanged(self):
        for text in ("", "plain", "caf\u00e9", "\U0001f600", "tab\tnl\n\x1b[31m", "\ufffd"):
            self.assertEqual(json_safe(text), text)

    def test_undecodable_bytes_become_replacement_characters(self):
        self.assertEqual(json_safe(os.fsdecode(b"bad\xfe\xffname")), "bad\ufffd\ufffdname")
        self.assertEqual(json_safe(os.fsdecode(b"\xff")), "\ufffd")
        self.assertEqual(json_safe(os.fsdecode(b"ok\xc3")), "ok\ufffd")       # a truncated sequence

    def test_equals_the_documented_recipe(self):
        rnd = random.Random(11)
        for _ in range(400):
            data = bytes(rnd.choice(list(range(0, 128)) + [0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80, 0xFE, 0xFF,
                                                           0x80, 0xBF]) for _ in range(rnd.randint(0, 24)))
            text = os.fsdecode(data)
            expected = os.fsencode(text).decode("utf-8", "replace")
            self.assertEqual(json_safe(text), expected, data)

    def test_a_surrogate_that_is_not_an_escaped_byte_does_not_raise(self):
        self.assertEqual(json_safe("a\ud800b"), "a\ufffdb")
        self.assertEqual(json_safe("\udfff"), "\ufffd")
        json_safe("x" + "\ud800" * 1000)

    def test_result_encodes_as_strict_utf8(self):
        for text in (os.fsdecode(b"\xfe\xff"), "a\ud800", "\udc80\udcff", "ok"):
            json_safe(text).encode("utf-8")


# ── neutralise_detail ──────────────────────────────────────────────────────────────────────────────────────────────
MARKER_WORDS = ("info", "low", "warning", "medium", "error", "high", "critical")


def has_marker(text: str) -> bool:
    folded = text.lower()
    return any(":%s:" % w in folded for w in MARKER_WORDS)


class NeutraliseDetailTests(unittest.TestCase):
    def test_exact_results(self):
        cases = [
            ("a:LOW:b", "a:LOW?b"),
            ("x:Error:y|z", "x:Error?y?z"),
            ("plain/entry.class", "plain/entry.class"),
            ("\u00e9\x00\x1b|a", "????a"),
            ("tab\there", "tab?here"),
            ("LOW:x", "LOW?x"),
            ("a:critical:b:high:c", "a:critical?b:high?c"),
            ("a:INFO:", "a:INFO?"),
            ("mail:warning:medium:error", "mail:warning?medium?error"),
            ("a: low :b", "a: low :b"),            # a space defeats the marker, so nothing to neutralise
            ("a:lowx:b", "a:lowx:b"),
            ("xlow:b", "xlow:b"),                  # not the word "low"
            ("\\back", "\\back"),                  # a backslash is data
            ("", ""),
        ]
        for detail, expected in cases:
            with self.subTest(detail=detail):
                self.assertEqual(neutralise_detail(detail, max_chars=110), expected)

    def test_cut_to_max_chars(self):
        self.assertEqual(neutralise_detail("a" * 200, max_chars=110), "a" * 110)
        self.assertEqual(neutralise_detail("a" * 200, max_chars=120), "a" * 120)
        self.assertEqual(neutralise_detail("abc", max_chars=2), "ab")
        self.assertEqual(neutralise_detail("abc", max_chars=0), "")
        self.assertEqual(neutralise_detail("abc", max_chars=-5), "")
        self.assertEqual(neutralise_detail("abcdefgh", max_chars=-3), "")      # a negative limit is not "all but the last"
        # the cut comes first, so a marker the cut leaves whole is still neutralised
        self.assertEqual(neutralise_detail("a:low:" + "b" * 200, max_chars=6), "a:low?")
        self.assertEqual(neutralise_detail("a:low:b", max_chars=5), "a:low")

    def test_a_marker_can_never_be_read_from_the_result(self):
        rnd = random.Random(31)
        pieces = [":", ":", "info", "LOW", "Warning", "medium", "ERROR", "high", "Critical", "x", " ", "|", "\n", "\u00e9",
                  "a:", "\x1b", "\\", "-"]
        for _ in range(3000):
            detail = "".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 16)))
            for limit in (110, 120, 7):
                out = neutralise_detail(detail, max_chars=limit)
                self.assertLessEqual(len(out), limit)
                self.assertFalse(has_marker(out), (detail, out))
                self.assertTrue(all(" " <= c <= "~" for c in out), (detail, out))
                self.assertNotIn("|", out)
                self.assertEqual(neutralise_detail(out, max_chars=limit), out, "idempotent")
                # and in the message the scanner puts it in, severity is not changed by it
                message = "CWE-22:jar_entry_path_traversal_zip_slip(1: %s)" % out
                self.assertEqual(classify_severity(message).name, "HIGH", (detail, out))

    def test_the_example_of_s7_still_fails(self):
        # a jar entry called a:LOW:b must not turn a HIGH finding into a LOW one
        detail = neutralise_detail("a:LOW:b", max_chars=110)
        self.assertEqual(classify_severity("CWE-22:jar_entry_path_traversal_zip_slip(1: " + detail + ")").name, "HIGH")
        self.assertEqual(classify_severity("CWE-22:x(1: a:LOW:b)").name, "LOW")   # without it the severity moves

    def test_linear_time(self):
        started = time.monotonic()
        neutralise_detail((":low" * 1_000_000), max_chars=10_000_000)
        neutralise_detail("x" * 5_000_000, max_chars=10_000_000)
        self.assertLess(time.monotonic() - started, 10.0)


# ── structure ──────────────────────────────────────────────────────────────────────────────────────────────────────
class StructureTests(unittest.TestCase):
    def test_no_regular_expressions_and_no_io(self):
        tree = ast.parse((ROOT / "transit" / "findings.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("re", imported)
        self.assertNotIn("subprocess", imported)
        self.assertNotIn("transit", imported, "findings is a leaf module")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"print", "eval", "exec", "open", "compile"})

    def test_constants(self):
        self.assertEqual(findings.ENGINE_PREFIX, "engine:")
        self.assertEqual(findings.CATEGORIES, ("security", "sast", "secret", "malware", "ioc", "cwe", "owasp"))


if __name__ == "__main__":
    unittest.main()
