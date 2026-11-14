"""Tests of transit/scanners/doc.py (WP-10): the two families that ``classify_file`` handles with one inline credential rule each,
``docs`` (``.md .txt .rst``) and ``json`` (``.json``).

    python3 -I -m unittest discover -s tests/engine -p "test_doc.py"

Every scanner is exercised through ``scanners.invoke`` over a REAL ``ScanContext`` (``tests/engine/support.make_context``: real ``Verdict``,
``FileView`` and rule machinery), so a scanner that records nothing, or the wrong thing, is caught the way the engine would catch it. The
oracle is REAL GNU ``grep`` run the way bash runs it (``grep -qE -e PATTERN FILE``, C locale); the two patterns are read from
tests/conformance/patterns.json and the messages from ``scan_pipeline.sh``, never from the module under test. The golden file
tests/conformance/golden/rules_corpus.json is the target of ``CorpusTests``.

Known difference from bash (E8, reported to the lead): a table row is ``grep -a`` (``Match(binary="text")``), while bash's ``grep_check`` has no
``-a`` and so reads a NUL byte as a line break once it decides the file is binary. For these two UNANCHORED patterns that can only make this
engine find MORE than bash on a file holding a NUL byte (a match may run across the NUL), never less; ``OracleTests`` pins exactly that.

A token-shaped credential is never written contiguously in this file; the values used here are ordinary words.
"""
from __future__ import annotations

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
from tests.engine import support  # noqa: E402
from transit import dispatch, rx  # noqa: E402
from transit.findings import Allowlist  # noqa: E402
from transit.rules import Match, RuleSet, SearchPolicy  # noqa: E402
from transit.scanners import doc, guard, invoke, load_registry, universal  # noqa: E402

SCRIPT = ROOT / "scan_pipeline.sh"
GOLDEN = ROOT / "tests" / "conformance" / "golden" / "rules_corpus.json"
FIXTURES = ROOT / "tests" / "fixtures" / "rules"
GREP = shutil.which("grep")

DOC_MESSAGE = "CWE-798:hardcoded_credential_in_doc"
JSON_MESSAGE = "CWE-798:hardcoded_credential_in_JSON"


def _gnu_grep() -> bool:
    if GREP is None:
        return False
    try:
        out = subprocess.run([GREP, "--version"], capture_output=True, timeout=10, env={"LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return b"GNU grep" in out


NEEDS_GREP = unittest.skipUnless(_gnu_grep(), "GNU grep is not installed")


def inventory_pattern(entry_id: str) -> str:
    """The pattern text of one ``tests/conformance/patterns.json`` entry (the text bash hands to grep)."""
    rows = json.loads((ROOT / "tests" / "conformance" / "patterns.json").read_text(encoding="utf-8"))
    for row in rows:
        if row["id"] == entry_id:
            return row["pattern"]
    raise AssertionError("patterns.json has no entry %s" % entry_id)


DOC_PATTERN = inventory_pattern("classify_file:54a7fdd9")
JSON_PATTERN = inventory_pattern("classify_file:df96137c")


def grep_fires(pattern: str, data: bytes) -> bool:
    """Bash ``grep_check``: ``grep -qE -e PATTERN FILE`` in the C locale (no ``-a``)."""
    with tempfile.TemporaryDirectory(prefix="wp10-grep-") as tmp:
        path = os.path.join(tmp, "f")
        Path(path).write_bytes(data)
        proc = subprocess.run([GREP or "grep", "-qE", "-e", pattern, path], capture_output=True, timeout=60, env={"LC_ALL": "C"})
    if proc.returncode not in (0, 1):
        raise AssertionError("grep failed (%d): %s" % (proc.returncode, proc.stderr.decode("utf-8", "replace")))
    return proc.returncode == 0


def make_registry() -> "support.Registry":
    return support.make_registry({spec.id: spec for spec in doc.SCANNERS})


def scan(test: unittest.TestCase, scanner_id: str, data: "bytes | str", rel: "str | None" = None, **kwargs) -> support.Harness:
    """Run scanner ``scanner_id`` of this module on one file through ``invoke`` and return the harness (real ``Verdict``)."""
    rel = rel or ("a.md" if scanner_id == "docs" else "a.json")
    kwargs.setdefault("registry", make_registry())
    h = support.make_context(test, rel, data, **kwargs)
    test.assertTrue(invoke(h.registry, scanner_id, h.ctx))
    return h


def counters(h: support.Harness) -> "tuple[int, int, int]":
    c = h.snapshot().counters
    return c.pass_, c.warn, c.fail


def formatted(h: support.Harness, rel: "str | None" = None) -> "list[str]":
    """The conformance normaliser's view of one file: ``"[FAIL] message"`` strings, sorted."""
    return sorted("[%s] %s" % (level, text) for level, text in h.messages(None if rel is None else h.repo.recorded(rel)))


# (text, label). Each of them is also run through real grep below, so the table cannot drift from what bash does.
DOC_FAIL = (
    (b"password = hunter2abc\n", "spaces around ="),
    (b"password: hunter2\n", "colon"),
    (b"secret=abcde\n", "five characters is the shortest value"),
    (b"api_key:Zzzzz\n", "no space at all"),
    (b"Set the api_key=abc12 now\n", "inside a sentence"),
    (b"my_secret: abcdef\n", "no word boundary in front of the keyword"),
    (b"password\t=\tabcde\n", "a tab is white space"),
    (b"password = (abcde)\n", "a parenthesis may start the value"),
    (b"password: 'quoted'\n", "a quote may start the value"),
    (b"  password : abcde  \n", "blanks everywhere"),
    (b"secret: abcde", "no trailing newline"),
    (b"password = hunter2abc\r\n", "CRLF"),
    (b"line one\nline two\nsecret = abcdefgh\nline four\n", "on the third line"),
    (b"password = \xff\xfe\xfd\xfc\xfb\n", "undecodable bytes are ordinary characters in the C locale"),
)
DOC_PASS = (
    (b"", "empty file"),
    (b"# Clean sample project\n", "ordinary text"),
    (b"password: ${PASSWORD}\n", "a variable reference: the value may not start with $"),
    (b"password = $PASS1\n", "a variable reference without braces"),
    (b"password = {abcde}\n", "the value may not start with {"),
    (b"secret=abcd\n", "four characters is one too few"),
    (b"api_key: ab cd\n", "a value that stops at a blank"),
    (b"PASSWORD = hunter2abc\n", "the rule is case-sensitive"),
    (b"Password: hunter2abc\n", "the rule is case-sensitive (capital P)"),
    (b"API_KEY=abcdefgh\n", "the rule is case-sensitive (API_KEY)"),
    (b"token = abcdefgh\n", "token is a JSON keyword, not a docs keyword"),
    (b"password:\n", "no value"),
    (b"password:      \n", "blanks only"),
    (b"the password is hunter2\n", "no : or ="),
    (b"password\n= abcdefgh\n", "the = is on the next line: grep matches one line at a time"),
)
JSON_FAIL = (
    (b'{"password": "sup3rs3cret"}\n', "the fixture shape"),
    (b'{"api_key":"abcd"}\n', "four characters is the shortest value"),
    (b'{"private_key" : "x1y2"}\n', "blanks around the colon"),
    (b'{"token": "abcdef"}\n', "token"),
    (b'{"secret":"abcd efgh"}\n', "a value that has four characters before its first blank"),
    (b'password: "abcd"\n', "an unquoted key (YAML-like text in a .json)"),
    (b'{"csrf_token": "abcdef"}\n', "a name that ends in token"),
    (b'{"token": "^2.0.0"}\n', "a semver range: the exclusion lives in the package.json scanner only"),
    (b'{"secret"  :   "abcdefgh"}\n', "wide blanks"),
    (b'{"private_key": "-----BEGIN PRIVATE KEY-----"}\n', "a PEM header as the value"),
    (b'{\n  "name": "svc",\n  "password": "sup3rs3cret"\n}\n', "a pretty-printed document"),
)
JSON_PASS = (
    (b"", "empty file"),
    (b'{"name": "x", "version": "1.0.0"}\n', "ordinary document"),
    (b'{"password": "${PW}"}\n', "a variable reference"),
    (b'{"password": "{{pw}}"}\n', "a template placeholder"),
    (b'{"password": 12345678}\n', "a number is not a quoted value"),
    (b'{"password": null}\n', "null"),
    (b'{"secret": "ab cd"}\n', "two characters before the blank"),
    (b'{"secret": ""}\n', "empty string"),
    (b'{"token": "abc"}\n', "three characters is one too few"),
    (b'{"token": "$tok1234"}\n', "the value may not start with $"),
    (b'{"Password": "abcdefgh"}\n', "case-sensitive"),
    (b'{"secret_key": "abcdefgh"}\n', "secret_key is not on the list (a blind spot copied from bash)"),
    (b'{"password"\n: "abcdefgh"}\n', "the colon is on the next line"),
)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ModuleTests(unittest.TestCase):
    def test_two_specs_are_registered_and_ported(self) -> None:
        by_id = {spec.id: spec for spec in doc.SCANNERS}
        self.assertEqual(sorted(by_id), ["docs", "json"])
        self.assertEqual((by_id["docs"].family, by_id["docs"].fn, by_id["docs"].tools, by_id["docs"].ported),
                         ("docs", doc.scan_docs, (), True))
        self.assertEqual((by_id["json"].family, by_id["json"].fn, by_id["json"].tools, by_id["json"].ported),
                         ("json", doc.scan_json, (), True))
        self.assertEqual(by_id["docs"].bash_function, "classify_file (.md|.txt|.rst arm)")
        self.assertEqual(by_id["json"].bash_function, "classify_file (.json arm)")

    def test_the_registry_finds_both_and_reports_them_ported(self) -> None:
        registry = load_registry(["doc"])
        self.assertEqual(registry.load_errors, ())
        self.assertEqual(sorted(registry.specs), ["docs", "json"])
        self.assertNotIn("docs", registry.unported())
        self.assertNotIn("json", registry.unported())

    def test_each_table_is_one_row_with_the_bash_message_and_pattern(self) -> None:
        for table, name, message, pattern in ((doc.DOC_RULES, "docs", DOC_MESSAGE, DOC_PATTERN), (doc.JSON_RULES, "json", JSON_MESSAGE, JSON_PATTERN)):
            with self.subTest(table=name):
                self.assertIsInstance(table, RuleSet)
                self.assertEqual(table.name, name)
                self.assertEqual(len(table.rules), 1)
                row = table.rules[0]
                self.assertEqual((row.outcome, row.message, row.severity, row.applies_to), ("fail", message, None, None))
                self.assertTrue(row.id.startswith(name + "/01-"), row.id)
                self.assertEqual(row.cond, Match(pattern))          # grep_check: line mode, case-sensitive, binary text
                self.assertEqual(row.source, "classify_file")

    def test_messages_and_patterns_occur_in_the_bash_script(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('record_fail "$f" "%s"' % DOC_MESSAGE, text)
        self.assertIn('record_fail "$f" "%s"' % JSON_MESSAGE, text)

    def test_both_rules_are_registered_with_rx_as_line_rules(self) -> None:
        by_id = {rule.id: rule for rule in rx.registered()}
        for table, pattern in ((doc.DOC_RULES, DOC_PATTERN), (doc.JSON_RULES, JSON_PATTERN)):
            rule = by_id[table.rules[0].id]
            self.assertEqual((rule.pattern, rule.mode, rule.excl), (pattern, "line", None))

    def test_the_module_has_no_module_level_mutable_state(self) -> None:
        for name, value in vars(doc).items():
            if name.startswith("__"):
                continue
            self.assertNotIsInstance(value, (list, dict, set), name)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RuleRowTests(unittest.TestCase):
    """Every row, fail and near-miss, through ``invoke`` and a real Verdict."""

    def check_fail(self, scanner_id: str, message: str, data: bytes, label: str) -> None:
        with self.subTest(label=label, data=data[:40]):
            h = scan(self, scanner_id, data)
            self.assertEqual(h.messages(), [("FAIL", message)])
            self.assertEqual(h.status(), "FAIL")
            self.assertEqual(counters(h), (0, 0, 1), "a FAIL file is not also counted as a PASS")
            self.assertEqual(h.verdict.verdict, "FAIL")

    def check_pass(self, scanner_id: str, data: bytes, label: str) -> None:
        with self.subTest(label=label, data=data[:40]):
            h = scan(self, scanner_id, data)
            self.assertEqual(h.messages(), [])
            self.assertEqual(h.status(), "PASS")
            self.assertEqual(counters(h), (1, 0, 0))
            self.assertEqual(h.verdict.verdict, "PASS")

    def test_docs_fail(self) -> None:
        for data, label in DOC_FAIL:
            self.check_fail("docs", DOC_MESSAGE, data, label)

    def test_docs_pass(self) -> None:
        for data, label in DOC_PASS:
            self.check_pass("docs", data, label)

    def test_json_fail(self) -> None:
        for data, label in JSON_FAIL:
            self.check_fail("json", JSON_MESSAGE, data, label)

    def test_json_pass(self) -> None:
        for data, label in JSON_PASS:
            self.check_pass("json", data, label)

    def test_the_two_rules_are_not_interchangeable(self) -> None:
        # token is a JSON keyword only; the docs rule has no quote handling at all
        self.check_pass("docs", b'{"token": "abcdef"}\n', "the JSON line under the docs rule")
        self.check_pass("docs", b'{"password": "sup3rs3cret"}\n', "the closing quote of the key stands between password and the colon")
        self.check_pass("json", b"password = abcdefgh\n", "the docs line under the JSON rule: JSON needs a colon and a quote")

    def test_the_scanner_does_not_look_at_the_file_name(self) -> None:
        for rel in ("README.md", "notes.txt", "guide.rst", "package.json", "weird name.json", "NOEXT"):
            with self.subTest(rel=rel):
                self.assertEqual(scan(self, "docs", b"password = hunter2abc\n", rel=rel).messages(), [("FAIL", DOC_MESSAGE)])
                self.assertEqual(scan(self, "json", b'{"token": "abcdef"}\n', rel=rel).messages(), [("FAIL", JSON_MESSAGE)])

    def test_a_prose_readme_that_quotes_an_attack_string_fails(self) -> None:
        # documented behaviour (CLAUDE.md): that is what .transit-allow.json is for
        h = scan(self, "docs", b"Never write password = hunter2abc in a config.\n")
        self.assertEqual(h.messages(), [("FAIL", DOC_MESSAGE)])

    def test_both_rows_run_and_both_could_fire_in_one_file_only_once_per_scanner(self) -> None:
        data = b"password = hunter2abc\nsecret: abcdefgh\napi_key=abcdefgh\n"
        h = scan(self, "docs", data)
        self.assertEqual(h.messages(), [("FAIL", DOC_MESSAGE)], "one grep, one message, however many lines match")


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class FiredTests(unittest.TestCase):
    """``fired`` is true whenever the rule matched, whatever the allowlist or ``--min-severity`` did with the FAIL: no PASS beside it."""

    def test_an_allowlisted_fail_is_a_warn_and_records_no_pass(self) -> None:
        for scanner_id, rel, data, message in (("docs", "a.md", b"password = hunter2abc\n", DOC_MESSAGE),
                                               ("json", "a.json", b'{"token": "abcdef"}\n', JSON_MESSAGE)):
            with self.subTest(scanner=scanner_id):
                allow = Allowlist({(message.split(":")[0], rel): "test fixture only"})
                h = scan(self, scanner_id, data, rel=rel, allowlist=allow)
                self.assertEqual(h.messages(), [("WARN", "ALLOWED:%s (reason: test fixture only)" % message)])
                self.assertEqual(h.status(), "WARN")
                self.assertEqual(counters(h), (0, 1, 0), "bash: failed=true, so record_pass is not reached")
                self.assertEqual(h.verdict.verdict, "PASS", "an allowlisted finding does not block")

    def test_a_fail_below_the_severity_threshold_is_a_warn_and_records_no_pass(self) -> None:
        for scanner_id, data, message in (("docs", b"password = hunter2abc\n", DOC_MESSAGE), ("json", b'{"token": "abcdef"}\n', JSON_MESSAGE)):
            with self.subTest(scanner=scanner_id):
                h = scan(self, scanner_id, data, threshold=4, min_severity="critical")
                self.assertEqual(h.messages(), [("WARN", "LOW_SEV(below --min-severity critical):" + message)])
                self.assertEqual(counters(h), (0, 1, 0))

    def test_the_allowlist_entry_must_name_this_rule_and_this_file(self) -> None:
        allow = Allowlist({("CWE-798", "other.md"): "wrong file", ("CWE-22", "a.md"): "wrong rule"})
        h = scan(self, "docs", b"password = hunter2abc\n", allowlist=allow)
        self.assertEqual(h.messages(), [("FAIL", DOC_MESSAGE)])


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class EngineFailureTests(unittest.TestCase):
    """What the engine records when the search itself cannot finish: never a PASS, never a downgrade."""

    def test_a_search_that_cannot_finish_is_the_engine_fail_and_no_pass(self) -> None:
        for scanner_id in ("docs", "json"):
            with self.subTest(scanner=scanner_id):
                with mock.patch("transit.rules.run_ruleset", side_effect=MemoryError):
                    h = scan(self, scanner_id, b"nothing to see\n")
                self.assertEqual(h.messages(), [("FAIL", "engine:search_incomplete")])
                self.assertEqual(counters(h), (0, 0, 1), "bash grep_flat leaves no PASS beside engine:search_incomplete (contract 8.7, K F6)")
                h.verdict.record_layer("L5_per_language_sast", "ran")
                self.assertIn("partial:", h.snapshot().coverage["L5_per_language_sast"])

    def test_a_search_failure_is_not_downgraded_by_the_allowlist_or_the_threshold(self) -> None:
        allow = Allowlist({("engine", "a.md"): "x", ("engine:search_incomplete", "a.md"): "x"})
        with mock.patch("transit.rules.run_ruleset", side_effect=MemoryError):
            h = scan(self, "docs", b"x\n", allowlist=allow, threshold=4, min_severity="critical")
        self.assertEqual(h.messages(), [("FAIL", "engine:search_incomplete")])

    def test_a_passed_file_deadline_is_the_engine_fail_and_not_a_pass(self) -> None:
        for scanner_id, rel in (("docs", "a.md"), ("json", "a.json")):
            with self.subTest(scanner=scanner_id):
                h = scan(self, scanner_id, b"nothing to see\n", rel=rel, deadline=time.monotonic() - 1.0)
                self.assertEqual(h.messages(), [("FAIL", "engine:scan_incomplete:%s:time_budget" % scanner_id)])
                self.assertEqual(h.status(), "FAIL")
                self.assertEqual(counters(h), (0, 0, 1), "a file whose rules were not evaluated must not also count as passed")

    def test_the_rule_machinery_is_what_decides_the_policy(self) -> None:
        # the scanner takes no switch of its own: the context's SearchPolicy is the single control point
        policy = SearchPolicy(rule_budget_s=0.25, long_line_bytes=8192, excl_nul_blind=True)
        h = scan(self, "docs", b"password = hunter2abc\n", policy=policy)
        self.assertEqual(h.messages(), [("FAIL", DOC_MESSAGE)])


# ═══════════════════════════════════════════════════════════════════════════════════════════════
@NEEDS_GREP
class OracleTests(unittest.TestCase):
    """The two rows against real ``grep -qE`` (the C locale, no ``-a``), on the hand-written tables and on random documents."""

    def fires(self, scanner_id: str, data: bytes) -> bool:
        h = scan(self, scanner_id, data)
        outcome = h.messages()
        self.assertIn(outcome, ([], [("FAIL", DOC_MESSAGE if scanner_id == "docs" else JSON_MESSAGE)]))
        return bool(outcome)

    def test_the_tables_are_what_grep_says(self) -> None:
        for table, scanner_id, pattern in ((DOC_FAIL, "docs", DOC_PATTERN), (DOC_PASS, "docs", DOC_PATTERN),
                                           (JSON_FAIL, "json", JSON_PATTERN), (JSON_PASS, "json", JSON_PATTERN)):
            for data, label in table:
                with self.subTest(scanner=scanner_id, label=label):
                    self.assertEqual(self.fires(scanner_id, data), grep_fires(pattern, data))

    def random_document(self, rnd: random.Random, tokens: "list[bytes]") -> bytes:
        lines = []
        for _ in range(rnd.randint(1, 5)):
            lines.append(b"".join(rnd.choice(tokens) for _ in range(rnd.randint(1, 9))))
        return b"\n".join(lines) + rnd.choice((b"\n", b"", b"\r\n"))

    DOC_TOKENS = [b"password", b"secret", b"api_key", b"token", b"=", b":", b" ", b" ", b"\t", b"$", b"{", b"abc", b"x", b"12345", b"'", b'"',
                  b"\xff", b"PASSWORD", b"_", b"\r", b"password = ", b"secret: ", b"api_key=", b"abcdef"]
    JSON_TOKENS = [b"password", b"secret", b"token", b"api_key", b"private_key", b":", b" ", b'"', b'"', b"abcd", b"ab", b"$", b"{", b"${X}",
                   b"\t", b"x1y2", b",", b"=", b"\xe9", b'"token": "', b'"secret":"', b'password: "', b'"api_key" : "', b"abcdef", b"abc"]

    def test_random_documents_agree_with_grep_exactly(self) -> None:
        rnd = random.Random(20261114)
        for scanner_id, pattern, tokens in (("docs", DOC_PATTERN, self.DOC_TOKENS), ("json", JSON_PATTERN, self.JSON_TOKENS)):
            fired = 0
            for case in range(160):
                data = self.random_document(rnd, tokens)
                expect = grep_fires(pattern, data)
                fired += expect
                self.assertEqual(self.fires(scanner_id, data), expect, "%s case %d: %r" % (scanner_id, case, data))
            self.assertGreater(fired, 8, "the random documents must exercise the positive side too (%s)" % scanner_id)
            self.assertLess(fired, 150, "...and the negative side (%s)" % scanner_id)

    def test_a_nul_byte_can_only_make_this_engine_find_more_than_bash(self) -> None:
        # E8: grep_check has no -a, so bash reads each NUL as a line break once the file is binary; the rows here are grep -a.
        # The two patterns are unanchored, so a match bash finds is a match here too; the converse is the known difference.
        rnd = random.Random(7)
        for scanner_id, pattern, tokens in (("docs", DOC_PATTERN, self.DOC_TOKENS), ("json", JSON_PATTERN, self.JSON_TOKENS)):
            for case in range(80):
                data = self.random_document(rnd, tokens + [b"\0", b"\0"])
                if grep_fires(pattern, data):
                    self.assertTrue(self.fires(scanner_id, data), "%s case %d: %r" % (scanner_id, case, data))
        # the NUL changes nothing for a value that sits wholly on one side of it
        self.assertTrue(self.fires("docs", b"password = hunter2abc\n\0\0binary tail\n"))
        self.assertTrue(self.fires("json", b'\0{"token": "abcdef"}\0'))
        # ...and the difference itself, spelled out: a value that runs across the NUL is found here and not by bash
        across = b"password=ab\0cdef\n"
        self.assertTrue(self.fires("docs", across))
        self.assertFalse(grep_fires(DOC_PATTERN, across))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class HostileInputTests(unittest.TestCase):
    """S12: a line of any length costs bounded time (the linear matcher takes over)."""

    def test_a_600_kb_line_is_searched_in_bounded_time_and_the_match_at_its_end_is_found(self) -> None:
        for scanner_id, filler, tail, message in (("docs", b"password ", b" password = hunter2abc\n", DOC_MESSAGE),
                                                  ("json", b'"token" ', b' "token": "abcdef"\n', JSON_MESSAGE)):
            with self.subTest(scanner=scanner_id):
                began = time.monotonic()
                clean = scan(self, scanner_id, filler * 70000 + b"\n")
                found = scan(self, scanner_id, filler * 70000 + tail)
                self.assertLess(time.monotonic() - began, 20.0)
                self.assertEqual(clean.messages(), [])
                self.assertEqual(found.messages(), [("FAIL", message)])

    def test_a_file_that_is_one_giant_value_is_found(self) -> None:
        h = scan(self, "docs", b"secret=" + b"x" * 400000 + b"\n")
        self.assertEqual(h.messages(), [("FAIL", DOC_MESSAGE)])


# ═══════════════════════════════════════════════════════════════════════════════════════════════
def run_tree(test: unittest.TestCase, files: "dict[str, bytes]", extra: "dict | None" = None) -> support.Harness:
    """Scan ``files`` the way ``layers.run_file_layers`` does: for each file, in the byte order of its name, the universal layer through
    ``guard`` and then ``dispatch.classify_file`` with a ``run`` that builds a context and calls ``invoke``. Real Verdict throughout."""
    scanners: dict = {spec.id: spec for spec in doc.SCANNERS}
    scanners.update(extra or {})
    first = sorted(files)[0]
    h = support.make_context(test, first, files[first], files=files, registry=support.make_registry(scanners))
    for rel in sorted(files):
        view = h.repo.view(rel)
        guard("universal", universal.scan, h.new_context(rel), requires_outcome=False)

        def run(scanner_id: str, sniffed: bool, rel: str = rel) -> bool:
            return invoke(h.registry, scanner_id, h.new_context(rel, sniffed=sniffed))

        dispatch.classify_file(view, run)
    return h


class CorpusTests(unittest.TestCase):
    """The golden ``rules_corpus``: the files of tests/fixtures/rules that dispatch sends to ``docs`` or ``json``, with the universal layer
    in front of them, must end with the status and messages the bash engine recorded."""

    CORPUS = ("cred_s.json", "cred_s.md", "office_rt2_plain_notes.txt", "office_rt3_notes_mentions_rtf.txt", "private_key.txt",
              "safe_key_prose.txt", "safe_relative_paths.txt", "service_account.json", "traversal.txt")

    def test_each_fixture_ends_as_in_the_bash_golden(self) -> None:
        golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["report"]["file_results"]
        files = {name: (FIXTURES / name).read_bytes() for name in self.CORPUS}
        h = run_tree(self, files)
        for name in self.CORPUS:
            with self.subTest(fixture=name):
                self.assertEqual(h.status(h.repo.recorded(name)), golden[name]["status"])
                self.assertEqual(formatted(h, name), sorted(golden[name]["messages"]))

    def test_the_clean_fixture_readme_passes_with_no_message(self) -> None:
        h = run_tree(self, {"README.md": (ROOT / "tests" / "fixtures" / "clean" / "README.md").read_bytes()})
        self.assertEqual(h.status(h.repo.recorded("README.md")), "PASS")
        self.assertEqual(h.messages(h.repo.recorded("README.md")), [])
        self.assertEqual(counters(h), (1, 0, 0))

    def test_the_fixtures_reach_their_scanner(self) -> None:
        # a guard against a corpus that passes because nothing ran: each of these must have been scanned by the module under test
        files = {name: (FIXTURES / name).read_bytes() for name in ("cred_s.json", "cred_s.md")}
        h = run_tree(self, files)
        self.assertEqual(h.messages(h.repo.recorded("cred_s.json")), [("FAIL", JSON_MESSAGE)])
        self.assertEqual(h.messages(h.repo.recorded("cred_s.md")), [("FAIL", DOC_MESSAGE)])


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RtfHandOffTests(unittest.TestCase):
    """``dispatch.classify_file`` offers a ``.md``, ``.txt`` or ``.rst`` that starts with ``{\\rtf`` to the RTF scanner first (Word opens an RTF
    whatever it is called); the docs rule runs only on what the RTF scanner does not take. Exercised with the REAL dispatch, the real ``docs``
    scanner and a fake ``rtf`` scanner (the office scanner is a later package)."""

    RTF_WITH_SECRET = b"{\\rtf1\\ansi{\\fonttbl{\\f0 Arial;}}\\f0 password = hunter2abc\\par}\n"
    PLAIN_WITH_SECRET = b"password = hunter2abc\n"

    def tree(self, rel: str, data: bytes, rtf_handles: bool):
        calls: "list[tuple[str, bool]]" = []

        def fake_rtf(ctx) -> bool:
            calls.append((ctx.rel, ctx.sniffed))
            if not rtf_handles:
                return False                                    # legal because the context is sniffed
            ctx.record_warn("office:fake_rtf_scanner_ran")
            ctx.record_pass()
            return True

        h = run_tree(self, {rel: data}, extra={"rtf": fake_rtf})
        return h, calls

    def test_an_rtf_with_a_text_extension_goes_to_the_rtf_scanner_and_not_to_the_docs_rule(self) -> None:
        for rel in ("notes.txt", "README.md", "guide.rst", "dir/UPPER.TXT"):
            with self.subTest(rel=rel):
                h, calls = self.tree(rel, self.RTF_WITH_SECRET, rtf_handles=True)
                self.assertEqual(calls, [(rel, True)], "the RTF scanner is offered the file, sniffed")
                self.assertEqual(formatted(h, rel), ["[WARN] office:fake_rtf_scanner_ran"], "no CWE-798 doc finding: the docs rule did not run")

    def test_an_rtf_that_the_rtf_scanner_declines_is_read_as_plain_text_by_docs(self) -> None:
        h, calls = self.tree("notes.txt", self.RTF_WITH_SECRET, rtf_handles=False)
        self.assertEqual(calls, [("notes.txt", True)])
        self.assertEqual(formatted(h, "notes.txt"), ["[FAIL] " + DOC_MESSAGE])

    def test_a_text_file_that_is_not_an_rtf_never_meets_the_rtf_scanner(self) -> None:
        h, calls = self.tree("notes.txt", self.PLAIN_WITH_SECRET, rtf_handles=True)
        self.assertEqual(calls, [])
        self.assertEqual(formatted(h, "notes.txt"), ["[FAIL] " + DOC_MESSAGE])

    def test_the_rtf_scanner_is_not_offered_a_json_file(self) -> None:
        h, calls = self.tree("a.json", b'{\\rtf1 "token": "abcdef"}\n', rtf_handles=True)
        self.assertEqual(calls, [])

    def test_the_docs_scanner_itself_never_hands_over(self) -> None:
        # hand-off is dispatch's decision: scan_docs called directly on an RTF reads it as text and records an outcome
        h = scan(self, "docs", self.RTF_WITH_SECRET, rel="notes.txt")
        self.assertEqual(h.messages(), [("FAIL", DOC_MESSAGE)])


if __name__ == "__main__":
    unittest.main()
