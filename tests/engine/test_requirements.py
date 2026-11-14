"""Tests of transit/scanners/requirements.py (WP-10): pip requirement files (bash ``scan_requirements``), scanner id ``manifest.requirements``.

    python3 -I -m unittest discover -s tests/engine -p "test_requirements.py"

Every case runs through ``scanners.invoke`` over a REAL ``ScanContext`` (``tests/engine/support.make_context``). The oracle is REAL GNU ``grep`` run
the way the hardened bash engine runs the five rules (``grep -qE``, ``grep -qiE`` and the two-stage ``grep -ahiE | grep -aviE`` of
``grep_check_excl``, C locale); the patterns come from tests/conformance/patterns.json and the order and text of the messages from
``scan_pipeline.sh``, never from the module under test. tests/conformance/golden/rules_corpus.json is the target of ``CorpusTests``.

D-029 is closed in bash (the exclusion rule reads the file as text), so ``support.default_policy`` (``excl_nul_blind=False``) is the policy the engine
uses; ``NulTests`` shows that the policy, and nothing in the scanner, is the one control point.

Known difference from bash (E8, reported to the lead): a table row is ``grep -a`` while bash's ``grep_check`` has no ``-a`` and reads each NUL byte as a line
break once it decides the file is binary. For the three ``^``-anchored rows that means a directive that follows a NUL on the same physical line is a
line start to bash and not to this engine (``NulTests`` shows it; pip itself refuses such a line, so the gap is not an exposure); for the unanchored
credential row this engine can only find more.

No token-shaped credential is written in this file: the "passwords" are ordinary words.
"""
from __future__ import annotations

import json
import os
import random
import re
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
from transit.scanners import guard, invoke, load_registry, requirements, universal  # noqa: E402

SCRIPT = ROOT / "scan_pipeline.sh"
GOLDEN = ROOT / "tests" / "conformance" / "golden" / "rules_corpus.json"
FIXTURES = ROOT / "tests" / "fixtures" / "rules"
GREP = shutil.which("grep")

M_PLAIN = "CWE-319:pip_index_or_requirement_over_plaintext"
M_CRED = "CWE-798:pip_credentials_embedded_in_url"
M_TRUSTED = "pip:trusted_host_disables_tls_verification"
M_EXTRA = "pip:extra_index_url_enables_dependency_confusion"
M_VCS = "pip:vcs_requirement_not_pinned_to_a_commit"
#: bash order, with the outcome of each
ROWS = ((M_PLAIN, "fail"), (M_CRED, "fail"), (M_TRUSTED, "warn"), (M_EXTRA, "warn"), (M_VCS, "warn"))
ROW_IDS = ("scan_requirements:6de6233b", "scan_requirements:ddb43b39", "scan_requirements:3517c85f", "scan_requirements:440003fb",
           "scan_requirements:05b625f0")
REL = "requirements.txt"


def _gnu_grep() -> bool:
    if GREP is None:
        return False
    try:
        out = subprocess.run([GREP, "--version"], capture_output=True, timeout=10, env={"LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return b"GNU grep" in out


NEEDS_GREP = unittest.skipUnless(_gnu_grep(), "GNU grep is not installed")


def inventory() -> "list[dict]":
    rows = json.loads((ROOT / "tests" / "conformance" / "patterns.json").read_text(encoding="utf-8"))
    return [r for r in rows if r.get("enclosing_function") == "scan_requirements"]


def inventory_row(entry_id: str) -> dict:
    return [r for r in inventory() if r["id"] == entry_id][0]


def bash_oracle(data: bytes, *, only: "tuple[int, ...] | None" = None) -> "list[str]":
    """The messages the five rows of the hardened bash function record for ``data``, in order (real ``grep``, C locale)."""
    out = []
    with tempfile.TemporaryDirectory(prefix="wp10-grep-") as tmp:
        path = os.path.join(tmp, "f")
        Path(path).write_bytes(data)
        env = {"LC_ALL": "C"}

        def grep(args: "list[str]", stdin: "bytes | None" = None) -> "subprocess.CompletedProcess[bytes]":
            proc = subprocess.run([GREP or "grep"] + args, input=stdin, capture_output=True, timeout=60, env=env)
            if proc.returncode not in (0, 1):
                raise AssertionError("grep failed (%d): %s" % (proc.returncode, proc.stderr.decode("utf-8", "replace")))
            return proc

        for index, (message, _outcome) in enumerate(ROWS):
            if only is not None and index not in only:
                continue
            row = inventory_row(ROW_IDS[index])
            if row["helper"] == "grep_check":
                hit = grep(["-qE", "-e", row["pattern"], path]).returncode == 0
            elif row["helper"] == "grep_check_i":
                hit = grep(["-qiE", "-e", row["pattern"], path]).returncode == 0
            else:                                              # grep_check_excl: grep -ahiE PAT FILE | grep -aviE EXCL (a line is left over)
                first = grep(["-ahiE", "-e", row["pattern"], path])
                hit = grep(["-aviE", "-e", row["excl"]], stdin=first.stdout).returncode == 0
            if hit:
                out.append(message)
    return out


def make_registry() -> "support.Registry":
    return support.make_registry({spec.id: spec for spec in requirements.SCANNERS})


def scan(test: unittest.TestCase, data: "bytes | str", rel: str = REL, **kwargs) -> support.Harness:
    kwargs.setdefault("registry", make_registry())
    h = support.make_context(test, rel, data, **kwargs)
    test.assertTrue(invoke(h.registry, "manifest.requirements", h.ctx))
    return h


def counters(h: support.Harness) -> "tuple[int, int, int]":
    c = h.snapshot().counters
    return c.pass_, c.warn, c.fail


def formatted(h: support.Harness, rel: "str | None" = None) -> "list[str]":
    return sorted("[%s] %s" % (level, text) for level, text in h.messages(None if rel is None else h.repo.recorded(rel)))


def expected_messages(messages: "tuple[str, ...]") -> "list[tuple[str, str]]":
    outcome = dict(ROWS)
    return [("FAIL" if outcome[m] == "fail" else "WARN", m) for m in messages]


TOKENS = [b"--index-url", b"-i", b"-e", b"-f", b"--find-links", b"--extra-index-url", b"--trusted-host", b"http://", b"https://",
          b"git+https://", b"git+ssh://", b"git+http://", b"git://", b"ssh://", b"@", b":", b"/", b" ", b" ", b"\t", b"=", b"x.example",
          b"a.tar.gz", b"b.zip", b"c.whl", b"u:p@", b"user@", b"#egg=pkg", b"abcdef1", b"4f9c1d2e", b"ABCDEF12", b"main", b"requests==2.0",
          b"# ", b"\xff", b".git", b"-"]


def random_document(rnd: random.Random, tokens: "list[bytes]") -> bytes:
    lines = []
    for _ in range(rnd.randint(1, 4)):
        lines.append(b"".join(rnd.choice(tokens) for _ in range(rnd.randint(1, 10))))
    return b"\n".join(lines) + rnd.choice((b"\n", b"", b"\r\n"))


# (data, label, messages the file must get, in bash order). A file with no FAIL message among them is also passed.
CASES = (
    # 1. CWE-319: an index or a requirement over plaintext
    (b"--index-url http://x.example/simple\n", "plaintext --index-url", (M_PLAIN,)),
    (b"-i http://x.example/simple\n", "plaintext -i", (M_PLAIN,)),
    (b"--find-links http://x.example/wheels\n", "plaintext --find-links", (M_PLAIN,)),
    (b"-f http://x.example/wheels\n", "plaintext -f", (M_PLAIN,)),
    (b"--index-url=http://x.example/simple\n", "an = instead of a blank", (M_PLAIN,)),
    (b"--extra-index-url http://x.example/simple\n", "plaintext --extra-index-url is also a dependency-confusion warning", (M_PLAIN, M_EXTRA)),
    (b"git+http://evil.example/pkg.git#egg=pkg\n", "git+http", (M_PLAIN,)),
    (b"-e git+http://evil.example/pkg.git#egg=pkg\n", "editable git+http", (M_PLAIN,)),
    (b"git://github.com/org/pkg.git#egg=pkg\n", "git:// is unauthenticated", (M_PLAIN,)),
    (b"-e   git://github.com/org/pkg.git\n", "editable git:// with extra blanks", (M_PLAIN,)),
    (b"http://evil.example/dep-1.0.tar.gz\n", "a plaintext .tar.gz", (M_PLAIN,)),
    (b"http://evil.example/dep-1.0.tgz\n", "a plaintext .tgz", (M_PLAIN,)),
    (b"http://evil.example/dep-1.0.zip\n", "a plaintext .zip", (M_PLAIN,)),
    (b"http://evil.example/dep-1.0-py3-none-any.whl\n", "a plaintext .whl", (M_PLAIN,)),
    (b"http://evil.example/dep-1.0.tar.bz2\n", "a plaintext .tar.bz2", (M_PLAIN,)),
    (b"http://evil.example/dep-1.0.ZIP\n", "the rule is case-insensitive (the extension)", (M_PLAIN,)),
    (b"   --index-url http://x.example/simple\n", "leading blanks", (M_PLAIN,)),
    (b"--INDEX-URL HTTP://X.EXAMPLE/Simple\n", "the rule is case-insensitive (the option and the scheme)", (M_PLAIN,)),
    (b"requests==2.0\n--index-url http://x.example/simple\n", "on the second line", (M_PLAIN,)),
    (b"--index-url https://x.example/simple\n", "https is fine", ()),
    (b"http://x.example/page.html\n", "a plaintext URL that is not an archive", ()),
    (b"requests==2.0  # see http://x.example/y.zip\n", "an archive URL after a requirement is anchored out", ()),
    (b"# --index-url http://x.example/simple\n", "a comment", ()),
    (b"foo --index-url http://x.example/simple\n", "the option must start the line", ()),
    (b"https://x.example/dep-1.0.tar.gz\n", "an https archive", ()),
    (b"-e git+https://github.com/org/pkg.git@4f9c1d2e#egg=pkg\n", "git+https, pinned", ()),
    # 2. CWE-798: credentials embedded in a URL
    (b"https://deploy:hunter2pass@private.example/simple\n", "user:password@host over https", (M_CRED,)),
    (b"http://u:p@h.example/simple\n", "over http (not an archive, so not a plaintext finding)", (M_CRED,)),
    (b"ssh://git:secret@host.example/x.git\n", "ssh", (M_CRED,)),
    (b"git+https://u:p@h.example/r.git@abcdef1\n", "git+https, pinned", (M_CRED,)),
    (b"--index-url http://u:p@h.example/\n", "plaintext and credentials", (M_PLAIN, M_CRED)),
    (b"--extra-index-url https://deploy:hunter2pass@private.example/simple\n", "credentials in the extra index", (M_CRED, M_EXTRA)),
    (b"https://user@host.example/\n", "a user name without a password", ()),
    (b"https://host.example:8080/p@x\n", "a port, then a path that holds an @", ()),
    (b"git@github.com:org/repo.git\n", "scp-style, no scheme", ()),
    (b"HTTPS://u:p@h.example/\n", "the credential rule is case-sensitive", ()),
    (b"https://u:@h.example/\n", "an empty password", ()),
    (b"ftp://u:p@h.example/\n", "a scheme that is not on the list", ()),
    # 3. --trusted-host
    (b"--trusted-host pypi.corp.example\n", "--trusted-host", (M_TRUSTED,)),
    (b"  --TRUSTED-HOST pypi.corp.example\n", "case-insensitive, leading blanks", (M_TRUSTED,)),
    (b"--trusted-host=pypi.corp.example\n", "an = after the option", (M_TRUSTED,)),
    (b"# --trusted-host pypi.corp.example\n", "a comment", ()),
    (b"pkg --trusted-host pypi.corp.example\n", "the option must start the line", ()),
    (b"--trusted\n", "a prefix of the option", ()),
    # 4. --extra-index-url
    (b"--extra-index-url https://pypi.corp.example/simple\n", "--extra-index-url", (M_EXTRA,)),
    (b"--Extra-Index-URL=https://pypi.corp.example/simple\n", "case-insensitive, with =", (M_EXTRA,)),
    (b"--index-url https://pypi.corp.example/simple\n", "the primary index is not the confusion vector", ()),
    (b"# --extra-index-url https://pypi.corp.example/simple\n", "a comment", ()),
    (b"extra-index-url\n", "the word without the dashes", ()),
    # 5. a VCS requirement not pinned to a commit
    (b"git+https://github.com/org/pkg.git#egg=pkg\n", "git+https with no revision", (M_VCS,)),
    (b"-e git+ssh://git@github.com/org/pkg.git@main#egg=pkg\n", "a branch name", (M_VCS,)),
    (b"git+https://x.example/r.git@abc123\n", "six hex digits are not a commit", (M_VCS,)),
    (b"git+https://x.example/r.git@4f9c1d2e-extra\n", "hex followed by something else", (M_VCS,)),
    (b"git+https://x.example/r.git@" + b"a" * 41 + b"\n", "41 hex digits are too many", (M_VCS,)),
    (b"GIT+HTTPS://x.example/r.git\n", "case-insensitive scheme", (M_VCS,)),
    (b"-e git+https://x.example/r.git@v1.2.3#egg=r\n", "a tag", (M_VCS,)),
    (b"git+https://x.example/a.git@4f9c1d2\ngit+https://x.example/b.git\n", "one pinned line does not excuse another", (M_VCS,)),
    (b"git+https://github.com/org/pkg.git@4f9c1d2e#egg=pkg\n", "pinned, then #", ()),
    (b"git+https://x.example/r.git@4f9c1d2e extra\n", "pinned, then a blank", ()),
    (b"git+https://x.example/r.git@4f9c1d2e\n", "pinned, end of line", ()),
    (b"git+https://x.example/r.git@" + b"a" * 40 + b"\n", "40 hex digits", ()),
    (b"git+https://x.example/r.git@4F9C1D2E#egg=r\n", "upper-case hex (the exclusion is case-insensitive)", ()),
    (b"git+https://x.example/a.git@4f9c1d2e git+https://x.example/b.git\n", "per line: a pinned revision on the line excuses the line", ()),
    (b"git+git://x.example/r.git\n", "git+git is not https or ssh", ()),
    # nothing at all
    (b"", "empty file", ()),
    (b"requests==2.32.3\n", "the clean fixture", ()),
    (b"# Ordinary pins\nrequests==2.31.0\nflask>=2.0,<3\n", "ordinary pins", ()),
    (b"requests==2.31.0", "no trailing newline", ()),
    (b"requests==2.31.0\r\n--trusted-host a\r\n", "CRLF", (M_TRUSTED,)),
)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ModuleTests(unittest.TestCase):
    def test_the_spec(self) -> None:
        self.assertEqual(len(requirements.SCANNERS), 1)
        spec = requirements.SCANNERS[0]
        self.assertEqual((spec.id, spec.family, spec.fn, spec.bash_function, spec.tools, spec.ported),
                         ("manifest.requirements", "manifest", requirements.scan, "scan_requirements", (), True))

    def test_the_registry_finds_it_and_reports_it_ported(self) -> None:
        registry = load_registry(["requirements"])
        self.assertEqual(registry.load_errors, ())
        self.assertEqual(sorted(registry.specs), ["manifest.requirements"])
        self.assertNotIn("manifest.requirements", registry.unported())

    def test_the_table_has_the_five_rows_in_bash_order(self) -> None:
        table = requirements.RULES
        self.assertIsInstance(table, RuleSet)
        self.assertEqual([(r.message, r.outcome) for r in table.rules], list(ROWS))
        for position, row in enumerate(table.rules, 1):
            self.assertTrue(row.id.startswith("manifest.requirements/%02d-" % position), row.id)
            self.assertEqual((row.severity, row.applies_to, row.source), (None, None, "scan_requirements"))

    def test_the_conditions_are_the_inventory_patterns_with_the_helper_flags_of_bash(self) -> None:
        rows = requirements.RULES.rules
        self.assertEqual([r.cond for r in rows], [
            Match(inventory_row(ROW_IDS[0])["pattern"], ci=True),            # grep_check_i
            Match(inventory_row(ROW_IDS[1])["pattern"]),                     # grep_check
            Match(inventory_row(ROW_IDS[2])["pattern"], ci=True),
            Match(inventory_row(ROW_IDS[3])["pattern"], ci=True),
            Match(inventory_row(ROW_IDS[4])["pattern"], excl=inventory_row(ROW_IDS[4])["excl"]),   # grep_check_excl
        ])

    def test_the_inventory_has_exactly_these_five_calls_in_this_order(self) -> None:
        self.assertEqual([r["id"] for r in sorted(inventory(), key=lambda r: r["line"])], list(ROW_IDS))

    def test_messages_occur_in_the_bash_function_in_the_same_order(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        body = text[text.index("scan_requirements() {"):]
        body = body[:body.index("\n}\n")]
        order = re.findall(r'record_(?:fail|warn) "\$f" "([^"]+)"', body)
        self.assertEqual(order, [m for m, _ in ROWS])

    def test_every_pattern_is_registered_with_rx(self) -> None:
        by_id = {rule.id: rule for rule in rx.registered()}
        for position, row in enumerate(requirements.RULES.rules):
            inv = inventory_row(ROW_IDS[position])
            rule = by_id[row.id]
            self.assertEqual((rule.pattern, rule.excl), (inv["pattern"], inv.get("excl")))
            self.assertEqual(rule.mode, {"grep_check": "line", "grep_check_i": "line_i", "grep_check_excl": "excl"}[inv["helper"]])

    def test_no_module_level_mutable_state(self) -> None:
        for name, value in vars(requirements).items():
            if not name.startswith("__"):
                self.assertNotIsInstance(value, (list, dict, set), name)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RuleRowTests(unittest.TestCase):
    def test_every_case_records_its_messages_in_bash_order_and_then_a_pass_unless_a_fail_fired(self) -> None:
        for data, label, messages in CASES:
            with self.subTest(label=label, data=data[:60]):
                h = scan(self, data)
                self.assertEqual(h.messages(), expected_messages(messages))
                fails = [m for m in messages if dict(ROWS)[m] == "fail"]
                warns = len(messages) - len(fails)
                if fails:
                    self.assertEqual(h.status(), "FAIL")
                    self.assertEqual(counters(h), (0, warns, len(fails)), "no PASS after a FAIL")
                    self.assertEqual(h.verdict.verdict, "FAIL")
                else:
                    self.assertEqual(h.status(), "WARN" if warns else "PASS")
                    self.assertEqual(counters(h), (1, warns, 0), "bash: failed=false, so record_pass follows the warnings")
                    self.assertEqual(h.verdict.verdict, "PASS")

    def test_a_file_that_trips_every_row_gets_the_five_messages_in_bash_order(self) -> None:
        data = (b"--index-url http://a.example/simple\n"
                b"--extra-index-url https://deploy:hunter2pass@b.example/simple\n"
                b"--trusted-host b.example\n"
                b"git+https://c.example/r.git#egg=r\n")
        h = scan(self, data)
        self.assertEqual(h.messages(), expected_messages((M_PLAIN, M_CRED, M_TRUSTED, M_EXTRA, M_VCS)))
        self.assertEqual(counters(h), (0, 3, 2))

    def test_the_scanner_does_not_look_at_the_file_name(self) -> None:
        for rel in ("requirements.txt", "requirements-dev.txt", "constraints.txt", "sub/requirements_test.txt", "odd name.txt", "NOEXT"):
            with self.subTest(rel=rel):
                self.assertEqual(scan(self, b"--trusted-host a\n", rel=rel).messages(), expected_messages((M_TRUSTED,)))

    def test_the_fixtures(self) -> None:
        clean = scan(self, (ROOT / "tests" / "fixtures" / "clean" / "requirements.txt").read_bytes())
        self.assertEqual((clean.messages(), clean.status(), counters(clean)), ([], "PASS", (1, 0, 0)))
        evil = scan(self, (FIXTURES / "req_evil" / "requirements.txt").read_bytes())
        self.assertEqual(evil.messages(), expected_messages((M_PLAIN, M_CRED, M_EXTRA)))
        safe = scan(self, (FIXTURES / "req_safe" / "requirements.txt").read_bytes())
        self.assertEqual(safe.messages(), expected_messages((M_TRUSTED, M_EXTRA)))
        self.assertEqual((safe.status(), counters(safe)), ("WARN", (1, 2, 0)))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class FiredTests(unittest.TestCase):
    """``fired`` is true when a FAIL row matched, whatever the allowlist or the threshold did with it: no PASS beside it."""

    def test_an_allowlisted_fail_is_a_warn_and_there_is_no_pass(self) -> None:
        allow = Allowlist({("CWE-319", REL): "internal mirror"})
        h = scan(self, b"--index-url http://mirror.corp.example/simple\n", allowlist=allow)
        self.assertEqual(h.messages(), [("WARN", "ALLOWED:%s (reason: internal mirror)" % M_PLAIN)])
        self.assertEqual((h.status(), counters(h), h.verdict.verdict), ("WARN", (0, 1, 0), "PASS"))

    def test_an_allowlisted_fail_does_not_excuse_the_other_fail(self) -> None:
        allow = Allowlist({("CWE-319", REL): "internal mirror"})
        h = scan(self, b"--index-url http://u:p@mirror.corp.example/simple\n", allowlist=allow)
        self.assertEqual(h.messages(), [("WARN", "ALLOWED:%s (reason: internal mirror)" % M_PLAIN), ("FAIL", M_CRED)])

    def test_the_second_fail_rule_is_matched_by_its_own_token(self) -> None:
        allow = Allowlist({("CWE-798", REL): "build token"})
        h = scan(self, b"https://u:p@private.example/simple\n", allowlist=allow)
        self.assertEqual(h.messages(), [("WARN", "ALLOWED:%s (reason: build token)" % M_CRED)])
        self.assertEqual(counters(h), (0, 1, 0))

    def test_a_fail_below_the_threshold_is_a_warn_and_there_is_no_pass(self) -> None:
        h = scan(self, b"--index-url http://x.example/simple\n", threshold=4, min_severity="critical")
        self.assertEqual(h.messages(), [("WARN", "LOW_SEV(below --min-severity critical):" + M_PLAIN)])
        self.assertEqual(counters(h), (0, 1, 0))

    def test_a_warn_rule_is_not_an_allowlist_target(self) -> None:
        allow = Allowlist({("pip", REL): "x"})
        h = scan(self, b"--trusted-host a\n", allowlist=allow)
        self.assertEqual(h.messages(), expected_messages((M_TRUSTED,)))


class EngineFailureTests(unittest.TestCase):
    def test_a_search_that_cannot_finish_is_the_engine_fail_and_no_pass(self) -> None:
        with mock.patch("transit.rules.run_ruleset", side_effect=MemoryError):
            h = scan(self, b"requests==2.0\n")
        self.assertEqual(h.messages(), [("FAIL", "engine:search_incomplete")])
        self.assertEqual(counters(h), (0, 0, 1))

    def test_a_passed_file_deadline_is_the_engine_fail_and_no_pass(self) -> None:
        h = scan(self, b"requests==2.0\n", deadline=time.monotonic() - 1.0)
        self.assertEqual(h.messages(), [("FAIL", "engine:scan_incomplete:manifest.requirements:time_budget")])
        self.assertEqual(counters(h), (0, 0, 1))
        h.verdict.record_layer("L5_per_language_sast", "ran")
        self.assertIn("per-file time budget reached", h.snapshot().coverage["L5_per_language_sast"])


# ═══════════════════════════════════════════════════════════════════════════════════════════════
@NEEDS_GREP
class OracleTests(unittest.TestCase):
    """The five rows against the real greps of the hardened bash function."""

    def test_the_hand_written_cases_are_what_grep_says(self) -> None:
        for data, label, messages in CASES:
            with self.subTest(label=label):
                self.assertEqual(bash_oracle(data), list(messages))

    def test_random_documents_agree_with_grep_exactly(self) -> None:
        rnd = random.Random(20261114)
        seen = {m: 0 for m, _ in ROWS}
        for case in range(220):
            data = random_document(rnd, TOKENS)
            expect = bash_oracle(data)
            for message in expect:
                seen[message] += 1
            h = scan(self, data)
            self.assertEqual([m for _, m in h.messages() if not m.startswith(("ALLOWED", "LOW_SEV"))], expect, "case %d: %r" % (case, data))
        for message, count in seen.items():
            self.assertGreater(count, 3, "the random documents must exercise %s (%d times)" % (message, count))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class NulTests(unittest.TestCase):
    """D-029 (closed in bash): the exclusion rule reads a file with a NUL byte as text, and the SearchPolicy is the single control point."""

    UNPINNED = b"git+https://x.example/pkg.git#egg=pkg\n\0\n"

    def test_a_nul_byte_does_not_blind_the_vcs_rule(self) -> None:
        h = scan(self, self.UNPINNED)
        self.assertEqual(h.messages(), expected_messages((M_VCS,)))

    def test_the_frozen_default_policy_would_blind_it_and_the_scanner_does_not_choose(self) -> None:
        h = scan(self, self.UNPINNED, policy=SearchPolicy(rule_budget_s=0.25, long_line_bytes=8192, excl_nul_blind=True))
        self.assertEqual(h.messages(), [], "the pre-hardening behaviour, reachable only through the policy")

    @NEEDS_GREP
    def test_the_vcs_rule_equals_the_hardened_bash_pipeline_on_files_with_nul_bytes(self) -> None:
        rnd = random.Random(99)
        tokens = TOKENS + [b"\0", b"\0", b"\n"]
        for case in range(120):
            data = random_document(rnd, tokens)
            expect = bash_oracle(data, only=(4,))
            h = scan(self, data)
            self.assertEqual([m for _, m in h.messages() if m == M_VCS], expect, "case %d: %r" % (case, data))

    def test_a_file_with_a_nul_byte_is_still_examined_by_every_row(self) -> None:
        data = b"--index-url http://x.example/simple\n\0\0\n--trusted-host a\n"
        h = scan(self, data)
        self.assertEqual(h.messages(), expected_messages((M_PLAIN, M_TRUSTED)))

    @NEEDS_GREP
    def test_a_nul_inside_a_credential_url_can_only_add_findings_against_bash(self) -> None:
        # E8: the credential row is unanchored; a match bash finds is found here, and a match across the NUL is found here only
        across = b"https://u\0x:pass@h.example/\n"
        self.assertEqual(bash_oracle(across, only=(1,)), [])
        self.assertEqual([m for _, m in scan(self, across).messages()], [M_CRED])
        plain = b"https://user:pass@h.example/\n\0"
        self.assertEqual(bash_oracle(plain, only=(1,)), [M_CRED])
        self.assertEqual([m for _, m in scan(self, plain).messages()], [M_CRED])

    @NEEDS_GREP
    def test_known_difference_a_directive_after_a_nul_is_a_line_start_to_bash_and_not_to_this_engine(self) -> None:
        # E8, reported to the lead. grep_check has no -a, so bash reads the NUL as a line break and ``^`` matches after it; the row here is
        # ``grep -a``. pip does not honour such a line (it fails to parse ``\0--trusted-host``), so nothing real is hidden; the test pins the
        # difference so that a later switch of the rules to bash's reading (rx binary="grep") is a deliberate act.
        data = b"x\0--trusted-host a.example\n"
        self.assertEqual(bash_oracle(data, only=(2,)), [M_TRUSTED])
        self.assertEqual(scan(self, data).messages(), [])


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class HostileInputTests(unittest.TestCase):
    def test_a_600_kb_line_is_searched_in_bounded_time_and_the_match_at_its_end_is_found(self) -> None:
        began = time.monotonic()
        filler = b"--index-url "
        clean = scan(self, filler * 50000 + b"\n")
        late_url = scan(self, filler * 50000 + b"http://x.example/simple\n")
        excused = scan(self, b"git+https://x.example/r.git@abcdef1 " * 20000 + b"git+ssh://y.example/r.git\n")
        self.assertLess(time.monotonic() - began, 30.0)
        self.assertEqual(clean.messages(), [])
        self.assertEqual(late_url.messages(), [])   # the option must be FIRST on the line and followed directly by the URL: it is not
        self.assertEqual(excused.messages(), [])    # one line, and it holds a pinned revision: the line is excused whole (per-line exclusion)

    def test_a_long_line_that_starts_with_the_option_is_found(self) -> None:
        h = scan(self, b"--index-url http://x.example/simple " + b"x" * 600000 + b"\n")
        self.assertEqual(h.messages(), expected_messages((M_PLAIN,)))

    def test_a_long_unpinned_line_is_found_by_the_exclusion_rule(self) -> None:
        h = scan(self, b"git+https://x.example/r.git " + b"y" * 600000 + b"\n")
        self.assertEqual(h.messages(), expected_messages((M_VCS,)))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
def run_tree(test: unittest.TestCase, files: "dict[str, bytes]", extra: "dict | None" = None) -> support.Harness:
    """Scan ``files`` the way ``layers.run_file_layers`` does (universal layer through ``guard``, then ``classify_file`` with a ``run`` that calls ``invoke``)."""
    scanners: dict = {spec.id: spec for spec in requirements.SCANNERS}
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
    def test_the_golden_rules_corpus_fixtures(self) -> None:
        golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["report"]["file_results"]
        names = ("req_evil/requirements.txt", "req_safe/requirements.txt")
        h = run_tree(self, {name: (FIXTURES / name).read_bytes() for name in names})
        for name in names:
            with self.subTest(fixture=name):
                self.assertEqual(h.status(h.repo.recorded(name)), golden[name]["status"])
                self.assertEqual(formatted(h, name), sorted(golden[name]["messages"]))

    def test_the_clean_fixture_passes_with_no_message_and_one_pass_event(self) -> None:
        h = run_tree(self, {"requirements.txt": (ROOT / "tests" / "fixtures" / "clean" / "requirements.txt").read_bytes()})
        self.assertEqual((h.status(h.repo.recorded("requirements.txt")), h.messages(h.repo.recorded("requirements.txt")), counters(h)),
                         ("PASS", [], (1, 0, 0)))

    def test_dispatch_sends_the_requirement_names_here_and_nothing_else(self) -> None:
        text = b"--index-url http://x.example/simple\n"
        routed = ("requirements.txt", "requirements-dev.txt", "requirements_test.txt", "requirementsX.txt", "constraints.txt",
                  "constraints-3.txt", "sub/dir/requirements.txt")
        not_routed = ("Requirements.txt", "requirement.txt", "my-requirements.txt", "requirements.md", "requirements.txt.bak", "requirements")
        h = run_tree(self, {name: text for name in routed + not_routed})
        for name in routed:
            with self.subTest(routed=name):
                self.assertEqual(h.messages(h.repo.recorded(name)), [("FAIL", M_PLAIN)])
        for name in not_routed:
            with self.subTest(not_routed=name):
                self.assertNotIn(("FAIL", M_PLAIN), h.messages(h.repo.recorded(name)))

    def test_a_requirements_file_that_starts_with_an_rtf_header_is_still_a_requirements_file(self) -> None:
        # the basename arm ends the dispatch before any RTF sniff, as in bash
        called: "list[str]" = []

        def fake_rtf(ctx) -> bool:
            called.append(ctx.rel)
            ctx.record_pass()
            return True

        h = run_tree(self, {"requirements.txt": b"{\\rtf1 --index-url http://x.example/simple\n"}, extra={"rtf": fake_rtf})
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
