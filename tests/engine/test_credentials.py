"""Tests of transit/scanners/credentials.py (WP-08): the 18 known credential formats, the JWT warning and ``check_known_credentials``.

    python3 -I -m unittest discover -s tests/engine -p "test_credentials.py"

The module is exercised over a REAL ``ScanContext`` (``tests/engine/support.make_context``: real ``Verdict``, ``FileView`` and rule
machinery) and, as the oracle the design asks for, against REAL GNU ``grep``: ``OracleTests`` runs the bash pipeline of ``_known_cred_check``
(``grep -qIE`` of the alternation, then per provider ``grep -ohIE | grep -viE`` of the exclusion, then ``grep -qIE`` of the JWT) on the same
bytes and compares the decision. The patterns the oracle uses are read from tests/conformance/patterns.json, not from the module under test.

A token-shaped credential is NEVER written contiguously in this file: every one is assembled at run time from a context, a prefix and
two halves of a body held in separate string literals (``tests/run_tests.sh`` does the same), because this pipeline run over its own
repository would otherwise flag its own test suite.
"""
from __future__ import annotations

import ast
import dataclasses
import json
import os
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
from transit import rx  # noqa: E402
from transit.findings import Allowlist  # noqa: E402
from transit.rules import Match, Matcher, ScanBudgetExceeded  # noqa: E402
from transit.scanners import credentials  # noqa: E402
from transit.scanners.credentials import CredentialResult, check_known_credentials  # noqa: E402

CRED_MODULE = ROOT / "transit" / "scanners" / "credentials.py"
FAIL_PREFIX = "CWE-798:known_credential_format_"


def j(*parts: str) -> str:
    return "".join(parts)


#: One line holding a token of each provider (context, prefix, two halves of the body), the shapes of tests/run_tests.sh.
SECRET_LINES = {
    "aws_access_key_id": j("aws_access_key_id = ", "AKIA", "WSLDPOPA", "8IDMMTGM"),
    "aws_secret_access_key": j("aws_secret_access_key = ", "toB5aoVsS8hhss6inCQm", "w31l26fqXAhjVmMyamjX"),
    "github_token": j("export GITHUB_TOKEN=", "ghp_", "oKFEOeVI2WdxcX4L8y", "aUEcp4bWTkt2HGVHQx"),
    "github_fine_grained_pat": j("token: ", "github_pat_", "Uc2tDa29hb5sLLd6cUGXayGrBbDUvQ", "mSuP4MJ5SQGUH7FrVQ2quG8z1YJ0Kw"),
    "gitlab_pat": j("GITLAB_TOKEN=", "glpat-", "Twtt7L5tbe", "6IDp_3st9F"),
    "stripe_live_key": j("STRIPE_KEY=", "sk_live_", "KUbMBGKxflzvZd", "u34gMRmaUrUwyM"),
    "slack_token": j("SLACK_BOT_TOKEN=", "xoxb-", "871990237361-137326652659", "-tZddgPODHoEidsYlVEEBxzud"),
    "google_api_key": j("key = ", "AIza", "CrCX6iZlxlj7fDNuR", "GwJSfhIENqKTTiqt2x"),
    "google_oauth_token": j("access = ", "ya29.", "N5OXzzezpSWT9SqRzG9l", "Up--cLLpQJa3WIeMosrs"),
    "sendgrid_key": j("SENDGRID=", "SG.", "mhSJnHLwAXcUnTf6MvPTVg.QU9gnSsHUU", "FRleDJAlNhCYlhQupaD70ahgOQ0TvJDK5"),
    "npm_token": j("//registry.npmjs.org/:_authToken=", "npm_", "NMNGQAItkyWqEc3VQh", "aX31ke6Uu53X2ohd5c"),
    "pypi_token": j("password = ", "pypi-AgEIcHlwaS5vcmc", "8dNKdzVHlw6s5wWOroxjtBhYeNvuvg", "lFU9leuBZHYyEBrxKbg2Ir6zOKRuhl"),
    "huggingface_token": j("HF_TOKEN=", "hf_", "HyqmHLPFDUi4OOEit", "j59FfZTWuE7xVAuwQ"),
    "anthropic_key": j("ANTHROPIC_API_KEY=", "sk-ant-api03-", "DRlCCy2XaflpZPEIkEosNeLJvFZJX_ucvqIDITZFgE0_F",
                       "bvIY3nXCZY72Co5fzjVj-zG5eISJVAG7_rr0xKBvwNsmJ"),
    "openai_project_key": j("OPENAI_API_KEY=", "sk-proj-", "8VpoAuXnm-sMkbiTANEBhAxQ", "FknjLLlzjkXnHlNfyeG6hf9q"),
    "openai_legacy_key": j("OPENAI_API_KEY=", "sk-", "WXrSZrLEeoS7bCDUC64yhrYq", "zb3joq4YDtfomwplf3LZ3cws"),
    "shopify_token": j("SHOPIFY=", "shpat_", "cd7701ff77976566", "445ff51d43c0a76f"),
    "digitalocean_token": j("DO_TOKEN=", "dop_v1_", "81e402f19126284c122a510e2ed5e81d", "a5487e8579f405b60532147c46e01bfa"),
}
JWT_LINE = j("session = ", "eyJlCIxr89LcspvfiHbtwjH_j3Db0BtCH9sY", ".", "eyJFsvZc6Xjc3Gy4Orwd", "naWW-iTRnXvaZtm9eaygGWI", ".",
             "3r90T2kmsR95izWTG1E3s9nE_5jG_f34X5FPbxph9y5")
#: Lines a naive pattern flags and the rule must not (tests/run_tests.sh, ``known_safe.txt``).
NEAR_MISSES = {
    "AWS documentation key": j("aws_access_key_id = ", "AKIAIOSFODNN7", "EXAMPLE"),
    "placeholder body": j("token = ", "ghp_", "x" * 36),
    "one repeated character": j("token = ", "ghp_", "A" * 36),
    "GitHub documentation token": j("token = ", "ghp_16C7e42F", "292c6912E7710c838347Ae178B4a"),
    "Stripe test key": j("STRIPE_KEY=", "sk_test_", "PP7tbgUZLQPJww5wQMMyBQQn5zpG"),
    "underscores end a token": "x = hf_config_value_that_is_long_enough_to_look_real",
    "a git sha": "commit 3a7bd3e2360a3d29eea436fcfb7e44c735d117c4",
    "token embedded mid-identifier": j("id = zzAKIA", "Z961ELEFI1I64MFQ", "zz"),
    "too short": j("token = ", "ghp_", "a1B2c3D4"),
}

GREP = shutil.which("grep")


def _gnu_grep() -> bool:
    if GREP is None:
        return False
    try:
        out = subprocess.run([GREP, "--version"], capture_output=True, timeout=10, env={"LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return b"GNU grep" in out


HAVE_GNU_GREP = _gnu_grep()


def inventory() -> "list[dict]":
    """The ``_known_cred_check`` entries of tests/conformance/patterns.json (what bash hands to grep), independent of the module."""
    rows = json.loads((ROOT / "tests" / "conformance" / "patterns.json").read_text(encoding="utf-8"))
    return [r for r in rows if r.get("enclosing_function") == "_known_cred_check"]


def inventory_alternation() -> str:
    return [r["pattern"] for r in inventory() if r["flags"] == "-qIE" and r.get("dynamic")][0]


def inventory_jwt() -> str:
    return [r["pattern"] for r in inventory() if r["flags"] == "-qIE" and not r.get("dynamic")][0]


def inventory_providers() -> "list[tuple[str, str, str]]":
    """``(name, wrapped pattern, exclusion)`` in bash order (KNOWN_CRED_PATS index), from the ``-ohIE`` entries."""
    found = {}
    for row in inventory():
        if row["flags"] != "-ohIE":
            continue
        head, _, rest = row["resolved_by"].partition("] (")
        found[int(head.partition("[")[2])] = (rest.rstrip(")"), row["pattern"], row["excl"])
    return [found[index] for index in sorted(found)]


def run_grep(args: "list[str]", *, stdin: "bytes | None" = None) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run([GREP or "grep"] + args, input=stdin, capture_output=True, timeout=60, env={"LC_ALL": "C"})


class GrepOracle:
    """Bash ``_known_cred_check`` on a file, with the real grep. ``decide(data)`` -> ``(providers in bash order, jwt)``."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="wp08-oracle-")
        self.path = os.path.join(self._tmp.name, "subject")
        self.alternation = inventory_alternation()
        self.jwt = inventory_jwt()
        self.providers = inventory_providers()

    def close(self) -> None:
        self._tmp.cleanup()

    def decide(self, data: bytes) -> "tuple[tuple[str, ...], bool]":
        with open(self.path, "wb") as handle:
            handle.write(data)
        fired = []
        if run_grep(["-qIE", "-e", self.alternation, self.path]).returncode == 0:
            for name, wrapped, excl in self.providers:
                matched = run_grep(["-ohIE", "-e", wrapped, self.path]).stdout
                if matched and run_grep(["-viE", "-e", excl], stdin=matched).stdout:
                    fired.append(name)
        return tuple(fired), run_grep(["-qIE", "-e", self.jwt, self.path]).returncode == 0


def context(test: unittest.TestCase, data: "bytes | str", rel: str = "a.txt", **kwargs) -> support.Harness:
    return support.make_context(test, rel, data, **kwargs)


def lines(*parts: str, sep: str = "\n") -> bytes:
    return (sep.join(parts) + sep).encode("utf-8")


# ---------------------------------------------------------------------------------------------------------------------------
class ConstantsTests(unittest.TestCase):
    """The tables are the bash tables, character for character, and every pattern is a registered ``Matcher``."""

    def test_the_eighteen_names_in_bash_order(self):
        self.assertEqual(len(credentials.PROVIDER_NAMES), 18)
        self.assertEqual(credentials.PROVIDER_NAMES, tuple(name for name, _w, _e in inventory_providers()))

    def test_provider_patterns_are_the_bare_patterns_of_the_inventory(self):
        self.assertEqual(tuple(credentials.PROVIDER_PATTERNS), credentials.PROVIDER_NAMES)
        for name, wrapped, _excl in inventory_providers():
            with self.subTest(name):
                self.assertEqual(wrapped, "(^|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|$)" % credentials.PROVIDER_PATTERNS[name])

    def test_provider_patterns_cannot_be_changed(self):
        with self.assertRaises(TypeError):
            credentials.PROVIDER_PATTERNS["x"] = "y"            # type: ignore[index]
        with self.assertRaises(TypeError):
            credentials.PROVIDER_MATCHERS["x"] = None           # type: ignore[index]

    def test_the_alternation_is_the_one_bash_passes_to_grep(self):
        self.assertIsInstance(credentials.ALTERNATION, Matcher)
        self.assertEqual(credentials.ALTERNATION.match.pattern, inventory_alternation())
        self.assertEqual(credentials.ALTERNATION.id, "credentials/alternation")

    def test_one_matcher_per_provider_with_the_wrapped_pattern(self):
        self.assertEqual(tuple(credentials.PROVIDER_MATCHERS), credentials.PROVIDER_NAMES)
        for name, wrapped, _excl in inventory_providers():
            with self.subTest(name):
                matcher = credentials.PROVIDER_MATCHERS[name]
                self.assertIsInstance(matcher, Matcher)
                self.assertEqual(matcher.id, "credentials/" + name)
                self.assertEqual(matcher.match.pattern, wrapped)

    def test_the_jwt_pattern_and_message(self):
        self.assertEqual(credentials.JWT_PATTERN, inventory_jwt())
        self.assertEqual(credentials.JWT.match.pattern, inventory_jwt())
        self.assertEqual(credentials.JWT.id, "credentials/jwt")
        self.assertEqual(credentials.JWT_MESSAGE, "CWE-798:jwt_embedded_review_whether_it_is_a_live_credential")

    def test_every_matcher_reads_like_grep_dash_I(self):
        """``binary="skip"`` is ``grep -I``; the mode is ``line`` (``grep -qE`` / ``-oE``), never case-insensitive."""
        every = [credentials.ALTERNATION, credentials.JWT, *credentials.PROVIDER_MATCHERS.values()]
        self.assertEqual(len(every), 20)
        for matcher in every:
            with self.subTest(matcher.id):
                self.assertEqual((matcher.match.binary, matcher.match.mode, matcher.match.ci, matcher.match.excl), ("skip", "line", False, None))

    def test_every_matcher_is_registered_with_rx(self):
        by_id = {rule.id: rule for rule in rx.registered()}
        for matcher in [credentials.ALTERNATION, credentials.JWT, *credentials.PROVIDER_MATCHERS.values()]:
            with self.subTest(matcher.id):
                self.assertIn(matcher.id, by_id)
                self.assertEqual((by_id[matcher.id].pattern, by_id[matcher.id].mode), (matcher.match.pattern, "line"))

    def test_the_exclusion_is_the_bash_exclusion_and_not_a_matcher(self):
        for name, _wrapped, excl in inventory_providers():
            self.assertEqual(excl, credentials.EXCLUSION, name)
        self.assertNotIn(credentials.EXCLUSION, [rule.pattern for rule in rx.registered()])   # it has a back-reference: no linear matcher

    def test_this_module_never_holds_a_contiguous_token(self):
        """The GitHub documentation token is written in two pieces in the source (the repository is itself scanned)."""
        text = CRED_MODULE.read_text(encoding="utf-8")
        documentation_token = j("ghp_16C7e42F", "292c6912E7710c838347Ae178B4a")
        self.assertNotIn(documentation_token, text)
        self.assertIn(documentation_token, credentials.EXCLUSION)

    def test_result_is_a_frozen_dataclass(self):
        result = CredentialResult(failed=False, providers=(), jwt=False)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.failed = True                                 # type: ignore[misc]
        self.assertEqual([f.name for f in dataclasses.fields(CredentialResult)], ["failed", "providers", "jwt"])

    def test_importing_it_is_silent_and_does_not_need_the_universal_layer(self):
        code = ("import sys\nfrom transit.scanners import credentials\n"
                "assert 'transit.scanners.universal' not in sys.modules\nassert credentials.ALTERNATION is not None\n")
        run = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r)\n%s" % (str(ROOT), code)],
                             capture_output=True, timeout=60)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b"", b""), run.stderr)

    def test_no_pattern_is_compiled_or_built_inside_a_function(self):
        """Design 9 / 7.1 rule 8: every pattern is a module-level ``Matcher``; a ``Match(`` or an ``rx.ere_to_py(`` in a function would be
        invisible to ``rx.registered()``, the hostile-line test and the fuzz gate."""
        tree = ast.parse(CRED_MODULE.read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call):
                        func = inner.func
                        name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
                        if name in ("Match", "Matcher", "RuleSet", "ere_to_py", "ere_to_py_source", "rule", "compile", "parse_ere"):
                            offenders.append((node.name, name, inner.lineno))
        self.assertEqual(offenders, [])

    def test_no_whole_buffer_split_and_no_rx_after_context(self):
        text = CRED_MODULE.read_text(encoding="utf-8")
        for needle in ("after_context", "lines_over", "splitlines", "split(b\"\\n\")", "import re\n", "from re "):
            self.assertNotIn(needle, text, needle)


# ---------------------------------------------------------------------------------------------------------------------------
class ProviderTests(unittest.TestCase):
    """One positive and one near-miss per provider, recorded through a real context."""

    def test_each_provider_fires_alone(self):
        for name, line in SECRET_LINES.items():
            with self.subTest(name):
                h = context(self, lines(line))
                result = check_known_credentials(h.ctx)
                self.assertEqual(result, CredentialResult(failed=True, providers=(name,), jwt=False))
                self.assertEqual(h.messages(), [("FAIL", FAIL_PREFIX + name)])
                self.assertEqual(h.status(), "FAIL")

    def test_each_near_miss_is_clean(self):
        for name, line in NEAR_MISSES.items():
            with self.subTest(name):
                h = context(self, lines(line))
                self.assertEqual(check_known_credentials(h.ctx), CredentialResult(failed=False, providers=(), jwt=False))
                self.assertEqual(h.messages(), [])
                self.assertIsNone(h.status())              # it never records a PASS: that belongs to the type scanner

    def test_all_near_misses_in_one_file(self):
        h = context(self, lines(*NEAR_MISSES.values()))
        self.assertFalse(check_known_credentials(h.ctx).failed)
        self.assertEqual(h.messages(), [])

    def test_an_empty_file_and_a_file_without_a_final_newline(self):
        h = context(self, b"")
        self.assertEqual(check_known_credentials(h.ctx), CredentialResult(False, (), False))
        h2 = context(self, SECRET_LINES["github_token"].encode())          # no LF at the end: the token ends with the line
        self.assertEqual(check_known_credentials(h2.ctx).providers, ("github_token",))

    def test_the_token_at_the_start_of_a_line_and_followed_by_crlf(self):
        token = SECRET_LINES["github_token"].partition("=")[2]
        for name, data in (("line start", lines(token)), ("CRLF", lines(token, "next", sep="\r\n")), ("in quotes", lines('x = "%s"' % token)),
                           ("in a URL", lines("https://u:%s@host/repo" % token))):
            with self.subTest(name):
                h = context(self, data)
                self.assertEqual(check_known_credentials(h.ctx).providers, ("github_token",))

    def test_a_token_inside_a_longer_alphanumeric_run_is_not_a_token(self):
        token = SECRET_LINES["npm_token"].partition("=")[2]                      # a fixed length: one more character is not a token
        for name, line in (("letter before", "a" + token), ("digit after", token + "7"), ("letter after", token + "z")):
            with self.subTest(name):
                self.assertFalse(check_known_credentials(context(self, lines(line)).ctx).failed)

    def test_two_providers_are_reported_in_bash_order_not_file_order(self):
        h = context(self, lines(SECRET_LINES["github_token"], SECRET_LINES["aws_access_key_id"], SECRET_LINES["npm_token"]))
        result = check_known_credentials(h.ctx)
        self.assertEqual(result.providers, ("aws_access_key_id", "github_token", "npm_token"))
        self.assertEqual([m for _k, m in h.messages()], [FAIL_PREFIX + n for n in result.providers])

    def test_every_provider_in_one_file(self):
        h = context(self, lines(*SECRET_LINES.values()))
        result = check_known_credentials(h.ctx)
        self.assertEqual(result.providers, credentials.PROVIDER_NAMES)
        self.assertEqual([m for _k, m in h.messages()], [FAIL_PREFIX + n for n in credentials.PROVIDER_NAMES])

    def test_an_ordinary_file_costs_one_search_and_not_eighteen(self):
        """bash: ``One alternation decides whether any provider is present; only then is each named, so an ordinary file costs a single grep``."""
        h = context(self, lines("def add(a, b):", "    return a + b"))
        with mock.patch.object(h.ctx, "spans", wraps=h.ctx.spans) as spans:
            check_known_credentials(h.ctx)
        self.assertEqual(spans.call_count, 0)
        h = context(self, lines(SECRET_LINES["github_token"]))
        with mock.patch.object(h.ctx, "spans", wraps=h.ctx.spans) as spans:
            check_known_credentials(h.ctx)
        self.assertEqual(spans.call_count, len(credentials.PROVIDER_NAMES))          # a hit: each provider is named, in turn

    def test_the_provider_is_recorded_once_however_many_tokens_there_are(self):
        line = SECRET_LINES["github_token"]
        h = context(self, lines(line, line, line))
        check_known_credentials(h.ctx)
        self.assertEqual(h.messages(), [("FAIL", FAIL_PREFIX + "github_token")])

    def test_stripe_restricted_keys_and_the_other_alternatives(self):
        for name, line in (("stripe_live_key", j("rk_live_", "KUbMBGKxflzvZd", "u34gMRmaUrUwyM")),
                           ("shopify_token", j("shpca_", "cd7701ff77976566", "445ff51d43c0a76f")),
                           ("aws_access_key_id", j("ASIA", "WSLDPOPA", "8IDMMTGM")),
                           ("github_token", j("gho_", "oKFEOeVI2WdxcX4L8y", "aUEcp4bWTkt2HGVHQx")),
                           ("anthropic_key", j("sk-ant-admin01-", "DRlCCy2XaflpZPEIkEosNeLJvFZJX_ucvqIDITZFgE0_F", "bvIY3nXCZY72Co5fzjVj-zG5eISJVAG7_rr0xKBvwNsmJ")),
                           ("slack_token", j("xoxp-", "871990237361-137326652659-", "198765432101-", "tZddgPODHoEidsYlVEEBxzud"))):
            with self.subTest(name):
                self.assertEqual(check_known_credentials(context(self, lines(line)).ctx).providers, (name,))


# ---------------------------------------------------------------------------------------------------------------------------
class JwtTests(unittest.TestCase):
    def test_a_jwt_is_a_warning_and_never_a_failure(self):
        h = context(self, lines(JWT_LINE))
        result = check_known_credentials(h.ctx)
        self.assertEqual(result, CredentialResult(failed=False, providers=(), jwt=True))
        self.assertEqual(h.messages(), [("WARN", credentials.JWT_MESSAGE)])
        self.assertEqual(h.status(), "WARN")

    def test_the_warning_follows_the_failures(self):
        h = context(self, lines(JWT_LINE, SECRET_LINES["github_token"]))
        result = check_known_credentials(h.ctx)
        self.assertEqual(result, CredentialResult(failed=True, providers=("github_token",), jwt=True))
        self.assertEqual(h.messages(), [("FAIL", FAIL_PREFIX + "github_token"), ("WARN", credentials.JWT_MESSAGE)])

    def test_near_misses_of_the_jwt(self):
        for name, line in (("two segments", j("t = eyJlCIxr89LcspvfiHbtwjH_j3Db0BtCH9sY", ".", "eyJFsvZc6Xjc3Gy4OrwdnaWW")),
                           ("third segment too short", j("t = eyJlCIxr89LcspvfiHbtwjH_j3Db0", ".", "eyJFsvZc6Xjc3Gy4Orwd", ".", "short")),
                           ("not eyJ", j("t = abcdefghijklmnop", ".", "eyJFsvZc6Xjc3Gy4Orwd", ".", "3r90T2kmsR95izWTG1E3s9nE"))):
            with self.subTest(name):
                self.assertFalse(check_known_credentials(context(self, lines(line)).ctx).jwt)


# ---------------------------------------------------------------------------------------------------------------------------
class ExclusionTests(unittest.TestCase):
    """The placeholder exclusion is applied to the MATCHED TEXT of each match, not to the line and not to the file."""

    def fires(self, text: str) -> bool:
        return check_known_credentials(context(self, lines(text)).ctx).failed

    def test_each_placeholder_word_excludes_a_match(self):
        body = "Qw3rTy5uIo7pLk9Jh2Gf"                                    # 20 characters, the glpat- minimum
        for word in ("EXAMPLE", "SAMPLE", "DUMMY", "PLACEHOLDER", "YOUR", "REDACTED", "FAKE", "CHANGEME", "example", "ReDaCtEd"):
            with self.subTest(word):
                self.assertFalse(self.fires("t = glpat-" + word + body))
        self.assertTrue(self.fires("t = glpat-" + body))

    def test_runs_and_sequences_exclude_a_match(self):
        for name, text in (("six x", "xxxxxx"), ("six X", "XXXXXX"), ("ten zeros", "0" * 10), ("1234567890", "1234567890"),
                           ("abcdefgh", "abcdefgh"), ("ten of one letter", "q" * 10), ("ten of one digit", "7" * 10),
                           ("a mixed-case run", "kKkKkKkKkK")):
            with self.subTest(name):
                self.assertFalse(self.fires("t = glpat-" + text + "Qw3rTy5uIo7pLk9Jh"))
        for name, text in (("five x", "xxxxx"), ("nine zeros", "0" * 9), ("nine of one", "q" * 9), ("1234567891", "1234567891")):
            with self.subTest("near " + name):
                self.assertTrue(self.fires("t = glpat-" + text + "Zw3rTy5uIo7pLk9Jh2Gf"))      # a Z: ``q`` then ``Q`` would be ten of one letter under -i

    def test_the_github_documentation_token_is_excluded_and_a_neighbour_is_not(self):
        doc = j("ghp_16C7e42F", "292c6912E7710c838347Ae178B4a")
        self.assertFalse(self.fires("t = " + doc))
        self.assertTrue(self.fires("t = " + doc[:-1] + "c"))

    def test_a_line_with_an_excluded_and_a_real_token_still_fails(self):
        """bash: ``grep -o`` prints each match on its own line and ``grep -v`` keeps the survivors: one real token among placeholders is enough."""
        real = SECRET_LINES["aws_access_key_id"].partition("= ")[2]
        example = j("AKIAIOSFODNN7", "EXAMPLE")
        for name, text in (("two lines", "%s\n%s\n" % (example, real)), ("real first", "%s\n%s\n" % (real, example)),
                           ("one line, two spaces", "%s  %s" % (example, real)), ("one line, comma", "%s, %s" % (example, real))):
            with self.subTest(name):
                h = context(self, text.encode())
                self.assertEqual(check_known_credentials(h.ctx).providers, ("aws_access_key_id",))

    def test_the_word_around_the_token_does_not_exclude_it(self):
        """The exclusion looks at the matched text (token plus one delimiter on each side), not at the rest of the line."""
        real = SECRET_LINES["aws_access_key_id"].partition("= ")[2]
        for text in ("# EXAMPLE: key is %s" % real, "YOUR key: %s (REDACTED elsewhere)" % real, "%s # DUMMY" % real):
            with self.subTest(text[:20]):
                self.assertTrue(self.fires(text))

    def test_a_placeholder_inside_an_aws_secret_assignment(self):
        self.assertFalse(self.fires(j("aws_secret_access_key = ", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY")))
        self.assertTrue(self.fires(SECRET_LINES["aws_secret_access_key"]))


# ---------------------------------------------------------------------------------------------------------------------------
class NulTests(unittest.TestCase):
    """A14 / D-014 copied: ``grep -I`` treats a file whose first 32 KiB hold a NUL byte as binary and matches nothing."""

    def test_a_nul_byte_silences_every_format_and_the_jwt(self):
        for name, nul_at in (("start", 0), ("middle", 20), ("end", None)):
            data = lines(SECRET_LINES["github_token"], JWT_LINE)
            data = data + b"\0" if nul_at is None else data[:nul_at] + b"\0" + data[nul_at:]
            with self.subTest(name):
                h = context(self, data)
                self.assertEqual(check_known_credentials(h.ctx), CredentialResult(False, (), False))
                self.assertEqual(h.messages(), [])

    def test_the_same_bytes_without_the_nul_byte_fire(self):
        data = lines(SECRET_LINES["github_token"], JWT_LINE)
        h = context(self, data)
        self.assertEqual(check_known_credentials(h.ctx), CredentialResult(True, ("github_token",), True))

    def test_a_nul_byte_inside_the_text_view_a_scanner_passes(self):
        """The jar and office scanners pass ``data=``: the same rule applies to that text."""
        h = context(self, b"nothing here\n")
        self.assertFalse(check_known_credentials(h.ctx, data=b"\0" + lines(SECRET_LINES["github_token"])).failed)
        self.assertTrue(check_known_credentials(h.ctx, data=lines(SECRET_LINES["github_token"])).failed)


class NulSwitchTests(unittest.TestCase):
    """D-014 (accepted for the Python engine, ``TRANSIT_FIXES=D-014``): the formats ALSO read a file that holds a NUL byte, as ``grep`` without
    ``-I`` does (a NUL ends a line, so a token cannot span one). Off by default: the default copies bash (A14), see ``NulTests``."""

    def switched(self, data: "bytes | str", **kwargs) -> support.Harness:
        return context(self, data, cfg=support.make_config(TRANSIT_FIXES="D-014"), **kwargs)

    def test_a_nul_byte_no_longer_hides_a_token(self):
        token = lines(SECRET_LINES["github_token"], JWT_LINE)
        for name, data in (("start", b"\0" + token), ("middle", token[:20] + b"\0" + token[20:]), ("end", token + b"\0"),
                           ("only nul lines around", b"\0\n" + token + b"\0\n"), ("many", b"\0" * 5000 + token + b"\0" * 5000)):
            with self.subTest(name):
                h = self.switched(data)
                self.assertEqual(check_known_credentials(h.ctx), CredentialResult(True, ("github_token",), True))
                self.assertEqual(h.messages(), [("FAIL", FAIL_PREFIX + "github_token"), ("WARN", credentials.JWT_MESSAGE)])

    def test_the_default_still_copies_bash(self):
        h = context(self, b"\0" + lines(SECRET_LINES["github_token"]))
        self.assertFalse(check_known_credentials(h.ctx).failed)
        h = context(self, b"\0" + lines(SECRET_LINES["github_token"]), cfg=support.make_config(TRANSIT_FIXES="D-029"))
        self.assertFalse(check_known_credentials(h.ctx).failed)                  # another switch does not turn this one on

    def test_a_token_is_not_made_by_a_nul_byte_in_the_middle_of_it(self):
        token = SECRET_LINES["github_token"].partition("=")[2]
        h = self.switched(("x = " + token[:20]).encode() + b"\0" + token[20:].encode() + b"\n")
        self.assertFalse(check_known_credentials(h.ctx).failed)

    def test_a_placeholder_is_still_a_placeholder_and_a_near_miss_a_near_miss(self):
        for name, line in NEAR_MISSES.items():
            with self.subTest(name):
                h = self.switched(b"\0" + lines(line))
                self.assertEqual(check_known_credentials(h.ctx), CredentialResult(False, (), False))

    def test_the_text_view_of_a_scanner_is_read_too(self):
        h = self.switched(b"harmless\n", rel="lib.jar")
        result = check_known_credentials(h.ctx, data=b"\0" + lines(SECRET_LINES["gitlab_pat"]), report_file=h.ctx.path)
        self.assertEqual(result.providers, ("gitlab_pat",))

    def test_a_file_without_a_nul_byte_is_searched_as_before(self):
        h = self.switched(lines(SECRET_LINES["github_token"], JWT_LINE))
        self.assertEqual(check_known_credentials(h.ctx), CredentialResult(True, ("github_token",), True))

    def test_the_file_itself_is_not_changed_and_the_cost_is_linear(self):
        data = (b"\0" + lines(*NEAR_MISSES.values())) * 2000
        h = self.switched(data)
        started = time.perf_counter()
        self.assertFalse(check_known_credentials(h.ctx).failed)
        self.assertLess(time.perf_counter() - started, 5.0)
        self.assertEqual(h.view.data(), data)

    def test_a_long_line_between_nul_bytes_fails_closed_like_any_long_line(self):
        long_line = b"pad " * 5000 + j("AKIAIOSFODNN7", "EXAMPLE").encode()
        h = self.switched(b"\0" + long_line + b"\0\n")
        self.assertEqual(check_known_credentials(h.ctx).providers, ("aws_access_key_id",))


@unittest.skipUnless(HAVE_GNU_GREP, "GNU grep is the oracle")
class NulSwitchOracleTests(unittest.TestCase):
    """With D-014 on, the decision on a NUL file equals ``_known_cred_check`` with ``-a`` instead of ``-I`` (grep reads the file; NUL is a delimiter)."""

    def decide(self, data: bytes) -> "tuple[tuple[str, ...], bool]":
        with tempfile.TemporaryDirectory(prefix="wp08-nul-") as tmp:
            path = os.path.join(tmp, "subject")
            with open(path, "wb") as handle:
                handle.write(data)
            fired = []
            for name, wrapped, excl in inventory_providers():
                matched = run_grep(["-ohaE", "-e", wrapped, path]).stdout
                if matched and run_grep(["-aviE", "-e", excl], stdin=matched).stdout:          # -a: the matched text can hold the NUL byte
                    fired.append(name)
            return tuple(fired), run_grep(["-qaE", "-e", inventory_jwt(), path]).returncode == 0

    def test_the_decision_equals_greps_without_dash_I(self):
        gh = SECRET_LINES["github_token"].partition("=")[2]
        real = SECRET_LINES["aws_access_key_id"].partition("= ")[2]
        example = j("AKIAIOSFODNN7", "EXAMPLE")
        corpus = {"token and NUL": b"\0" + lines(SECRET_LINES["github_token"]), "token, jwt, NUL": lines(SECRET_LINES["github_token"], JWT_LINE) + b"\0",
                  "NUL between two tokens": gh.encode() + b"\0" + real.encode() + b"\n", "NUL as the delimiter": b"\0" + gh.encode() + b"\0",
                  "token split by NUL": gh[:20].encode() + b"\0" + gh[20:].encode() + b"\n", "placeholder only": b"\0" + example.encode() + b"\n",
                  "placeholder and real": b"\0" + example.encode() + b"\n" + real.encode() + b"\n", "nothing": b"\0\0\0\n",
                  "every provider": b"\0" + lines(*SECRET_LINES.values())}
        for name, data in corpus.items():
            with self.subTest(name):
                h = context(self, data, cfg=support.make_config(TRANSIT_FIXES="D-014"))
                result = check_known_credentials(h.ctx)
                self.assertEqual((result.providers, result.jwt), self.decide(data))


# ---------------------------------------------------------------------------------------------------------------------------
class DataAndReportFileTests(unittest.TestCase):
    """``data=`` is a derived text (a jar's entries); ``report_file=`` is where the findings land."""

    def test_data_replaces_the_file_and_the_report_file_names_the_archive(self):
        h = context(self, b"harmless\n", rel="lib.jar")
        archive = h.ctx.path
        view_text = lines(SECRET_LINES["github_token"], JWT_LINE)
        result = check_known_credentials(h.ctx, data=view_text, report_file=archive)
        self.assertEqual(result, CredentialResult(True, ("github_token",), True))
        self.assertEqual(h.messages(archive), [("FAIL", FAIL_PREFIX + "github_token"), ("WARN", credentials.JWT_MESSAGE)])

    def test_report_file_other_than_the_context_file(self):
        h = context(self, b"harmless\n", rel="view.txt")
        other = h.repo.recorded("archive.jar")
        check_known_credentials(h.ctx, data=lines(SECRET_LINES["gitlab_pat"]), report_file=other)
        self.assertEqual(h.messages(other), [("FAIL", FAIL_PREFIX + "gitlab_pat")])
        self.assertEqual(h.messages(h.ctx.path), [])                   # nothing landed on the file that was searched

    def test_without_data_the_files_own_bytes_are_searched(self):
        h = context(self, lines(SECRET_LINES["npm_token"]))
        self.assertEqual(check_known_credentials(h.ctx).providers, ("npm_token",))
        self.assertEqual(h.messages(), [("FAIL", FAIL_PREFIX + "npm_token")])

    def test_data_that_is_empty_is_searched_not_replaced_by_the_file(self):
        h = context(self, lines(SECRET_LINES["npm_token"]))
        self.assertEqual(check_known_credentials(h.ctx, data=b""), CredentialResult(False, (), False))

    def test_a_derived_text_with_a_long_line_is_searched_linearly(self):
        h = context(self, b"harmless\n")
        data = b"x " * 100_000 + b"\n" + lines(SECRET_LINES["github_token"])
        self.assertEqual(check_known_credentials(h.ctx, data=data).providers, ("github_token",))


# ---------------------------------------------------------------------------------------------------------------------------
class VerdictSemanticsTests(unittest.TestCase):
    def test_failed_is_true_when_the_allowlist_turned_the_fail_into_a_warning(self):
        """bash ``hit=0`` follows ``record_fail`` whatever it did with the finding (the scanner's ``failed`` must stay true)."""
        h = context(self, lines(SECRET_LINES["github_token"]), allowlist=Allowlist({("CWE-798", "a.txt"): "test fixture"}))
        result = check_known_credentials(h.ctx)
        self.assertTrue(result.failed)
        self.assertEqual(result.providers, ("github_token",))
        self.assertEqual(h.status(), "WARN")
        self.assertEqual(h.verdict.verdict, "PASS")

    def test_failed_is_true_when_the_threshold_turned_the_fail_into_a_warning(self):
        h = context(self, lines(SECRET_LINES["github_token"]), threshold=4, min_severity="critical")
        self.assertTrue(check_known_credentials(h.ctx).failed)
        self.assertEqual(h.status(), "WARN")

    def test_the_message_is_the_bash_message_and_the_severity_is_derived(self):
        h = context(self, lines(SECRET_LINES["github_token"]), verdict="fake")
        check_known_credentials(h.ctx)
        self.assertEqual(h.verdict.log, [("fail", h.ctx.path, FAIL_PREFIX + "github_token", None, True)])

    def test_the_jwt_warning_goes_through_record_warn(self):
        h = context(self, lines(JWT_LINE), verdict="fake")
        check_known_credentials(h.ctx)
        self.assertEqual(h.verdict.log, [("warn", h.ctx.path, credentials.JWT_MESSAGE)])

    def test_the_matched_text_is_never_printed_or_stored(self):
        h = context(self, lines(SECRET_LINES["github_token"], SECRET_LINES["aws_secret_access_key"], JWT_LINE))
        check_known_credentials(h.ctx)
        everything = h.buffers.stdout + h.buffers.stderr + repr(h.snapshot())
        for secret in ("oKFEOeVI2WdxcX4L8y" + "aUEcp4bWTkt2HGVHQx", "toB5aoVsS8hhss6inCQm" + "w31l26fqXAhjVmMyamjX", "eyJlCIxr89Lcsp"):
            self.assertNotIn(secret, everything)

    def test_it_honours_the_file_deadline(self):
        h = context(self, lines(SECRET_LINES["github_token"]), deadline=time.monotonic() - 1.0)
        with self.assertRaises(ScanBudgetExceeded):
            check_known_credentials(h.ctx)
        self.assertEqual(h.messages(), [])


# ---------------------------------------------------------------------------------------------------------------------------
class LongLineTests(unittest.TestCase):
    """D-030: a matching line longer than ``long_line_bytes`` is reported WITHOUT the placeholder exclusion (``rx.only_matching`` has no
    budget, so it is never run on such a line); fail closed."""

    def limit(self) -> int:
        return support.make_config().limits.long_line_bytes

    def test_a_placeholder_on_a_long_line_still_fails(self):
        example = j("AKIAIOSFODNN7", "EXAMPLE")
        short = b"key = " + example.encode() + b"\n"
        self.assertFalse(check_known_credentials(context(self, short).ctx).failed)             # excluded on a short line
        long_line = b"# " + b"pad " * (self.limit() // 4 + 100) + example.encode() + b"\n"
        self.assertGreater(len(long_line), self.limit())
        h = context(self, long_line)
        result = check_known_credentials(h.ctx)
        self.assertEqual(result.providers, ("aws_access_key_id",))
        self.assertEqual(h.messages(), [("FAIL", FAIL_PREFIX + "aws_access_key_id")])

    def test_every_placeholder_kind_on_a_long_line(self):
        for name, token in (("x run", j("ghp_", "x" * 36)), ("one letter", j("ghp_", "B" * 36)),
                            ("documentation token", j("ghp_16C7e42F", "292c6912E7710c838347Ae178B4a"))):
            with self.subTest(name):
                data = b"pad " * (self.limit() // 4 + 100) + b" " + token.encode() + b"\n"
                self.assertEqual(check_known_credentials(context(self, data).ctx).providers, ("github_token",))

    def test_the_boundary_is_the_line_length(self):
        """A line of exactly ``long_line_bytes`` is still tested with the exclusion; one byte more is not."""
        limit = self.limit()
        token = j("ghp_", "x" * 36).encode()
        prefix = b"a="
        for extra, expected in ((0, False), (1, True)):
            line = b"-" * (limit + extra - len(prefix) - len(token)) + prefix + token
            self.assertEqual(len(line), limit + extra)
            with self.subTest(extra=extra):
                self.assertEqual(check_known_credentials(context(self, line + b"\n").ctx).failed, expected)

    def test_a_long_line_next_to_short_ones(self):
        data = b"x" * (self.limit() + 50) + b"\n" + lines(j("ghp_", "x" * 36), SECRET_LINES["gitlab_pat"])
        result = check_known_credentials(context(self, data).ctx)
        self.assertEqual(result.providers, ("gitlab_pat",))                  # the placeholder is on a short line: excluded

    def test_cost_on_a_long_line_with_many_tokens(self):
        token = j("ghp_", "x" * 36).encode()
        data = (token + b" ") * 10_000 + b"\n"
        started = time.perf_counter()
        self.assertTrue(check_known_credentials(context(self, data).ctx).failed)
        self.assertLess(time.perf_counter() - started, 3.0)


HOSTILE_LINES = {
    "curl": (b"curl x " * 100_000)[:600_000],
    "a": b"a" * 600_000,
    "akia": b"AKIA" * 150_000,
    "ghp": b"ghp_" * 150_000,
    "sk": b"sk-" * 200_000,
    "base64": b"A1b2" * 150_000,
    "eyJ": (b"eyJ" + b"a" * 20 + b".") * 25_000,
    "aws secret": b"aws_secret_access_key = " * 25_000,
    "dashes": b"-" * 600_000,
}


class HostileLineTests(unittest.TestCase):
    """S12 / R-18: the alternation, each provider and the JWT are registered ``Matcher``s, and a 600 KB line costs each of them well under a second."""

    LIMIT_S = 1.0

    def test_every_matcher_finishes_on_every_hostile_line(self):
        h = context(self, b"x\n")
        matchers = [credentials.ALTERNATION, credentials.JWT, *credentials.PROVIDER_MATCHERS.values()]
        worst = 0.0
        for matcher in matchers:
            for label, line in HOSTILE_LINES.items():
                started = time.perf_counter()
                found = h.ctx.search(matcher.match, data=line)
                took = time.perf_counter() - started
                worst = max(worst, took)
                self.assertLess(took, self.LIMIT_S, "%s on the %s line took %.2f s (found: %s)" % (matcher.id, label, took, found))

    def test_the_whole_check_on_a_hostile_file(self):
        for label, line in HOSTILE_LINES.items():
            with self.subTest(label):
                h = context(self, line + b"\n")
                started = time.perf_counter()
                result = check_known_credentials(h.ctx)
                self.assertLess(time.perf_counter() - started, 3.0)
                self.assertFalse(result.failed)

    def test_a_hostile_line_followed_by_a_token_is_still_found(self):
        h = context(self, HOSTILE_LINES["curl"] + b"\n" + lines(SECRET_LINES["github_token"]))
        self.assertEqual(check_known_credentials(h.ctx).providers, ("github_token",))


# ---------------------------------------------------------------------------------------------------------------------------
@unittest.skipUnless(HAVE_GNU_GREP, "GNU grep is the oracle")
class OracleTests(unittest.TestCase):
    """The decision equals the one of ``_known_cred_check`` run with the real grep, on every shape the rule has met."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.oracle = GrepOracle()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.oracle.close()

    def corpus(self) -> "dict[str, bytes]":
        real = SECRET_LINES["aws_access_key_id"].partition("= ")[2]
        example = j("AKIAIOSFODNN7", "EXAMPLE")
        gh = SECRET_LINES["github_token"].partition("=")[2]
        cases: "dict[str, bytes]" = {}
        for name, line in SECRET_LINES.items():
            cases["provider " + name] = lines(line)
        for name, line in NEAR_MISSES.items():
            cases["near " + name] = lines(line)
        cases["jwt"] = lines(JWT_LINE)
        cases["jwt and provider"] = lines(JWT_LINE, SECRET_LINES["stripe_live_key"])
        cases["every provider"] = lines(*SECRET_LINES.values())
        cases["empty"] = b""
        cases["no final newline"] = SECRET_LINES["github_token"].encode()
        cases["crlf"] = lines(SECRET_LINES["github_token"], "x", sep="\r\n")
        cases["token line start"] = lines(gh)
        cases["quoted"] = lines('x = "%s"' % gh)
        cases["embedded after letter"] = lines("a" + gh)
        cases["github token plus a digit (variable length)"] = lines(gh + "7")
        cases["example and real, two lines"] = lines(example, real)
        cases["example and real, one line two spaces"] = ("%s  %s\n" % (example, real)).encode()
        cases["example and real, one line one space"] = ("%s %s\n" % (example, real)).encode()
        cases["real and example, one line one space"] = ("%s %s\n" % (real, example)).encode()
        cases["the word EXAMPLE around a real key"] = ("# EXAMPLE: key is %s\n" % real).encode()
        cases["two real tokens one space"] = ("%s %s\n" % (real, j("AKIA", "Z961ELEFI1I64MFQ"))).encode()
        cases["two real tokens two spaces"] = ("%s  %s\n" % (real, j("AKIA", "Z961ELEFI1I64MFQ"))).encode()
        cases["placeholder x run"] = lines(j("ghp_", "x" * 36))
        cases["mixed-case repeated letter"] = lines(j("glpat-", "kKkKkKkKkK", "Qw3rTy5uIo7pLk9Jh"))
        cases["NUL at the start"] = b"\0" + lines(gh)
        cases["NUL in the middle"] = lines(gh)[:10] + b"\0" + lines(gh)[10:]
        cases["NUL at the end"] = lines(gh) + b"\0"
        cases["tab and cr before token"] = ("a\t\r%s\r\n" % gh).encode()
        cases["high bytes around"] = b"\xff\xfe" + gh.encode() + b"\xc3\xa9\n"
        cases["long run of word characters"] = b"A" * 5000 + gh.encode() + b"\n"
        return cases

    def test_the_decision_equals_greps_on_the_corpus(self):
        for name, data in self.corpus().items():
            with self.subTest(name):
                expected = self.oracle.decide(data)
                h = context(self, data)
                result = check_known_credentials(h.ctx)
                self.assertEqual((result.providers, result.jwt, result.failed), (expected[0], expected[1], bool(expected[0])), name)
                self.assertEqual([m for _k, m in h.messages()],
                                 [FAIL_PREFIX + n for n in expected[0]] + ([credentials.JWT_MESSAGE] if expected[1] else []))

    def test_the_exclusion_equals_greps_on_matched_texts(self):
        """The placeholder exclusion, string by string, against ``grep -viE`` (it has a back-reference: no linear matcher, and ``rx`` is the translator)."""
        texts = [b"EXAMPLE", b"example", b"SAMPLE", b"dummy", b"PlaceHolder", b"your", b"REDACTED", b"fake", b"changeme", b"xxxxxx", b"xxxxx", b"XXXXXX",
                 b"0000000000", b"000000000", b"***", b"**", b"...", b"..", b"1234567890", b"123456789", b"abcdefgh", b"abcdefg", b"qqqqqqqqqq",
                 b"qqqqqqqqq", b"QqQqQqQqQq", j("ghp_16C7e42F", "292c6912E7710c838347Ae178B4a").encode(),
                 j("GHP_16C7E42F", "292C6912E7710C838347AE178B4A").encode(), j("ghp_16C7e42F", "292c6912E7710c838347Ae178B4b").encode(),
                 b"Qw3rTy5uIo7pLk9Jh2Gf", b"prefix-EXAMPLE-suffix", b"a" * 9 + b"b", b""]
        compiled = rx.ere_to_py(credentials.EXCLUSION, True)
        for text in texts:
            with self.subTest(text):
                grep_excludes = run_grep(["-iqE", "-e", credentials.EXCLUSION], stdin=text + b"\n").returncode == 0
                self.assertEqual(compiled.search(text) is not None, grep_excludes)

    def test_a_long_line_is_the_one_documented_difference(self):
        """D-030: grep applies the exclusion to a long line too; the engine does not (fail closed). Everything else above is equal."""
        example = j("AKIAIOSFODNN7", "EXAMPLE")
        data = b"pad " * 5000 + example.encode() + b"\n"
        self.assertEqual(self.oracle.decide(data), ((), False))
        self.assertEqual(check_known_credentials(context(self, data).ctx).providers, ("aws_access_key_id",))


if __name__ == "__main__":
    unittest.main()
