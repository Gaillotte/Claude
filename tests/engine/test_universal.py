"""Tests of transit/scanners/universal.py (WP-08): the universal layer (Layer 4) that runs on every file before its own scanner.

    python3 -I -m unittest discover -s tests/engine -p "test_universal.py"

``universal.scan`` is exercised over a REAL ``ScanContext`` (``tests/engine/support.make_context``: real ``Verdict``, ``FileView`` and rule
machinery). The oracle is REAL GNU ``grep`` run the way ``scan_universal_patterns`` runs it (``grep -qE`` / ``-qiE`` per row, the
``grep -aE -A5 | tr | grep -aE`` pipeline of the private-key rule, the ``_known_cred_check`` pipeline); the patterns it uses are read from
tests/conformance/patterns.json and the order of the messages from ``scan_pipeline.sh``, never from the module under test.

The one deliberate difference from bash on a file with a NUL byte: a table row is evaluated as ``grep -a`` (``Match(binary="text")``, E8)
while bash's ``grep_check`` has no ``-a``, so a match that spans a NUL byte is found here and not by bash (never the other way round).
``OracleTests`` states it: on a file without a NUL byte the two are equal, on a file with one bash's findings are a subset of ours.

A token-shaped credential or PEM private key is NEVER written contiguously in this file: each is assembled at run time from separate
string literals (``tests/run_tests.sh`` does the same).
"""
from __future__ import annotations

import ast
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
from transit import rx  # noqa: E402
from transit.findings import Allowlist  # noqa: E402
from transit.rules import Match, Matcher, RuleSet, ScanBudgetExceeded  # noqa: E402
from transit.scanners import credentials, guard, universal  # noqa: E402

UNIVERSAL_MODULE = ROOT / "transit" / "scanners" / "universal.py"
SCRIPT = ROOT / "scan_pipeline.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "rules"
GREP = shutil.which("grep")

KEY_MESSAGE = "CWE-321:hardcoded_private_key"
#: The ten rows of the table (steps 1, 4, 5 and 6), in bash order: ``(message, outcome, helper)``.
ROWS = (
    ("CWE-798:hardcoded_credential", "fail", "grep_check"),
    ("crypto:public_certificate_embedded", "warn", "grep_check"),
    ("CWE-22:path_traversal_encoded", "fail", "grep_check_i"),
    ("CWE-22:path_traversal_to_sensitive_path", "fail", "grep_check_i"),
    ("CWE-22:path_traversal_composed_with_input", "fail", "grep_check_i"),
    ("CWE-918:potential_SSRF_unvalidated_URL", "warn", "grep_check"),
    ("CWE-327:weak_crypto_algorithm", "warn", "grep_check"),
    ("CWE-338:weak_PRNG_for_security", "warn", "grep_check"),
    ("OWASP-A02:debug_or_backdoor_comment", "warn", "grep_check"),
    ("OWASP-A09:logging_suppressed", "warn", "grep_check"),
)
ROW_MESSAGES = tuple(message for message, _o, _h in ROWS)


def j(*parts: str) -> str:
    return "".join(parts)


def _gnu_grep() -> bool:
    if GREP is None:
        return False
    try:
        out = subprocess.run([GREP, "--version"], capture_output=True, timeout=10, env={"LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return b"GNU grep" in out


HAVE_GNU_GREP = _gnu_grep()


def run_grep(args: "list[str]", *, stdin: "bytes | None" = None) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run([GREP or "grep"] + args, input=stdin, capture_output=True, timeout=120, env={"LC_ALL": "C"})


def inventory() -> "list[dict]":
    rows = json.loads((ROOT / "tests" / "conformance" / "patterns.json").read_text(encoding="utf-8"))
    return sorted((r for r in rows if r.get("enclosing_function") == "scan_universal_patterns"), key=lambda r: r["line"])


def table_inventory() -> "list[dict]":
    """The ten ``grep_check`` / ``grep_check_i`` entries of ``scan_universal_patterns``, in file order."""
    return [r for r in inventory() if r["helper"] in ("grep_check", "grep_check_i")]


def key_inventory() -> dict:
    return [r for r in inventory() if r.get("shape") == "pipe2"][0]


def bash_message_order() -> "list[str]":
    """Every message ``scan_universal_patterns`` can record, in the order the function reads, with ``_known_cred_check`` expanded
    (its providers in table order, then the JWT warning): read from ``scan_pipeline.sh``."""
    text = SCRIPT.read_text(encoding="utf-8")
    body = text[text.index("scan_universal_patterns() {"):]
    body = body[:body.index("\n}\n")]
    order: "list[str]" = []
    for found in re.finditer(r'record_(?:fail|warn) "\$f" "([^"]+)"|_known_cred_check "\$f" "\$f"', body):
        if found.group(1):
            order.append(found.group(1))
        else:
            order.extend("CWE-798:known_credential_format_" + name for name in credentials.PROVIDER_NAMES)
            order.append(credentials.JWT_MESSAGE)
    return order


def context(test: unittest.TestCase, data: "bytes | str", rel: str = "a.txt", **kwargs) -> support.Harness:
    return support.make_context(test, rel, data, **kwargs)


def lines(*parts: str, sep: str = "\n") -> bytes:
    return (sep.join(parts) + sep).encode("utf-8")


def recorded(h: support.Harness) -> "list[tuple[str, str]]":
    return h.messages()


def run_scan(test: unittest.TestCase, data: "bytes | str", **kwargs) -> "tuple[support.Harness, list[tuple[str, str]]]":
    h = context(test, data, **kwargs)
    result = universal.scan(h.ctx)
    test.assertIs(result, True)
    return h, h.messages()


def messages_of(h: support.Harness) -> "list[str]":
    return [message for _kind, message in h.messages()]


# ---- private keys, built at run time -----------------------------------------------------------------------------------
def header(kind: str = "RSA ") -> str:
    return j("-----BEGIN ", kind, "PRIVATE KEY-----")


def footer(kind: str = "RSA ") -> str:
    return j("-----END ", kind, "PRIVATE KEY-----")


def body(n: int = 64) -> str:
    return ("MIIEowIBAAKCAQEA" * 16)[:n]


def pem(kind: str = "RSA ", body_lines: int = 2, width: int = 64) -> str:
    return "\n".join([header(kind)] + [body(width)] * body_lines + [footer(kind)]) + "\n"


# ---------------------------------------------------------------------------------------------------------------------------
class TableTests(unittest.TestCase):
    """The table is the bash table: rows, messages, order, patterns, flags."""

    def test_the_table_is_a_registered_ruleset_of_ten_rows(self):
        self.assertIsInstance(universal.RULES, RuleSet)
        self.assertEqual(len(universal.RULES.rules), len(ROWS))

    def test_ids_are_universal_nn_slug_and_sequential(self):
        ids = [spec.id for spec in universal.RULES.rules]
        for position, rule_id in enumerate(ids, 1):
            self.assertRegex(rule_id, r"^universal/%02d-[a-z0-9]+(-[a-z0-9]+)*$" % position)
        self.assertEqual(len(set(ids)), len(ids))

    def test_messages_outcomes_and_order(self):
        self.assertEqual([(s.message, s.outcome) for s in universal.RULES.rules], [(m, o) for m, o, _h in ROWS])

    def test_every_message_occurs_in_scan_pipeline_sh(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for message in ROW_MESSAGES + (KEY_MESSAGE,):
            self.assertIn('"%s"' % message, text, message)

    def test_every_row_is_one_match_taken_from_the_inventory(self):
        entries = table_inventory()
        self.assertEqual(len(entries), len(ROWS))
        for spec, entry, (_m, _o, helper) in zip(universal.RULES.rules, entries, ROWS):
            with self.subTest(spec.id):
                self.assertEqual(entry["helper"], helper)                         # the order of rows is the order of the grep calls
                self.assertIsInstance(spec.cond, Match)
                self.assertEqual(spec.cond.pattern, entry["pattern"])
                self.assertEqual(spec.cond.ci, helper == "grep_check_i")
                self.assertEqual((spec.cond.mode, spec.cond.binary, spec.cond.excl), ("line", "text", None))

    def test_the_messages_follow_the_calls_of_the_bash_function(self):
        calls = [m for m in bash_message_order() if m in ROW_MESSAGES]
        self.assertEqual(calls, list(ROW_MESSAGES))

    def test_rows_leave_the_severity_to_the_classifier_and_name_their_source(self):
        for spec in universal.RULES.rules:
            self.assertIsNone(spec.severity, spec.id)
            self.assertEqual(spec.source, "scan_universal_patterns", spec.id)
            self.assertIsNone(spec.applies_to, spec.id)

    def test_every_leaf_is_registered_with_rx(self):
        by_id = {rule.id: rule for rule in rx.registered()}
        for spec in universal.RULES.rules:
            self.assertIn(spec.id, by_id)
            self.assertEqual(by_id[spec.id].pattern, spec.cond.pattern)
            self.assertEqual(by_id[spec.id].mode, "line_i" if spec.cond.ci else "line")

    def test_the_key_matchers(self):
        entry = key_inventory()
        self.assertEqual(universal.PRIVATE_KEY_HEADER, entry["pattern"])
        self.assertEqual(universal.PRIVATE_KEY_WITH_BODY, entry["excl"])
        for matcher, rule_id, pattern in ((universal.KEY_HEADER, "universal/key-header", entry["pattern"]),
                                          (universal.KEY_WITH_BODY, "universal/key-body", entry["excl"])):
            self.assertIsInstance(matcher, Matcher)
            self.assertEqual(matcher.id, rule_id)
            self.assertEqual((matcher.match.pattern, matcher.match.mode, matcher.match.binary, matcher.match.ci),
                             (pattern, "line", "text", False))      # bash reads the key as text: ``grep -aE``
            self.assertIn(rule_id, [rule.id for rule in rx.registered()])

    def test_importing_the_module_is_silent_and_registers_everything(self):
        code = ("import sys\nfrom transit.scanners import universal\n"
                "assert universal.RULES is not None and universal.KEY_HEADER is not None and universal.KEY_WITH_BODY is not None\n")
        run = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r)\n%s" % (str(ROOT), code)],
                             capture_output=True, timeout=60)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b"", b""), run.stderr)

    def test_the_module_is_not_a_registered_scanner(self):
        self.assertFalse(hasattr(universal, "SCANNERS"))                          # layers calls it through guard("universal", ...)


class SourceDisciplineTests(unittest.TestCase):
    """Design 9 and 3.2, checked on this module's source as well as by tests/engine/test_lints.py."""

    def tree(self) -> ast.Module:
        return ast.parse(UNIVERSAL_MODULE.read_text(encoding="utf-8"))

    def test_no_pattern_is_built_inside_a_function(self):
        offenders = []
        for node in ast.walk(self.tree()):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call):
                        func = inner.func
                        name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
                        if name in ("Match", "Matcher", "RuleSet", "ere_to_py", "ere_to_py_source", "rule", "compile", "parse_ere"):
                            offenders.append((node.name, name, inner.lineno))
        self.assertEqual(offenders, [])

    def test_the_buffer_is_never_split_or_given_to_after_context(self):
        text = UNIVERSAL_MODULE.read_text(encoding="utf-8")
        calls = [n for n in ast.walk(self.tree()) if isinstance(n, ast.Attribute)]
        used = {n.attr for n in calls}
        for forbidden in ("after_context", "lines_over", "splitlines", "readlines"):
            self.assertNotIn(forbidden, used, forbidden)
        for needle in ('split(b"\\n")', "split(b'\\n')", "import re\n", "from re "):
            self.assertNotIn(needle, text, needle)

    def test_it_never_imports_verdict_or_console(self):
        for node in ast.walk(self.tree()):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for name in names:
                self.assertNotIn(name, ("transit.verdict", "transit.console", "transit.layers", "transit.pipeline", "transit.report"))

    def test_the_message_of_a_scanner_never_holds_repository_text(self):
        """Every message the module can record is a literal of the table or of this file: nothing is formatted with a name or a line."""
        source = UNIVERSAL_MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"record_(fail|warn)\([^)]*(%|\.format|f\")")


# ---------------------------------------------------------------------------------------------------------------------------
#: ``(positive lines, near-miss lines)`` for every row, as text. A positive must fire its row; a near miss must not.
ROW_CASES = {
    "CWE-798:hardcoded_credential": (
        ['password = "hunter2supersecret"', 'db_secret = "s3cr3t-value-123"', "api_key = 'sunflower-token-99'", 'auth_token: "abcd1234"',
         'password="sup3rs3cret"', "passwd = 'zzzzzz'", 'x.access_token = "abcd"', 'apikey : "abcdefgh"', 'pwd = "hunter22"'],
        ['password = os.environ["APP_PW"]', 'password = ""', 'password = "${DB_PASSWORD}"', 'secret = "{{ vault_secret }}"', 'password = "abc"',
         'DB_PASSWORD = "hunter2supersecret"', 'API_KEY = "abcdefgh1234"', "password = get_password(session)", 'password = "has space"',
         "password: unquoted_value"]),
    "crypto:public_certificate_embedded": (
        ["-----BEGIN CERTIFICATE-----", "x = '-----BEGIN CERTIFICATE-----'"],
        ["-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE REQUEST-----", "BEGIN CERTIFICATE", "----BEGIN CERTIFICATE-----"]),
    "CWE-22:path_traversal_encoded": (
        ["GET /download?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "GET /d?f=..%2fid_rsa", "x=%2E%2E/y", "%252e%252e", "..%5cwindows", "a%2f..b", "%5c..",
         "..%2F"],
        ["100%2d", "a%2fb", "a..b", "..", "%2e", "%2", "%25 2e%2e"]),
    "CWE-22:path_traversal_to_sensitive_path": (
        ['path = "../../../../etc/passwd"', 'cp = "..\\\\..\\\\windows\\\\system32\\\\cmd.exe"', 'shutil.copy(src, "../../.ssh/authorized_keys")',
         "../.aws/credentials", "../../proc/self/environ", "../../ETC/SHADOW", "..\\id_rsa", "../x/id_rsa.pub"],
        ["../include", "../../etc/hosts", "/etc/passwd", "cat /etc/shadow", "../ passwd", "..", "../../", "..x/etc/passwd"]),
    "CWE-22:path_traversal_composed_with_input": (
        ['open(base_dir + "../" + user_file)', 'target = f"{upload_dir}/../{filename}"', "include($_GET['page'] . '../config.php');",
         "x = `${root}/../${name}`", 'p = "x" + "../" + y', "f'../{name}'", "q = `../${x}`"],
        ['set(DIR "${resolved_dir}/../lib")', "from ..models import User", 'print("..." + x)', 'a = "../"', "cd .. && make",
         'include("${CMAKE_CURRENT_SOURCE_DIR}/../common.cmake")', "sys.path.insert(0, os.path.dirname(__file__) + \"/..\")"]),
    "CWE-918:potential_SSRF_unvalidated_URL": (
        ["requests.get(url)", "axios(target)", "fetch(endpoint)", "urllib.request (target)", "http.get (url, cb)", "fetch( 'x', url )"],
        ['requests.get("https://api.example.com")', "fetch(urls)", "requests.get(session_url_value)", "fetch (x) // url", "post(url)"]),
    "CWE-327:weak_crypto_algorithm": (
        ["hashlib.md5(x)", "h = sha1(x)", "des", "use rc4 here", "blowfish", "md5"],
        ["describe(x)", "md5sum f", "MD5", "DES", "SHA256", "sha1sum", "undes", "des_x", "x-md5y"]),
    "CWE-338:weak_PRNG_for_security": (
        ["Math.random()", "n = random.random()", "mt_rand(1, 2)", "Math.random"],
        ["x = rand();", "secrets.randbelow(5)", "random.choice(xs)", "operand()", "Math.randomize()"]),
    "OWASP-A02:debug_or_backdoor_comment": (
        ["# TODO: remove before release", "FIXME: auth missing", "backdoor", "def test_password(): pass", "debug the token", "hardcoded api key"],
        ["todo: remove", "TODO: add tests", "fixme auth", "FIXME: later", "Backdoor", "test passwor d", "debug_tok"]),
    "OWASP-A09:logging_suppressed": (
        ["logging.disable(logging.CRITICAL)", "log_level = NOTSET", "logger.setLevel(CRITICAL)  # security", "disableStdoutLogger()"],
        ["logging.basicConfig()", "log_level = DEBUG", "logging.getLogger(x)", "setLevel(CRITICAL)", "loggingXdisable"]),
}


class RowTests(unittest.TestCase):
    """One positive and one near-miss fixture per rule, through ``scan`` (a real context and verdict)."""

    def test_the_cases_cover_every_row(self):
        self.assertEqual(sorted(ROW_CASES), sorted(ROW_MESSAGES))

    def test_a_positive_fires_its_row(self):
        for message, (positives, _near) in ROW_CASES.items():
            for text in positives:
                with self.subTest(message=message, text=text):
                    h, got = run_scan(self, lines(text))
                    self.assertIn(message, [m for _k, m in got])
                    outcome = dict((m, o) for m, o, _h in ROWS)[message]
                    self.assertIn(("FAIL" if outcome == "fail" else "WARN", message), got)

    def test_a_near_miss_does_not_fire_its_row(self):
        for message, (_pos, near) in ROW_CASES.items():
            for text in near:
                with self.subTest(message=message, text=text):
                    h, got = run_scan(self, lines(text))
                    self.assertNotIn(message, [m for _k, m in got])

    def test_a_clean_file_records_nothing_and_never_a_pass(self):
        h, got = run_scan(self, lines("def add(a, b):", "    return a + b"))
        self.assertEqual(got, [])
        self.assertIsNone(h.status())
        self.assertEqual(h.verdict.events, 0)                           # "do not set PASS here - handled by the per-type scanner"

    def test_it_never_records_a_pass_even_when_it_finds_something(self):
        h = context(self, lines('password = "hunter2supersecret"'), verdict="fake")
        universal.scan(h.ctx)
        self.assertEqual([e[0] for e in h.verdict.log], ["fail"])
        self.assertEqual(h.verdict.log[0][1:], (h.ctx.path, "CWE-798:hardcoded_credential", None, True))

    def test_the_credential_value_class_is_not_a_backslash_s(self):
        """The bracket bug of CLAUDE.md: ``[^"\\s]`` is the characters ``\\`` and ``s``. A value with an "s" in front must still match."""
        for value in ("sup3rs3cret", "ssss", "s3cr3t-value-123", "sunflower"):
            with self.subTest(value):
                _h, got = run_scan(self, lines('password = "%s"' % value))
                self.assertIn(("FAIL", "CWE-798:hardcoded_credential"), got)

    def test_the_documented_weak_spots_of_the_bash_rules_are_copied(self):
        """CLAUDE.md "Still weak": upper-case names are not matched, and ``rand()`` followed by ``;`` is never found (``\\b`` next to ``)``)."""
        for text in ('DB_PASSWORD = "hunter2supersecret"', 'SECRET_KEY = "hunter2supersecret"', "x = rand();", "x = rand() ;"):
            with self.subTest(text):
                _h, got = run_scan(self, lines(text))
                self.assertEqual(got, [])

    def test_the_traversal_rules_are_case_insensitive_and_the_others_are_not(self):
        _h, got = run_scan(self, lines("GET /d?f=%2E%2E%2F"))
        self.assertIn(("FAIL", "CWE-22:path_traversal_encoded"), got)
        _h, got = run_scan(self, lines("PASSWORD = 'abcdefgh'", "TODO REMOVE", "MD5", "MATH.RANDOM()"))
        self.assertEqual(got, [])

    def test_the_fixture_files_of_the_traversal_rules(self):
        h, got = run_scan(self, (FIXTURES / "traversal.txt").read_bytes(), rel="traversal.txt")
        self.assertEqual([m for _k, m in got if m.startswith("CWE-22")],
                         ["CWE-22:path_traversal_encoded", "CWE-22:path_traversal_to_sensitive_path", "CWE-22:path_traversal_composed_with_input"])
        h, got = run_scan(self, (FIXTURES / "safe_relative_paths.txt").read_bytes(), rel="safe_relative_paths.txt")
        self.assertEqual([m for _k, m in got if m.startswith("CWE-22")], [])

    def test_each_traversal_form_fires_only_its_own_row(self):
        for text, expected in (("%2e%2e%2fx", "path_traversal_encoded"), ("../../etc/passwd", "path_traversal_to_sensitive_path"),
                               ("open(a + '../' + b)", "path_traversal_composed_with_input")):
            with self.subTest(text):
                _h, got = run_scan(self, lines(text))
                self.assertEqual([m for _k, m in got if m.startswith("CWE-22")], ["CWE-22:" + expected])

    def test_the_hardcoded_fixture_files(self):
        _h, got = run_scan(self, (FIXTURES / "cred_s_values.py").read_bytes(), rel="cred_s_values.py")
        self.assertEqual(got, [("FAIL", "CWE-798:hardcoded_credential")])
        _h, got = run_scan(self, (FIXTURES / "cred_s_safe.py").read_bytes(), rel="cred_s_safe.py")
        self.assertEqual(got, [])


# ---------------------------------------------------------------------------------------------------------------------------
class PrivateKeyTests(unittest.TestCase):
    """CWE-321: a PEM header AND a base64 body within five lines. The F9 cases, the NUL cases of Layer K F4, and the boundaries."""

    def present(self, data: "bytes | str", **kwargs) -> bool:
        h = context(self, data, **kwargs)
        return universal.private_key_present(h.ctx)

    def test_header_with_a_body_line_is_a_key(self):
        for kind in ("", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED ", "PGP ", "RSA2 ", "A B "):
            with self.subTest(kind):
                self.assertTrue(self.present(pem(kind)))

    def test_the_header_and_the_body_on_one_line_as_a_json_string(self):
        text = '{"private_key": "%s\\n%s\\n%s\\n"}\n' % (header(""), body(64), footer(""))
        self.assertIn("\\n", text)
        self.assertTrue(self.present(text))

    def test_a_pgp_block_whose_armor_headers_push_the_body_down(self):
        text = "\n".join([j("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"), "Version: GnuPG v1", "Comment: fixture only, not a real key", "", body(64),
                          "=fixt", j("-----END PGP ", "PRIVATE KEY BLOCK-----")]) + "\n"
        self.assertTrue(self.present(text))

    def test_openssh_lines_of_seventy_characters(self):
        self.assertTrue(self.present(pem("OPENSSH ", 3, 70)))

    def test_fixture_files(self):
        for name, expected in (("private_key.txt", True), ("pgp_private.asc", True), ("service_account.json", True), ("safe_key_prose.txt", False)):
            with self.subTest(name):
                self.assertEqual(self.present((FIXTURES / name).read_bytes(), rel=name), expected)

    def test_a_header_alone_is_not_a_key(self):
        self.assertFalse(self.present(header("") + "\n"))
        self.assertFalse(self.present(header("") + "\n" + footer("") + "\n"))

    def test_a_file_type_signature_is_not_a_key(self):
        """shared-mime-info carries the header as a magic string, and npm's reference as a placeholder body."""
        self.assertFalse(self.present('<mime type="application/pgp-keys" magic="%s" />\n' % j("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----")))
        self.assertFalse(self.present('<match type="string" value="%s" offset="0"/>\n' % j("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----")))
        self.assertFalse(self.present('key="%s\\nXXXX\\nXXXX\\n%s"\n' % (header(""), footer(""))))

    def test_a_placeholder_body_is_not_a_key(self):
        self.assertFalse(self.present(pem("RSA ", 2, 16)))
        self.assertFalse(self.present("\n".join([header(), "XXXXXXXXXXXXXXXX", footer()]) + "\n"))

    def test_prose_about_a_key_is_not_a_key(self):
        self.assertFalse(self.present("Store the PRIVATE KEY in an HSM, never in the repo.\nBEGIN RSA is a header.\n"))

    def test_the_body_must_be_sixty_base64_characters(self):
        for width, expected in ((59, False), (60, True), (61, True), (200, True)):
            with self.subTest(width):
                self.assertEqual(self.present(pem("", 1, width)), expected)

    def test_a_body_made_of_other_characters_is_not_base64(self):
        self.assertFalse(self.present("\n".join([header(""), "-_" * 40, "!" * 80]) + "\n"))
        self.assertTrue(self.present("\n".join([header(""), "+/" * 40]) + "\n"))

    def test_two_hundred_characters_may_separate_the_header_from_the_body(self):
        """The pattern is ``header.{0,200}body``: 200 characters of anything in between, not 201 (the filler is not base64)."""
        for filler, expected in ((200, True), (201, False)):
            with self.subTest(filler):
                self.assertEqual(self.present(header("") + "-" * filler + body(64) + "\n"), expected)

    def test_the_window_is_the_header_line_and_five_more(self):
        for lines_between, expected in ((0, True), (3, True), (4, True), (5, False), (8, False)):
            text = "\n".join([header("")] + ["x"] * lines_between + [body(64)]) + "\n"
            with self.subTest(between=lines_between):
                self.assertEqual(self.present(text), expected, "the body is %d lines after the header" % (lines_between + 1))

    def test_the_body_on_the_fifth_line_after_is_inside_and_on_the_sixth_outside(self):
        inside = "\n".join([header(""), "1", "2", "3", "4", body(64)]) + "\n"
        outside = "\n".join([header(""), "1", "2", "3", "4", "5", body(64)]) + "\n"
        self.assertTrue(self.present(inside))
        self.assertFalse(self.present(outside))

    def test_a_key_is_found_wherever_it_sits_in_the_file(self):
        noise = "\n".join("line %d with some text" % i for i in range(3000)) + "\n"
        self.assertTrue(self.present(noise + pem("") + noise))
        self.assertTrue(self.present(pem("") + noise))
        self.assertTrue(self.present(noise + pem("").rstrip("\n")))             # no final newline

    def test_a_second_key_after_a_header_without_a_body(self):
        self.assertTrue(self.present(header("") + "\n" + "\n".join(["junk"] * 9) + "\n" + pem("EC ")))

    def test_two_overlapping_windows(self):
        self.assertTrue(self.present("\n".join([header(""), "a", header("EC "), "b", "c", "d", "e", body(64)]) + "\n"))

    def test_crlf_and_tab_are_folded_to_spaces(self):
        text = "\r\n".join([header(), body(64), body(64), footer()]) + "\r\n"
        self.assertTrue(self.present(text))
        self.assertTrue(self.present("\n".join([header(), "\t" + body(64), footer()]) + "\n"))
        self.assertTrue(self.present(header() + "\t\t" + body(64) + "\n"))
        self.assertTrue(self.present("\r".join([header(), body(64)])))

    def test_a_nul_byte_does_not_hide_a_key(self):
        """Layer K F4: ``grep -a`` on both sides, a NUL byte at the end, the start or the middle changes nothing."""
        plain = pem("RSA ").encode()
        nul_middle = b"\n".join(plain.split(b"\n")[:2]) + b"\n\0\n" + b"\n".join(plain.split(b"\n")[2:])
        for name, data in (("plain", plain), ("nul_end", plain + b"\0"), ("nul_start", b"\0" + plain), ("nul_middle", nul_middle),
                           ("nul between two keys", plain + b"\0\n" + plain)):
            with self.subTest(name):
                self.assertTrue(self.present(data))

    def test_a_nul_byte_does_not_make_a_placeholder_a_key(self):
        placeholder = pem("RSA ", 2, 16).encode()
        for name, data in (("placeholder", placeholder), ("placeholder and nul", placeholder + b"\0"),
                           ("prose and nul", b"store the PRIVATE KEY in an HSM\n\0\n")):
            with self.subTest(name):
                self.assertFalse(self.present(data))

    def test_binary_content_around_a_key(self):
        self.assertTrue(self.present(b"\xff\xfe\x00\x01" * 100 + pem("RSA ").encode() + b"\x80\x81" * 50))

    def test_the_derived_data_is_searched_instead_of_the_file(self):
        h = context(self, b"nothing to see\n")
        self.assertFalse(universal.private_key_present(h.ctx))
        self.assertTrue(universal.private_key_present(h.ctx, data=pem("RSA ").encode()))
        h2 = context(self, pem("RSA "))
        self.assertTrue(universal.private_key_present(h2.ctx))
        self.assertFalse(universal.private_key_present(h2.ctx, data=b"x\n"))
        self.assertFalse(universal.private_key_present(h2.ctx, data=b""))

    def test_a_derived_text_is_judged_per_string(self):
        """The jar scanner hands each string constant on its own: a header in one string and a body in the next are two texts, not a key."""
        h = context(self, b"x\n")
        self.assertFalse(universal.private_key_present(h.ctx, data=header("").encode()))
        self.assertFalse(universal.private_key_present(h.ctx, data=body(64).encode()))

    def test_it_records_nothing(self):
        h = context(self, pem("RSA "))
        self.assertTrue(universal.private_key_present(h.ctx))
        self.assertEqual(h.messages(), [])
        self.assertEqual(h.verdict.events, 0)

    def test_it_does_not_call_after_context_or_lines_over(self):
        def boom(*_a, **_k):
            raise AssertionError("rx.after_context / rx.lines_over must not be called (R-18, F12, F13)")
        with mock.patch.object(rx, "after_context", boom), mock.patch.object(rx, "lines_over", boom):
            self.assertTrue(self.present(pem("RSA ")))
            self.assertFalse(self.present(pem("RSA ", 2, 16)))

    def test_it_honours_the_file_deadline(self):
        h = context(self, pem("RSA "), deadline=time.monotonic() - 1.0)
        with self.assertRaises(ScanBudgetExceeded):
            universal.private_key_present(h.ctx)

    def test_the_deadline_is_checked_for_every_window(self):
        """A file of many header lines cannot outlast the deadline: the walk stops with ScanBudgetExceeded when it passes."""
        h = context(self, (header("") + "\n") * 50_000, deadline=time.monotonic() + 0.05)
        started = time.perf_counter()
        try:
            universal.private_key_present(h.ctx)
        except ScanBudgetExceeded:
            pass
        self.assertLess(time.perf_counter() - started, 10.0)


class PrivateKeyHostileTests(unittest.TestCase):
    """F13: ``rx.after_context`` took 6.7 s on a 281 KB line of ``PRIVATE KEY `` repeated; the windows from ``ctx.spans`` are linear."""

    def present(self, data: bytes) -> "tuple[bool, float]":
        h = context(self, data)
        started = time.perf_counter()
        result = universal.private_key_present(h.ctx)
        return result, time.perf_counter() - started

    def test_the_281_kb_line_of_private_key_repeated(self):
        line = b"-----BEGIN " + b"PRIVATE KEY " * 23_500 + b"x"
        self.assertGreaterEqual(len(line), 281_000)
        found, took = self.present(line + b"\n")
        self.assertFalse(found)
        self.assertLess(took, 1.0)

    def test_the_same_line_then_a_real_key_is_found(self):
        line = b"-----BEGIN " + b"PRIVATE KEY " * 23_500 + b"x"
        found, took = self.present(line + b"\n" + pem("RSA ").encode())
        self.assertTrue(found)
        self.assertLess(took, 1.0)

    def test_a_line_that_grows_linearly(self):
        for repeats in (3_900, 7_800, 23_500, 100_000):
            with self.subTest(repeats):
                found, took = self.present(b"-----BEGIN " + b"PRIVATE KEY " * repeats + b"x\n")
                self.assertFalse(found)
                self.assertLess(took, 1.0)

    def test_a_header_that_closes_on_a_very_long_line(self):
        long_line = header("").encode() + b" " * 100 + b"-" * 600_000
        found, took = self.present(long_line + b"\n")
        self.assertFalse(found)
        self.assertLess(took, 1.0)
        found, took = self.present(header("").encode() + body(64).encode() + b"-" * 600_000 + b"\n")
        self.assertTrue(found)
        self.assertLess(took, 1.0)

    def test_a_window_of_five_very_long_lines(self):
        lines_ = [header("").encode()] + [b"curl x " * 80_000] * 5
        found, took = self.present(b"\n".join(lines_) + b"\n")
        self.assertFalse(found)
        self.assertLess(took, 2.0)

    def test_many_header_lines(self):
        found, took = self.present((header("").encode() + b"\n") * 20_000)
        self.assertFalse(found)
        self.assertLess(took, 8.0)

    def test_a_long_run_of_base64_before_a_header(self):
        found, took = self.present(b"A" * 600_000 + header("").encode() + b"\n")
        self.assertFalse(found)
        self.assertLess(took, 1.0)

    def test_every_key_matcher_finishes_on_the_hostile_lines(self):
        h = context(self, b"x\n")
        hostile = {"curl": (b"curl x " * 100_000)[:600_000], "dashes": b"-" * 600_000, "begin": b"-----BEGIN " * 55_000,
                   "private key": b"PRIVATE KEY " * 50_000, "base64": b"A1b2" * 150_000, "mixed": (b"-----BEGIN PRIVATE KEY ") * 26_000}
        for matcher in (universal.KEY_HEADER, universal.KEY_WITH_BODY):
            for label, line in hostile.items():
                started = time.perf_counter()
                h.ctx.search(matcher.match, data=line)
                took = time.perf_counter() - started
                self.assertLess(took, 1.0, "%s on the %s line took %.2f s" % (matcher.id, label, took))


HOSTILE_LINES = {
    "curl": (b"curl x " * 100_000)[:600_000],
    "a": b"a" * 600_000,
    "password": b'password = "' * 50_000,
    "todo": b"TODO " * 120_000,
    "fixme": b"FIXME " * 100_000,
    "debug": b"debug " * 100_000,
    "dotdot": b"../" * 200_000,
    "ellipsis": b"... " * 150_000,
    "percent": b"%2e" * 200_000,
    "fstring": b"f'{x}" * 100_000,
    "backtick": b"`${x}" * 100_000,
    "requests": b"requests.get(" * 45_000,
    "logging": b"log_level " * 60_000,
    "setlevel": b"setLevel(CRITICAL) " * 30_000,
}


class HostileLineTests(unittest.TestCase):
    """S12 / R-18: every row and both key matchers finish a 600 KB line in well under a second; a whole file of it in a few."""

    LIMIT_S = 1.0

    def test_every_row_on_every_hostile_line(self):
        h = context(self, b"x\n")
        for spec in universal.RULES.rules:
            for label, line in HOSTILE_LINES.items():
                started = time.perf_counter()
                h.ctx.search(spec.cond, data=line)
                took = time.perf_counter() - started
                self.assertLess(took, self.LIMIT_S, "%s on the %s line took %.2f s" % (spec.id, label, took))

    def test_the_whole_scan_on_a_hostile_line(self):
        for label in ("curl", "todo", "dotdot", "password", "setlevel"):
            with self.subTest(label):
                h = context(self, HOSTILE_LINES[label] + b"\n")
                started = time.perf_counter()
                universal.scan(h.ctx)
                self.assertLess(time.perf_counter() - started, 6.0)

    def test_a_rule_still_fires_after_a_hostile_line(self):
        h = context(self, HOSTILE_LINES["curl"] + b"\n" + b'password = "hunter2supersecret"\n')
        universal.scan(h.ctx)
        self.assertIn(("FAIL", "CWE-798:hardcoded_credential"), h.messages())


# ---------------------------------------------------------------------------------------------------------------------------
def combined_file() -> bytes:
    """One file that trips every message of ``scan_universal_patterns`` except the other providers, in an order that is not bash's."""
    github = j("export GITHUB_TOKEN=", "ghp_", "oKFEOeVI2WdxcX4L8y", "aUEcp4bWTkt2HGVHQx")
    jwt = j("session = ", "eyJlCIxr89LcspvfiHbtwjH_j3Db0BtCH9sY", ".", "eyJFsvZc6Xjc3Gy4Orwd", "naWW-iTRnXvaZtm9eaygGWI", ".",
            "3r90T2kmsR95izWTG1E3s9nE_5jG_f34X5FPbxph9y5")
    text = [
        "logging.disable(logging.CRITICAL)", "# TODO: remove", "n = random.random()", "h = hashlib.md5(x)", "r = requests.get(url)",
        "open(base + '../' + u)", 'path = "../../../../etc/passwd"', "GET /x?f=%2e%2e%2fa", "-----BEGIN CERTIFICATE-----", jwt, github,
        pem("RSA ").rstrip("\n"), 'password = "hunter2supersecret"']
    return lines(*text)


class ScanTests(unittest.TestCase):
    """Steps 1 to 6 together: order, recording, NUL, allowlist, deadline."""

    def test_messages_come_in_the_order_of_the_bash_function(self):
        h, got = run_scan(self, combined_file())
        order = bash_message_order()
        names = [m for _k, m in got]
        self.assertEqual(names, [m for m in order if m in names])                  # bash order, whatever the order in the file
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names, [
            "CWE-798:hardcoded_credential", KEY_MESSAGE, "CWE-798:known_credential_format_github_token", credentials.JWT_MESSAGE,
            "crypto:public_certificate_embedded", "CWE-22:path_traversal_encoded", "CWE-22:path_traversal_to_sensitive_path",
            "CWE-22:path_traversal_composed_with_input", "CWE-918:potential_SSRF_unvalidated_URL", "CWE-327:weak_crypto_algorithm",
            "CWE-338:weak_PRNG_for_security", "OWASP-A02:debug_or_backdoor_comment", "OWASP-A09:logging_suppressed"])
        self.assertEqual([k for k, _m in got], ["FAIL", "FAIL", "FAIL", "WARN", "WARN", "FAIL", "FAIL", "FAIL", "WARN", "WARN", "WARN", "WARN", "WARN"])
        self.assertEqual(h.status(), "FAIL")

    def test_the_known_formats_sit_between_the_private_key_and_the_certificate(self):
        order = bash_message_order()
        self.assertLess(order.index("CWE-798:hardcoded_credential"), order.index(KEY_MESSAGE))
        self.assertLess(order.index(KEY_MESSAGE), order.index("CWE-798:known_credential_format_aws_access_key_id"))
        self.assertLess(order.index(credentials.JWT_MESSAGE), order.index("crypto:public_certificate_embedded"))

    def test_a_certificate_alone_is_a_warning(self):
        h, got = run_scan(self, (FIXTURES / "safe_key_prose.txt").read_bytes(), rel="safe_key_prose.txt")
        self.assertEqual(got, [("WARN", "crypto:public_certificate_embedded")])
        self.assertEqual(h.status(), "WARN")

    def test_the_private_key_fixtures(self):
        for name in ("private_key.txt", "pgp_private.asc", "service_account.json"):
            with self.subTest(name):
                _h, got = run_scan(self, (FIXTURES / name).read_bytes(), rel=name)
                self.assertIn(("FAIL", KEY_MESSAGE), got)

    def test_a_downloaded_token_is_found_by_the_formats(self):
        _h, got = run_scan(self, lines(j("export GITHUB_TOKEN=", "ghp_", "oKFEOeVI2WdxcX4L8y", "aUEcp4bWTkt2HGVHQx")))
        self.assertEqual(got, [("FAIL", "CWE-798:known_credential_format_github_token")])

    def test_a_nul_byte_silences_the_formats_but_not_the_grep_rules(self):
        """D-014 copied for the formats; the table rows and the key read the file as text (E8)."""
        token = j("export GITHUB_TOKEN=", "ghp_", "oKFEOeVI2WdxcX4L8y", "aUEcp4bWTkt2HGVHQx")
        data = b"\0" + lines(token, "hashlib.md5(x)", 'password = "hunter2supersecret"') + pem("RSA ").encode()
        _h, got = run_scan(self, data)
        names = [m for _k, m in got]
        self.assertEqual(names, ["CWE-798:hardcoded_credential", KEY_MESSAGE, "CWE-327:weak_crypto_algorithm"])

    def test_the_rules_see_a_match_that_spans_a_nul_byte(self):
        """Not what bash does (``grep_check`` has no ``-a`` and a NUL ends a line there), and the safe direction: a NUL byte must not hide a credential."""
        _h, got = run_scan(self, b'password = "hunter\0supersecret"\n')
        self.assertEqual(got, [("FAIL", "CWE-798:hardcoded_credential")])

    def test_an_allowlisted_rule_becomes_a_warning_and_the_others_still_fail(self):
        h = context(self, lines('password = "hunter2supersecret"', "GET /x?f=%2e%2e%2fa"), allowlist=Allowlist({("CWE-798", "a.txt"): "test fixture"}))
        universal.scan(h.ctx)
        kinds = dict((m.split("(")[0] if m.startswith("ALLOWED") else m, k) for k, m in h.messages())
        self.assertEqual(h.status(), "FAIL")
        self.assertEqual([k for k, _m in h.messages()], ["WARN", "FAIL"])
        self.assertIn("CWE-22:path_traversal_encoded", [m for _k, m in h.messages()])
        self.assertTrue(kinds)

    def test_below_the_threshold_a_fail_is_a_warning(self):
        h = context(self, lines('password = "hunter2supersecret"'), threshold=4, min_severity="critical")
        universal.scan(h.ctx)
        self.assertEqual(h.status(), "WARN")

    def test_the_file_deadline_raises_and_the_guard_records_the_budget_fail(self):
        h = context(self, lines('password = "hunter2supersecret"'), deadline=time.monotonic() - 1.0)
        with self.assertRaises(ScanBudgetExceeded):
            universal.scan(h.ctx)
        h2 = context(self, lines('password = "hunter2supersecret"'), deadline=time.monotonic() - 1.0)
        self.assertTrue(guard("universal", universal.scan, h2.ctx, requires_outcome=False))
        self.assertEqual(h2.messages(), [("FAIL", "engine:scan_incomplete:universal:time_budget")])

    def test_the_guard_accepts_a_clean_file_without_an_outcome(self):
        h = context(self, lines("print('hello')"))
        self.assertTrue(guard("universal", universal.scan, h.ctx, requires_outcome=False))
        self.assertEqual(h.messages(), [])

    def test_a_file_that_is_all_one_character(self):
        for data in (b"", b"\n", b"\0", b"\0\0\0", b"a", b"-" * 100):
            with self.subTest(data[:6]):
                _h, got = run_scan(self, data)
                self.assertEqual(got, [])

    def test_the_second_file_of_a_run_is_independent_of_the_first(self):
        h = context(self, lines('password = "hunter2supersecret"'))
        universal.scan(h.ctx)
        second = h.new_context("b.txt", data=lines("nothing"))
        universal.scan(second)
        self.assertEqual(h.messages(second.path), [])
        self.assertEqual(h.messages(h.ctx.path), [("FAIL", "CWE-798:hardcoded_credential")])

    def test_messages_are_the_only_text_recorded(self):
        h, _got = run_scan(self, combined_file())
        everything = h.buffers.stdout + h.buffers.stderr + repr(h.snapshot())
        for secret in ("oKFEOeVI2WdxcX4L8y" + "aUEcp4bWTkt2HGVHQx", "hunter2supersecret", "eyJlCIxr89Lcsp"):
            self.assertNotIn(secret, everything)


# ---------------------------------------------------------------------------------------------------------------------------
def grep_rows(path: str) -> "set[str]":
    """The messages of the ten table rows that real grep finds in ``path`` (``grep -qE`` / ``-qiE``, no ``-a``, as ``grep_check`` does)."""
    hits = set()
    for (message, _o, helper), entry in zip(ROWS, table_inventory()):
        flags = "-qiE" if helper == "grep_check_i" else "-qE"
        if run_grep([flags, "-e", entry["pattern"], path]).returncode == 0:
            hits.add(message)
    return hits


def grep_key(path: str) -> bool:
    entry = key_inventory()
    first = run_grep(["-aE", "-A5", "-e", entry["pattern"], path])
    folded = first.stdout.translate(bytes.maketrans(b"\r\n\t", b"   "))
    return run_grep(["-aE", "-e", entry["excl"]], stdin=folded).returncode == 0


def credential_inventory() -> "tuple[str, str, list[tuple[str, str]], str]":
    rows = json.loads((ROOT / "tests" / "conformance" / "patterns.json").read_text(encoding="utf-8"))
    rows = [r for r in rows if r.get("enclosing_function") == "_known_cred_check"]
    alternation = [r["pattern"] for r in rows if r["flags"] == "-qIE" and r.get("dynamic")][0]
    jwt = [r["pattern"] for r in rows if r["flags"] == "-qIE" and not r.get("dynamic")][0]
    found = {}
    for row in rows:
        if row["flags"] == "-ohIE":
            head, _, rest = row["resolved_by"].partition("] (")
            found[int(head.partition("[")[2])] = (rest.rstrip(")"), row["pattern"], row["excl"])
    return alternation, jwt, [found[i][:2] for i in sorted(found)], found[0][2]


def grep_credentials(path: str) -> "set[str]":
    alternation, jwt, providers, exclusion = credential_inventory()
    hits = set()
    if run_grep(["-qIE", "-e", alternation, path]).returncode == 0:
        for name, wrapped in providers:
            matched = run_grep(["-ohIE", "-e", wrapped, path]).stdout
            if matched and run_grep(["-viE", "-e", exclusion], stdin=matched).stdout:
                hits.add("CWE-798:known_credential_format_" + name)
    if run_grep(["-qIE", "-e", jwt, path]).returncode == 0:
        hits.add(credentials.JWT_MESSAGE)
    return hits


def grep_all(path: str) -> "set[str]":
    hits = grep_rows(path) | grep_credentials(path)
    if grep_key(path):
        hits.add(KEY_MESSAGE)
    return hits


def grep_listing(flags: "list[str]", pattern: str, paths: "list[str]") -> "set[str]":
    """The files of ``paths`` that ``grep <flags> -l`` reports for ``pattern``: one process per 150 files, names NUL-terminated."""
    found: "set[str]" = set()
    for index in range(0, len(paths), 150):
        out = run_grep(flags + ["-lZ", "-e", pattern, "--"] + paths[index:index + 150]).stdout
        found.update(name.decode("utf-8", "surrogateescape") for name in out.split(b"\0") if name)
    return found


def grep_all_batch(paths: "list[str]") -> "dict[str, set[str]]":
    """``grep_all`` for many files, with one grep per pattern instead of one per file and pattern (the same decisions)."""
    hits: "dict[str, set[str]]" = {path: set() for path in paths}
    for (message, _o, helper), entry in zip(ROWS, table_inventory()):
        for path in grep_listing(["-iE" if helper == "grep_check_i" else "-E"], entry["pattern"], paths):
            hits[path].add(message)
    entry = key_inventory()
    for path in grep_listing(["-aE"], entry["pattern"], paths):
        if grep_key(path):
            hits[path].add(KEY_MESSAGE)
    alternation, jwt, providers, exclusion = credential_inventory()
    for path in grep_listing(["-IE"], alternation, paths):
        for name, wrapped in providers:
            matched = run_grep(["-ohIE", "-e", wrapped, path]).stdout
            if matched and run_grep(["-viE", "-e", exclusion], stdin=matched).stdout:
                hits[path].add("CWE-798:known_credential_format_" + name)
    for path in grep_listing(["-IE"], jwt, paths):
        hits[path].add(credentials.JWT_MESSAGE)
    return hits


@unittest.skipUnless(HAVE_GNU_GREP, "GNU grep is the oracle")
class OracleTests(unittest.TestCase):
    """What ``scan`` records equals what the bash function finds with the real grep, on every shape the rules have met."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="wp08-universal-")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def python_hits(self, h: support.Harness, rel: str, data: bytes) -> "set[str]":
        ctx = h.new_context(rel, data=data)
        before = len(h.verdict.log)
        universal.scan(ctx)
        entries = h.verdict.log[before:]
        self.assertEqual([e for e in entries if e[0] == "pass"], [])
        return {e[2] for e in entries if e[0] in ("warn", "fail")}

    def sample(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def test_every_row_sample_equals_greps_decision(self):
        h = context(self, b"", verdict="fake")
        samples = [(message, text) for message, (positives, near) in ROW_CASES.items() for text in positives + near]
        paths = [self.sample("row%03d.txt" % number, lines(text)) for number, (_m, text) in enumerate(samples)]
        expected = grep_all_batch(paths)
        for number, ((message, text), path) in enumerate(zip(samples, paths)):
            with self.subTest(message=message, text=text):
                got = self.python_hits(h, "row.txt", lines(text))
                self.assertEqual(got, expected[path])

    def test_the_combined_file(self):
        h = context(self, b"", verdict="fake")
        data = combined_file()
        path = self.sample("combined.txt", data)
        self.assertEqual(self.python_hits(h, "combined.txt", data), grep_all(path))

    def test_the_private_key_rule_equals_the_bash_pipeline_on_random_files(self):
        """250 files made of header, body, junk and NUL lines in random order: the window of five lines, the fold and the body test equal grep."""
        rng = random.Random(20261113)
        heads = [header(""), header("RSA "), "key = \"" + header("EC "), header("OPENSSH "), "  " + header("DSA ") + "  ", j("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----")]
        bodies = [body(64), body(70), body(59), body(60), body(16), "\t" + body(64), body(64) + "\r", body(30) + " " + body(30), body(120)]
        junks = ["", "x", "abc def", footer("RSA "), "Comment: something here", "-" * 100, "-" * 201, "\0", "Version: GnuPG v1", "y" * 150]
        h = context(self, b"", verdict="fake")
        mismatches = []
        for case in range(250):
            count = rng.randint(1, 14)
            picked = []
            for _ in range(count):
                kind = rng.random()
                picked.append(rng.choice(heads) if kind < 0.2 else rng.choice(bodies) if kind < 0.45 else rng.choice(junks))
            sep = rng.choice(["\n", "\n", "\r\n"])
            data = sep.join(picked).encode("latin-1") + rng.choice([b"", b"\n"])
            expected = grep_key(self.sample("key.txt", data))
            ctx = h.new_context("key.txt", data=data)
            got = universal.private_key_present(ctx)
            if got != expected:
                mismatches.append((case, expected, got, picked))
        self.assertEqual(mismatches, [])

    def test_the_fixture_corpus_equals_grep_file_by_file(self):
        """Every file under tests/fixtures/rules (the 364 of them, directories included: 141 text and 223 with a NUL byte): equal to bash where the file holds no NUL byte; where it does,
        bash's findings are a subset of ours (the table rows read as ``grep -a``) and the extra ones are table rows only."""
        paths = sorted(p for p in FIXTURES.rglob("*") if p.is_file())
        self.assertGreater(len(paths), 300)
        h = context(self, b"", verdict="fake")
        problems = []
        compared_nul = compared_text = 0
        every = grep_all_batch([str(path) for path in paths])
        for path in paths:
            data = path.read_bytes()
            rel = str(path.relative_to(FIXTURES))
            expected = every[str(path)]
            got = self.python_hits(h, rel, data)
            if b"\0" in data:
                compared_nul += 1
                if not expected <= got or not (got - expected) <= set(ROW_MESSAGES):
                    problems.append((rel, "nul", sorted(expected ^ got)))
            else:
                compared_text += 1
                if got != expected:
                    problems.append((rel, "text", sorted(expected ^ got)))
        self.assertEqual(problems, [])
        self.assertGreater(compared_text, 100)
        self.assertGreater(compared_nul, 100)

    def test_nul_files_are_the_only_difference_and_in_one_direction(self):
        """The table rows over ``grep -a``: a match across a NUL byte is ours and not bash's; there is no match of bash's that is not ours."""
        h = context(self, b"", verdict="fake")
        for text in ('password = "hunter\0supersecret"\n', 'hashlib.md5\0(x)\n', "TODO\0remove\n", "a\0b%2e%2e\n", "x\0\n", "\0password = 'abcdef'\n"):
            data = text.encode("latin-1")
            with self.subTest(data):
                expected = grep_rows(self.sample("nul.txt", data))
                got = self.python_hits(h, "nul.txt", data) & set(ROW_MESSAGES)
                self.assertLessEqual(expected, got)


if __name__ == "__main__":
    unittest.main()
