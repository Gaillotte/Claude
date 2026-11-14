"""Tests of transit/scanners/python_lang.py (WP-09): the ``python`` scanner (bash ``scan_python``).

    python3 -I -m unittest discover -s tests/engine -p "test_python_lang.py"

``python_lang.scan`` is exercised over a REAL ``ScanContext`` (``tests/engine/support.make_context``: real ``FileView``, real rule machinery,
and either the real ``Verdict`` or the recording ``FakeVerdict`` when the ORDER of events is the point). The oracle is REAL GNU ``grep`` run
the way ``scan_python`` runs it (``grep -qE -e PATTERN FILE`` in the C locale); the patterns it uses are read from tests/conformance/patterns.json
and the order of the messages from ``scan_pipeline.sh``, never from the module under test.

Bandit is a per-file tool: the scanner asks ``ctx.file_tool("bandit")`` and the four answers (``missing``, ``not_ported``, ``ok``, ``failed``) are
driven here with ``support.FakeLocator`` / ``support.StubWrapper``; the host's own tools are never used.

One known difference from bash on a file with a NUL byte (``OracleTests``): a table row is evaluated as ``grep -a`` (``Match(binary="text")``)
while bash's ``grep_check`` has no ``-a``, so on a file that holds a NUL byte bash reads the NUL as a line end. A match that spans the NUL is
found here and not by bash; a line-anchored row (``^\\s*assert``) is found by bash after a NUL and not here. Both are pinned by a test.

No token-shaped credential appears in this file (the scanner has no credential rule).
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
import sysconfig
import tempfile
import time
import types
import unittest
from itertools import chain, repeat
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.engine import support  # noqa: E402
from transit import dispatch, rx  # noqa: E402
from transit import rules as rules_module  # noqa: E402
from transit.findings import Allowlist  # noqa: E402
from transit.rules import Match, RuleSet  # noqa: E402
from transit.scanners import ScannerSpec, invoke, load_registry, python_lang  # noqa: E402
from transit.tools import FILE_TOOLS, ToolOutcome  # noqa: E402
from transit.verdict import GLOBAL_FILE  # noqa: E402

MODULE = ROOT / "transit" / "scanners" / "python_lang.py"
SCRIPT = ROOT / "scan_pipeline.sh"
FIXTURES = ROOT / "tests" / "fixtures"
RULE_FIXTURES = FIXTURES / "rules"
GOLDEN = ROOT / "tests" / "conformance" / "golden"
GREP = shutil.which("grep")

TOOL = "bandit"
MISSING = "bandit missing"
BANDIT_FAIL = "bandit:Severity: HIGH:B602"
#: The six rows of the table, in bash order: ``(message, outcome)``.
ROWS = (
    ("CWE-78:OS_command_injection_risk", "fail"),
    ("CWE-95:dynamic_code_execution_eval_exec", "fail"),
    ("CWE-502:insecure_deserialization_pickle_yaml", "fail"),
    ("CWE-89:SQL_injection_query_built_by_string_interpolation", "fail"),
    ("CWE-601:potential_open_redirect", "warn"),
    ("CWE-703:assert_used_for_security_check", "fail"),
)
ROW_MESSAGES = tuple(message for message, _o in ROWS)
FAIL_MESSAGES = tuple(message for message, outcome in ROWS if outcome == "fail")
WARN_MESSAGES = tuple(message for message, outcome in ROWS if outcome == "warn")
OS_COMMAND, EVAL_EXEC, PICKLE, SQL, REDIRECT, ASSERT = ROW_MESSAGES


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
    """The ``grep_check`` entries of ``scan_python`` in patterns.json, in file order (bandit's own greps are ``grep`` on its output, not rows)."""
    rows = json.loads((ROOT / "tests" / "conformance" / "patterns.json").read_text(encoding="utf-8"))
    return sorted((r for r in rows if r.get("enclosing_function") == "scan_python" and r["helper"] == "grep_check"), key=lambda r: r["line"])


def function_body(name: str) -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index(name + "() {")
    return text[start:text.index("\n}\n", start)]


def bash_events() -> "list[tuple[str, str]]":
    """Every ``record_fail`` / ``record_warn "$f" "..."`` of ``scan_python`` in the order the function reads (bandit's FAIL is cut at its first quote)."""
    return re.findall(r'record_(fail|warn) "\$f" "([^"]+)"', function_body("scan_python"))


def j(*parts: str) -> str:
    return "".join(parts)


def lines(*parts: str, sep: str = "\n") -> bytes:
    return (sep.join(parts) + sep).encode("utf-8")


def context(test: unittest.TestCase, data: "bytes | str", rel: str = "a.py", **kwargs) -> support.Harness:
    return support.make_context(test, rel, data, **kwargs)


def installed(**wrapper_args) -> "tuple[support.StubWrapper, dict]":
    """Keyword arguments for ``make_context`` that make bandit installed with a stub wrapper that answers ``wrapper_args``."""
    wrapper = support.StubWrapper(TOOL, **wrapper_args)
    return wrapper, {"locator": support.FakeLocator({TOOL: "/opt/bin/bandit"}), "wrappers": support.FakeWrappers(wrapper)}


def events(h: support.Harness) -> "list[tuple]":
    """What a ``FakeVerdict`` saw, as ``("pass",)``, ``("warn", msg)``, ``("fail", msg, severity, downgradable)``, ``("note", reason)``: order kept."""
    out: "list[tuple]" = []
    for entry in h.verdict.log:
        if entry[0] == "pass":
            out.append(("pass",))
        elif entry[0] == "warn":
            out.append(("warn", entry[2]))
        elif entry[0] == "fail":
            out.append(("fail", entry[2], entry[3], entry[4]))
        elif entry[0] == "incomplete":
            out.append(("note", entry[2]))
    return out


def rule_messages(test: unittest.TestCase, text: "bytes | str", **kwargs) -> "tuple[list[str], support.Harness]":
    """The messages of a file on a host with no bandit, without ``bandit missing``."""
    data = text if isinstance(text, bytes) else lines(text)
    h = context(test, data, **kwargs)
    python_lang.scan(h.ctx)
    return [message for _kind, message in h.messages() if message != MISSING], h


# ---------------------------------------------------------------------------------------------------------------------------
class TableTests(unittest.TestCase):
    """The table is the bash table: rows, messages, order, patterns, flags."""

    def test_the_table_is_a_registered_ruleset_of_six_rows(self):
        self.assertIsInstance(python_lang.RULES, RuleSet)
        self.assertEqual(python_lang.RULES.name, "python")
        self.assertEqual(len(python_lang.RULES.rules), len(ROWS))

    def test_ids_are_python_nn_slug_and_sequential(self):
        ids = [spec.id for spec in python_lang.RULES.rules]
        for position, rule_id in enumerate(ids, 1):
            self.assertRegex(rule_id, r"^python/%02d-[a-z0-9]+(-[a-z0-9]+)*$" % position)
        self.assertEqual(len(set(ids)), len(ids))

    def test_messages_outcomes_and_order(self):
        self.assertEqual([(s.message, s.outcome) for s in python_lang.RULES.rules], list(ROWS))

    def test_every_message_occurs_in_the_bash_function(self):
        body = function_body("scan_python")
        for message in ROW_MESSAGES + (MISSING,):
            self.assertIn('"%s"' % message, body, message)

    def test_the_rows_follow_the_calls_of_the_bash_function(self):
        calls = [message for _kind, message in bash_events() if not message.startswith("bandit:") and message != MISSING]
        self.assertEqual(calls, list(ROW_MESSAGES))
        outcomes = [kind for kind, message in bash_events() if message in ROW_MESSAGES]
        self.assertEqual(outcomes, [outcome for _m, outcome in ROWS])

    def test_every_row_is_one_match_taken_from_the_inventory(self):
        entries = inventory()
        self.assertEqual(len(entries), len(ROWS))
        for spec, entry in zip(python_lang.RULES.rules, entries):
            with self.subTest(spec.id):
                self.assertIsInstance(spec.cond, Match)
                self.assertEqual(spec.cond.pattern, entry["pattern"])
                self.assertEqual((spec.cond.mode, spec.cond.binary, spec.cond.excl, spec.cond.ci), ("line", "text", None, False))

    def test_the_bandit_calls_precede_every_rule_in_bash(self):
        body = function_body("scan_python")
        first_rule = min(body.index('"%s"' % message) for message in ROW_MESSAGES)
        self.assertLess(body.index("has_cmd bandit"), first_rule)
        self.assertLess(body.index('"%s"' % MISSING), first_rule)
        self.assertLess(body.index("bandit:${sev}"), first_rule)

    def test_rows_leave_the_severity_to_the_classifier_and_name_their_source(self):
        for spec in python_lang.RULES.rules:
            self.assertIsNone(spec.severity, spec.id)
            self.assertEqual(spec.source, "scan_python", spec.id)
            self.assertIsNone(spec.applies_to, spec.id)

    def test_every_leaf_is_registered_with_rx(self):
        by_id = {rule.id: rule for rule in rx.registered()}
        for spec in python_lang.RULES.rules:
            self.assertIn(spec.id, by_id)
            self.assertEqual(by_id[spec.id].pattern, spec.cond.pattern)
            self.assertEqual(by_id[spec.id].mode, "line")

    def test_every_pattern_has_a_linear_matcher(self):
        by_id = {rule.id: rule for rule in rx.registered()}
        for spec in python_lang.RULES.rules:
            self.assertTrue(rx.dfa_available(by_id[spec.id].compiled), spec.id)

    def test_the_scanner_declaration(self):
        self.assertEqual(len(python_lang.SCANNERS), 1)
        spec = python_lang.SCANNERS[0]
        self.assertIsInstance(spec, ScannerSpec)
        self.assertEqual((spec.id, spec.family, spec.bash_function, spec.tools, spec.ported), ("python", "python", "scan_python", (TOOL,), True))
        self.assertIs(spec.fn, python_lang.scan)
        self.assertIn(TOOL, FILE_TOOLS)

    def test_importing_the_module_is_silent_and_builds_the_table(self):
        code = ("import sys\nsys.path.insert(0, %r)\nfrom transit.scanners import python_lang\n"
                "assert python_lang.RULES is not None and len(python_lang.RULES.rules) == 6\n" % str(ROOT))
        run = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, timeout=60)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b"", b""), run.stderr)


class RegistryTests(unittest.TestCase):
    """The registry finds the scanner and counts it as ported."""

    def test_the_registry_loads_the_module_and_reports_it_ported(self):
        registry = load_registry(["python_lang"])
        self.assertEqual(registry.load_errors, ())
        self.assertIsNotNone(registry.get("python"))
        self.assertTrue(registry.get("python").ported)
        self.assertNotIn("python", registry.unported())

    def test_discovery_over_the_whole_package_finds_it(self):
        registry = load_registry()
        self.assertTrue(registry.get("python") is not None and registry.get("python").ported)
        self.assertEqual([e for e in registry.load_errors if e.startswith("python_lang")], [])

    def test_invoke_runs_the_scanner_and_a_clean_file_records_a_warn_and_a_pass(self):
        registry = load_registry(["python_lang"])
        h = context(self, lines("print(1)"), verdict="fake", registry=registry)
        self.assertIs(invoke(registry, "python", h.ctx), True)
        self.assertEqual(events(h), [("warn", MISSING), ("pass",)])


class SourceDisciplineTests(unittest.TestCase):
    """Design 3.2, 7.1 and 9 checked on this module's source (tests/engine/test_lints.py checks the same across the package)."""

    def tree(self) -> ast.Module:
        return ast.parse(MODULE.read_text(encoding="utf-8"))

    def test_no_pattern_is_built_inside_a_function(self):
        offenders = []
        for node in ast.walk(self.tree()):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call):
                        func = inner.func
                        name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
                        if name in ("Match", "Matcher", "RuleSet", "RuleSpec", "ere_to_py", "ere_to_py_source", "rule", "compile", "parse_ere"):
                            offenders.append((node.name, name, inner.lineno))
        self.assertEqual(offenders, [])

    def test_no_regex_module_and_no_whole_buffer_split(self):
        text = MODULE.read_text(encoding="utf-8")
        used = {n.attr for n in ast.walk(self.tree()) if isinstance(n, ast.Attribute)}
        for forbidden in ("after_context", "lines_over", "splitlines", "readlines"):
            self.assertNotIn(forbidden, used, forbidden)
        for needle in ('split(b"\\n")', "split(b'\\n')", "import re\n", "from re "):
            self.assertNotIn(needle, text, needle)
        imported = set()
        for node in ast.walk(self.tree()):
            if isinstance(node, ast.Import):
                imported.update(a.name.partition(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").partition(".")[0])
        self.assertFalse(imported & {"re", "subprocess", "os", "shlex", "signal", "threading"}, imported)
        for node in ast.walk(self.tree()):
            if isinstance(node, ast.Call):
                func = node.func
                called = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
                self.assertNotIn(called, ("eval", "exec", "system", "popen", "Popen", "compile"), called)
                self.assertNotIn("shell", [kw.arg for kw in node.keywords])

    def test_it_never_imports_verdict_console_or_the_layers_above(self):
        for node in ast.walk(self.tree()):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for name in names:
                self.assertNotIn(name, ("transit.verdict", "transit.console", "transit.layers", "transit.pipeline", "transit.report"))

    def test_the_tool_result_is_applied_by_the_context_and_never_by_a_loop_of_the_scanner(self):
        tree = self.tree()
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertIn("apply_tool_records", attributes)
        self.assertNotIn("records", attributes)                  # design 7.1 (9): a loop over run.records drops the WARN of a failed tool
        called = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "file_tool"]
        self.assertEqual([c.args[0].value for c in called], [TOOL])

    def test_no_message_is_formatted_from_repository_text(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"record_(fail|warn)\([^)]*(%|\.format|f\")")

    def test_no_module_level_mutable_state(self):
        for node in self.tree().body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                for inner in ast.walk(value) if value is not None else ():
                    self.assertNotIsInstance(inner, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp))
            self.assertNotIsInstance(node, ast.Global)
        for node in ast.walk(self.tree()):
            self.assertNotIsInstance(node, ast.Global)


# ---------------------------------------------------------------------------------------------------------------------------
#: ``(positive lines, near-miss lines)`` for every row, as text. A positive must fire its row and no other; a near miss must fire nothing.
#: Some positives are weak spots of the bash rule that are COPIED (a dotted ``.exec(``, ``assert is_adminx``, ``yaml.load(f)or``).
ROW_CASES = {
    OS_COMMAND: (
        ['os.system("ls")', "subprocess.call(cmd, shell=True)", "subprocess.Popen (args)", "commands.getoutput('x')", "rc = os.system\t(c)",
         "import os; os.system(c)"],
        ['subprocess.run(["ls"])', "os.systemd(x)", "myos.system(x)", "os.system is bad", "subprocess.check_output(x)", "os.popen(x)",
         "subprocess.call_x(y)", "os . system(x)", "OS.SYSTEM(x)", "Subprocess.call(x)"]),
    EVAL_EXEC: (
        ["eval(x)", "exec (code)", "result = eval( s )", "cursor.exec(q)", "exec\t(code)", "x = (eval)(y); eval(z)"],
        ["ast.literal_eval(x)", "evaluate(x)", "executor(x)", "exec_module(x)", "my_exec(x)", "eval", "# eval is risky", "preexec_fn(x)",
         "retrieval(x)", "EVAL(x)", "Exec(x)"]),
    PICKLE: (
        ["pickle.loads(data)", "pickle.load(f)", "marshal.loads(b)", "x = yaml.load(f)or {}", "data = yaml.load (stream)y"],
        ["yaml.load(f)", "yaml.load(f, Loader=yaml.SafeLoader)", "yaml.safe_load(f)", "pickle.dumps(x)", "cPickle.loads(x)", "mypickle.loads(x)",
         "marshal.load(f)", "yaml.load(f) # x", "pickle.loadz(x)", "Pickle.loads(x)"]),
    SQL: (
        ['cur.execute(f"SELECT * FROM t WHERE id={x}")', "cur.execute(f'SELECT {x}')", 'cur.execute("SELECT " + name)',
         "cur.execute('SELECT %s' % x)", 'cur.execute("SELECT {}".format(x))', 'cursor.executemany(f"INSERT {x}", rows)', 'db.execute( "a" + b )',
         'execute(f"x")'],
        ['cur.execute("SELECT id, name FROM users WHERE name = ?", (name,))', "cur.execute(query, params)", 'cur.execute("SELECT 1")',
         "cur.execute(sql)", 'cur.executescript(f"x")', "cur.execute(f)", 'cur.execute("a", (x,))', 'cur.execute(format("a"))',
         'cur.execute("SELECT %s", (a,))', 'cur.Execute(f"x")']),
    REDIRECT: (
        ['return redirect(request.GET["next"])', "HttpResponseRedirect( request.args.get('u'))", 'redirect (request.form["x"])',
         "flask.redirect(request.url)"],
        ['redirect(url_for("index"))', 'redirect("/home")', "redirect(next_url)", "redirect(requests.get(u))", "redirect(request)",
         "Redirect(request.x)", "redirected(request.x)"]),
    ASSERT: (
        ["assert is_admin", "    assert user.is_staff", '\tassert has_perm("x")', "assert is_authenticated(request)", 'assert user.is_superuser, "no"',
         "assert is_adminx"],
        ["assert x == 1", "# assert is_admin", "x = 1; assert is_admin", "assertTrue(is_admin)", "assert  not is_admin", "assert_is_admin",
         "assert user.name", "Assert is_admin", "assert"]),
}


class RowTests(unittest.TestCase):
    """One positive and one near-miss fixture per rule, through ``scan`` (a real context and verdict, bandit not installed)."""

    def test_the_cases_cover_every_row(self):
        self.assertEqual(tuple(ROW_CASES), ROW_MESSAGES)
        for message, (positives, near) in ROW_CASES.items():
            self.assertGreaterEqual(len(positives), 4, message)
            self.assertGreaterEqual(len(near), 6, message)

    def test_a_positive_fires_its_row_and_only_its_row(self):
        for message, (positives, _near) in ROW_CASES.items():
            for text in positives:
                with self.subTest(message=message, text=text):
                    got, _h = rule_messages(self, text)
                    self.assertEqual(got, [message])

    def test_a_near_miss_fires_nothing(self):
        for message, (_positives, near) in ROW_CASES.items():
            for text in near:
                with self.subTest(message=message, text=text):
                    got, h = rule_messages(self, text)
                    self.assertEqual(got, [])
                    self.assertEqual(h.snapshot().counters.pass_, 1)         # finish(False): the file's PASS

    def test_a_fail_row_is_recorded_as_a_fail_and_the_warn_row_as_a_warn(self):
        for message, outcome in ROWS:
            with self.subTest(message=message):
                got, h = rule_messages(self, ROW_CASES[message][0][0])
                self.assertEqual(h.messages(), [("WARN", MISSING), (outcome.upper(), message)])
                self.assertEqual(h.status(), "FAIL" if outcome == "fail" else "WARN")

    def test_the_same_row_is_reported_once_however_many_lines_match(self):
        got, _h = rule_messages(self, lines(*(["os.system(a)"] * 50)))
        self.assertEqual(got, [OS_COMMAND])

    def test_several_rows_are_reported_in_table_order_whatever_the_order_in_the_file(self):
        picked = [ROW_CASES[message][0][0] for message in reversed(ROW_MESSAGES)]
        got, _h = rule_messages(self, lines(*picked))
        self.assertEqual(got, list(ROW_MESSAGES))

    def test_rules_are_line_rules_not_whole_file_rules(self):
        """grep reads one line at a time: the two halves of a pattern on different lines are not a match (a flat rule would find them)."""
        for text in ("eval\n(x)", "os.system\n(x)", "pickle.\nloads(x)", "execute(\nf'x')", "redirect(\nrequest.x)", "assert\nis_admin", "yaml.load(\nf)y"):
            with self.subTest(text):
                got, _h = rule_messages(self, text + "\n")
                self.assertEqual(got, [])

    def test_the_rules_are_case_sensitive(self):
        for text in ("OS.SYSTEM(x)", "EVAL(x)", "PICKLE.LOADS(x)", "EXECUTE(F'X')", "REDIRECT(REQUEST.X)", "ASSERT IS_ADMIN"):
            with self.subTest(text):
                got, _h = rule_messages(self, text + "\n")
                self.assertEqual(got, [])

    def test_the_documented_weak_spots_of_the_bash_rules_are_copied(self):
        """A dotted ``.exec(``, ``assert is_adminx`` and ``yaml.load(f)or`` are findings in bash; a ``yaml.load(f)`` is the dead alternative and is not."""
        self.assertEqual(rule_messages(self, "x.exec(y)\n")[0], [EVAL_EXEC])
        self.assertEqual(rule_messages(self, "assert is_adminx\n")[0], [ASSERT])
        self.assertEqual(rule_messages(self, "d = yaml.load(f)or {}\n")[0], [PICKLE])
        self.assertEqual(rule_messages(self, "d = yaml.load(f)\n")[0], [])

    def test_crlf_lines_are_read_like_lf_lines(self):
        for message, (positives, _near) in ROW_CASES.items():
            with self.subTest(message):
                got, _h = rule_messages(self, lines(positives[0], "x = 1", sep="\r\n"))
                self.assertEqual(got, [message])

    def test_a_file_without_a_final_newline_and_a_file_of_one_line(self):
        for message, (positives, _near) in ROW_CASES.items():
            with self.subTest(message):
                got, _h = rule_messages(self, positives[0].encode("utf-8"))
                self.assertEqual(got, [message])

    def test_a_nul_byte_or_invalid_utf8_does_not_hide_a_rule(self):
        """Contract 8.7 / E8: ``grep_check`` examines a file that holds a NUL byte or bytes that are not UTF-8."""
        for blob in (b"\0", b"\xff\xfe", b"\x80\x81", b"\0\0\0"):
            for message, (positives, _near) in ROW_CASES.items():
                with self.subTest(blob=blob, message=message):
                    got, _h = rule_messages(self, blob + b"\n" + positives[0].encode("utf-8") + b"\n" + blob + b"\n")
                    self.assertEqual(got, [message])

    def test_an_empty_file_and_a_file_of_noise(self):
        for data in (b"", b"\n", b"\0", b"   \n\t\n", b"a" * 100, bytes(range(256)) * 4, b"\xff" * 1000):
            with self.subTest(data[:8]):
                got, h = rule_messages(self, data)
                self.assertEqual(got, [])
                self.assertEqual(h.snapshot().counters.pass_, 1)

    def test_the_fixture_files(self):
        expected = {
            "deserialize.py": [PICKLE], "sql_injection.py": [SQL], "safe_sql.py": [], "case_upper.PY": [OS_COMMAND], "entrypoint": [PICKLE],
        }
        for name, want in expected.items():
            with self.subTest(name):
                got, _h = rule_messages(self, (RULE_FIXTURES / name).read_bytes(), rel=name)
                self.assertEqual(got, want)

    def test_the_vulnerable_fixture(self):
        got, _h = rule_messages(self, (FIXTURES / "vulnerable" / "src" / "db.py").read_bytes(), rel="src/db.py")
        self.assertEqual(got, [SQL])


# ---------------------------------------------------------------------------------------------------------------------------
class ToolTests(unittest.TestCase):
    """Bandit through ``ctx.file_tool``: missing, not ported, ok and failed; the order of events; the WARN a failed run carries."""

    def test_bandit_missing_is_a_warn_on_the_file_before_anything_else_and_the_file_still_passes(self):
        h = context(self, lines("print(1)"), verdict="fake")
        self.assertTrue(python_lang.scan(h.ctx))
        self.assertEqual(events(h), [("warn", MISSING), ("pass",)])
        self.assertEqual(h.verdict.of("warn")[0][1], h.ctx.path)             # on the file, not on __global__
        self.assertEqual(h.locator.asked, [TOOL])                            # the scanner asks for bandit and for nothing else

    def test_bandit_ok_with_no_record_is_a_pass_and_no_warn(self):
        wrapper, kw = installed(outcome=ToolOutcome(layer_state=None))
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertEqual(events(h), [("pass",)])
        self.assertEqual(len(wrapper.requests), 1)
        self.assertEqual(wrapper.requests[0].target, h.ctx.path)
        self.assertEqual(wrapper.requests[0].info.path, "/opt/bin/bandit")

    def test_a_bandit_fail_is_recorded_first_with_its_severity_and_no_pass_follows(self):
        _w, kw = installed(outcome=ToolOutcome(layer_state=None, records=(support.fail_record(BANDIT_FAIL, severity="HIGH"),)))
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertEqual(events(h), [("fail", BANDIT_FAIL, "HIGH", True)])

    def test_bandit_comes_before_the_rules(self):
        """bash order: Bandit, then the six greps. The message of a file in the report keeps that order."""
        _w, kw = installed(outcome=ToolOutcome(layer_state=None, records=(support.fail_record(BANDIT_FAIL),)))
        h = context(self, lines("os.system(x)", "eval(y)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertEqual([e[:2] for e in events(h)], [("fail", BANDIT_FAIL), ("fail", OS_COMMAND), ("fail", EVAL_EXEC)])

    def test_the_missing_warn_comes_before_the_rules(self):
        h = context(self, lines("os.system(x)"), verdict="fake")
        python_lang.scan(h.ctx)
        self.assertEqual([e[:2] for e in events(h)], [("warn", MISSING), ("fail", OS_COMMAND)])

    def test_the_records_of_a_run_are_applied_in_order_the_warns_included(self):
        records = (support.warn_record("bandit:note"), support.fail_record(BANDIT_FAIL), support.warn_record("bandit:another"))
        _w, kw = installed(outcome=ToolOutcome(layer_state=None, records=records))
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertEqual([e[:2] for e in events(h)], [("warn", "bandit:note"), ("fail", BANDIT_FAIL), ("warn", "bandit:another")])

    def test_a_failed_run_keeps_its_warn_and_the_rules_still_run(self):
        """A tool that started and could not do its job: its WARN is recorded (design 7.1 rule 9), L5 is noted, the greps run, the file passes."""
        outcome = ToolOutcome(layer_state="skipped:bandit failed (exit 3)", records=(support.warn_record("bandit:scan_error_exit_3"),))
        _w, kw = installed(outcome=outcome)
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertEqual(events(h), [("note", "bandit failed (exit 3)"), ("warn", "bandit:scan_error_exit_3"), ("pass",)])

    def test_a_failed_run_does_not_hide_a_rule(self):
        outcome = ToolOutcome(layer_state="skipped:bandit failed (exit 3)", records=(support.warn_record("bandit:scan_error_exit_3"),))
        _w, kw = installed(outcome=outcome)
        h = context(self, lines("os.system(x)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertEqual([e[:2] for e in events(h) if e[0] != "note"], [("warn", "bandit:scan_error_exit_3"), ("fail", OS_COMMAND)])

    def test_a_timed_out_run_is_a_failed_run(self):
        outcome = ToolOutcome(layer_state=None, timed_out=True, records=(support.warn_record("bandit:timed_out"),))
        _w, kw = installed(outcome=outcome)
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertEqual(events(h), [("note", "bandit timed out"), ("warn", "bandit:timed_out"), ("pass",)])

    def test_a_failed_run_that_chose_a_fail_sets_fired(self):
        outcome = ToolOutcome(layer_state="partial:bandit output could not be read", records=(support.fail_record("bandit:unreadable"),))
        _w, kw = installed(outcome=outcome)
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertNotIn(("pass",), events(h))
        self.assertIn(("fail", "bandit:unreadable", None, True), events(h))

    def test_an_installed_tool_without_a_wrapper_is_noted_once_per_run_and_is_not_missing(self):
        locator = support.FakeLocator({TOOL: "/opt/bin/bandit"})
        h = context(self, lines("print(1)"), verdict="fake", locator=locator, wrappers=support.FakeWrappers())
        python_lang.scan(h.ctx)
        second = h.new_context("b.py", data=lines("print(2)"))
        python_lang.scan(second)
        warns = [e for e in h.verdict.of("warn")]
        self.assertEqual(warns, [("warn", GLOBAL_FILE, "engine:tool_not_ported:bandit")])        # once per run, on __global__
        self.assertNotIn(("warn", h.ctx.path, MISSING), h.verdict.log)
        self.assertEqual(len(h.verdict.of("pass")), 2)                                            # both files were scanned by the greps and passed
        self.assertIn(("incomplete", "L5_per_language_sast", "python engine has not ported bandit yet"), h.verdict.log)

    def test_an_installed_tool_without_a_wrapper_does_not_stop_the_rules(self):
        locator = support.FakeLocator({TOOL: "/opt/bin/bandit"})
        h = context(self, lines("eval(x)"), verdict="fake", locator=locator, wrappers=support.FakeWrappers())
        python_lang.scan(h.ctx)
        self.assertIn(("fail", EVAL_EXEC, None, True), events(h))

    def test_a_wrapper_that_raises_is_not_a_failed_run(self):
        """The exception reaches ``invoke``, which turns it into the non-downgradable FAIL; the scanner neither swallows it nor records a PASS."""
        _w, kw = installed(raises=RuntimeError("boom"))
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        with self.assertRaises(RuntimeError) as caught:
            python_lang.scan(h.ctx)
        self.assertEqual(str(caught.exception), "boom")                    # the wrapper's own exception (NotImplementedError is a RuntimeError too)
        self.assertEqual(events(h), [])

    def test_a_wrapper_that_raises_becomes_the_engine_fail_through_invoke(self):
        registry = load_registry(["python_lang"])
        _w, kw = installed(raises=RuntimeError("boom"))
        h = context(self, lines("print(1)"), verdict="fake", registry=registry, **kw)
        self.assertTrue(invoke(registry, "python", h.ctx))
        self.assertEqual(events(h), [("fail", "engine:scanner_error:python:RuntimeError", None, False)])

    def test_a_pass_record_from_a_wrapper_is_a_bug_and_nothing_is_recorded(self):
        _w, kw = installed(outcome=ToolOutcome(layer_state=None, records=(support.warn_record("x"), support.Record("pass", "", "", None))))
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        with self.assertRaises(ValueError):
            python_lang.scan(h.ctx)
        self.assertEqual(events(h), [])

    def test_a_bandit_fail_alone_is_enough_for_fired_the_clean_rules_do_not_add_a_pass(self):
        _w, kw = installed(outcome=ToolOutcome(layer_state=None, records=(support.fail_record(BANDIT_FAIL),)))
        h = context(self, lines("print(1)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertNotIn(("pass",), events(h))

    def test_a_rule_fail_alone_is_enough_for_fired_when_bandit_is_clean(self):
        _w, kw = installed(outcome=ToolOutcome(layer_state=None))
        h = context(self, lines("os.system(x)"), verdict="fake", **kw)
        python_lang.scan(h.ctx)
        self.assertEqual(events(h), [("fail", OS_COMMAND, None, True)])

    def test_a_per_file_tool_other_than_bandit_is_never_asked(self):
        h = context(self, lines("print(1)"), verdict="fake", locator=support.FakeLocator({"shellcheck": "/x", "cppcheck": "/y"}))
        python_lang.scan(h.ctx)
        self.assertEqual(h.locator.asked, [TOOL])
        self.assertEqual(events(h), [("warn", MISSING), ("pass",)])


# ---------------------------------------------------------------------------------------------------------------------------
class FiredTests(unittest.TestCase):
    """``fired`` stays true after the allowlist or the threshold downgraded the FAIL (bash ``failed=true``): no PASS is recorded beside it."""

    FIRST = {message: ROW_CASES[message][0][0] for message in ROW_MESSAGES}

    def test_every_fail_row_means_no_pass_and_the_warn_row_means_a_pass(self):
        for message, outcome in ROWS:
            with self.subTest(message=message):
                _got, h = rule_messages(self, self.FIRST[message])
                self.assertEqual(h.snapshot().counters.pass_, 0 if outcome == "fail" else 1)

    def test_an_allowlisted_rule_is_a_warn_and_still_means_no_pass(self):
        h = context(self, lines("os.system(x)"), allowlist=Allowlist({("CWE-78", "a.py"): "fixture"}))
        python_lang.scan(h.ctx)
        self.assertEqual(h.messages(), [("WARN", MISSING), ("WARN", "ALLOWED:%s (reason: fixture)" % OS_COMMAND)])
        counters = h.snapshot().counters
        self.assertEqual((counters.pass_, counters.fail), (0, 0))
        self.assertEqual((h.status(), h.snapshot().verdict), ("WARN", "PASS"))

    def test_a_rule_below_the_threshold_is_a_warn_and_still_means_no_pass(self):
        h = context(self, lines("os.system(x)"), threshold=4, min_severity="critical")
        python_lang.scan(h.ctx)
        self.assertEqual(h.messages(), [("WARN", MISSING), ("WARN", "LOW_SEV(below --min-severity critical):%s" % OS_COMMAND)])
        self.assertEqual(h.snapshot().counters.pass_, 0)
        self.assertEqual(h.snapshot().verdict, "PASS")

    def test_every_fail_row_stays_fired_after_a_downgrade(self):
        for message in FAIL_MESSAGES:
            with self.subTest(message=message):
                token = message.partition(":")[0]
                h = context(self, lines(self.FIRST[message]), allowlist=Allowlist({(token, "a.py"): "fixture"}))
                python_lang.scan(h.ctx)
                self.assertEqual(h.snapshot().counters.pass_, 0)
                self.assertEqual(h.snapshot().verdict, "PASS")

    def test_a_downgraded_bandit_fail_stays_fired(self):
        _w, kw = installed(outcome=ToolOutcome(layer_state=None, records=(support.fail_record(BANDIT_FAIL),)))
        h = context(self, lines("print(1)"), allowlist=Allowlist({("bandit", "a.py"): "fixture"}), **kw)
        python_lang.scan(h.ctx)
        self.assertEqual(h.messages(), [("WARN", "ALLOWED:%s (reason: fixture)" % BANDIT_FAIL)])
        self.assertEqual(h.snapshot().counters.pass_, 0)

    def test_one_downgraded_rule_does_not_excuse_another(self):
        h = context(self, lines("os.system(x)", "eval(y)"), allowlist=Allowlist({("CWE-78", "a.py"): "fixture"}))
        python_lang.scan(h.ctx)
        self.assertEqual(h.messages(), [("WARN", MISSING), ("WARN", "ALLOWED:%s (reason: fixture)" % OS_COMMAND), ("FAIL", EVAL_EXEC)])
        self.assertEqual(h.snapshot().verdict, "FAIL")

    def test_the_allowlist_is_per_file(self):
        h = context(self, lines("os.system(x)"), allowlist=Allowlist({("CWE-78", "other.py"): "fixture"}))
        python_lang.scan(h.ctx)
        self.assertEqual(h.messages(), [("WARN", MISSING), ("FAIL", OS_COMMAND)])


class BudgetTests(unittest.TestCase):
    """The per-file deadline and an unfinished search are visible: a file whose rules were not all evaluated is not clean and is not a PASS."""

    def test_a_deadline_that_has_passed_is_the_engine_fail_and_never_a_pass(self):
        h = context(self, lines("os.system(x)"), verdict="fake", deadline=time.monotonic() - 1.0)
        self.assertTrue(python_lang.scan(h.ctx))
        self.assertEqual(events(h), [("warn", MISSING), ("fail", "engine:scan_incomplete:python:time_budget", None, False),
                                     ("note", "per-file time budget reached")])

    def test_the_budget_fail_cannot_be_allowlisted_or_lowered(self):
        h = context(self, lines("print(1)"), deadline=time.monotonic() - 1.0, threshold=4, min_severity="critical",
                    allowlist=Allowlist({("engine", "a.py"): "x", ("scan_incomplete", "a.py"): "x"}))
        python_lang.scan(h.ctx)
        self.assertIn(("FAIL", "engine:scan_incomplete:python:time_budget"), h.messages())
        self.assertEqual(h.snapshot().verdict, "FAIL")
        self.assertEqual(h.snapshot().counters.pass_, 0)

    def test_a_deadline_that_passes_between_two_rules_keeps_the_hits_and_fails_the_rest(self):
        clock = chain([0.0], repeat(1000.0))
        h = context(self, lines("os.system(x)", "eval(y)"), verdict="fake", deadline=100.0)
        fake_time = types.SimpleNamespace(monotonic=lambda: next(clock), perf_counter=time.perf_counter)
        with mock.patch.object(rules_module, "time", fake_time):
            python_lang.scan(h.ctx)
        got = events(h)
        self.assertEqual([e[:2] for e in got if e[0] in ("warn", "fail")],
                         [("warn", MISSING), ("fail", OS_COMMAND), ("fail", "engine:scan_incomplete:python:time_budget")])
        self.assertNotIn(("pass",), got)

    def test_a_search_that_cannot_finish_is_the_engine_fail_once_and_never_a_pass(self):
        h = context(self, lines("print(1)"), verdict="fake")
        with mock.patch.object(rules_module, "run_ruleset", side_effect=MemoryError):
            self.assertTrue(python_lang.scan(h.ctx))
        got = events(h)
        self.assertEqual([e for e in got if e[0] == "fail"], [("fail", "engine:search_incomplete", None, False)])
        self.assertNotIn(("pass",), got)
        self.assertIn(("note", "a search could not be completed"), got)

    def test_the_budget_fail_is_not_followed_by_a_second_event_for_the_same_cause(self):
        h = context(self, lines("print(1)"), verdict="fake", deadline=time.monotonic() - 1.0)
        python_lang.scan(h.ctx)
        self.assertEqual(len([e for e in h.verdict.of("fail")]), 1)


class HostileLineTests(unittest.TestCase):
    """S12: every row finishes a 600 KB line in well under a second; a whole file of it in a few."""

    LIMIT_S = 1.0
    LINES = {
        "os_system": b"os.system " * 60_000,
        "eval": b"eval " * 120_000,
        "yaml": b"yaml.load(" * 60_000,
        "yaml_open": b"yaml.load(" + b"a" * 600_000,
        "execute_quote": b'execute("' + b"a" * 600_000,
        "execute_repeat": b"execute(" * 80_000,
        "redirect": b"redirect( " * 60_000,
        "assert": b"assert " * 90_000,
        "spaces": b" " * 600_000,
        "pickle": b"pickle.load" * 50_000,
        "quote_run": b"execute(\"a\" " * 50_000,
    }

    def test_every_row_on_every_hostile_line(self):
        h = context(self, b"x\n")
        for spec in python_lang.RULES.rules:
            for label, line in self.LINES.items():
                started = time.perf_counter()
                h.ctx.search(spec.cond, data=line)
                took = time.perf_counter() - started
                self.assertLess(took, self.LIMIT_S, "%s on the %s line took %.2f s" % (spec.id, label, took))

    def test_the_whole_scan_on_a_hostile_line(self):
        for label in ("os_system", "yaml", "execute_quote", "assert", "spaces"):
            with self.subTest(label):
                h = context(self, self.LINES[label] + b"\n")
                started = time.perf_counter()
                python_lang.scan(h.ctx)
                self.assertLess(time.perf_counter() - started, 6.0)

    def test_a_rule_still_fires_after_a_hostile_line(self):
        got, _h = rule_messages(self, self.LINES["os_system"] + b"\neval(x)\n")
        self.assertEqual(got, [EVAL_EXEC])                               # the long line itself has no ``(``: only the eval line is a finding

    def test_a_payload_behind_a_very_long_line_is_found(self):
        pad = b"#" + b"x" * 700_000
        got, _h = rule_messages(self, pad + b"\nos.system(x)\n" + pad + b"\n")
        self.assertEqual(got, [OS_COMMAND])

    def test_a_payload_at_the_end_of_a_very_long_line_is_found(self):
        got, _h = rule_messages(self, b"x = '" + b"y" * 700_000 + b"'; os.system(c)\n")
        self.assertEqual(got, [OS_COMMAND])


# ---------------------------------------------------------------------------------------------------------------------------
class ScanTests(unittest.TestCase):
    """The scanner as a whole."""

    def test_it_returns_true_and_records_an_event_for_every_file(self):
        for data in (b"", b"print(1)\n", b"os.system(x)\n", bytes(range(256))):
            with self.subTest(data[:10]):
                h = context(self, data, verdict="fake")
                before = h.verdict.events
                self.assertIs(python_lang.scan(h.ctx), True)
                self.assertGreater(h.verdict.events, before)

    def test_it_returns_true_for_a_sniffed_file_too(self):
        """An extensionless script routed by its shebang reaches this scanner with ``sniffed`` False (``unknown`` delegates) or True: both are handled."""
        for sniffed in (False, True):
            h = context(self, b"#!/usr/bin/env python3\nprint(1)\n", rel="entrypoint", verdict="fake", sniffed=sniffed)
            self.assertIs(python_lang.scan(h.ctx), True)

    def test_the_second_file_of_a_run_is_independent_of_the_first(self):
        h = context(self, lines("os.system(x)"))
        python_lang.scan(h.ctx)
        second = h.new_context("b.py", data=lines("print(1)"))
        python_lang.scan(second)
        self.assertEqual(h.messages(second.path), [("WARN", MISSING)])
        self.assertEqual(h.messages(h.ctx.path), [("WARN", MISSING), ("FAIL", OS_COMMAND)])

    def test_the_clean_fixture(self):
        """tests/fixtures/clean/src/app.py on a host with no bandit: one WARN, one PASS, status WARN (first writer), as golden/clean.json."""
        h = context(self, (FIXTURES / "clean" / "src" / "app.py").read_bytes(), rel="src/app.py", verdict="fake")
        python_lang.scan(h.ctx)
        self.assertEqual(events(h), [("warn", MISSING), ("pass",)])
        real = context(self, (FIXTURES / "clean" / "src" / "app.py").read_bytes(), rel="src/app.py")
        python_lang.scan(real.ctx)
        self.assertEqual((real.status(), real.snapshot().counters.pass_, real.snapshot().counters.warn), ("WARN", 1, 1))
        self.assertEqual(real.messages(), [("WARN", MISSING)])

    def test_the_messages_are_the_only_text_recorded(self):
        secret = "sup3r-s3cret-marker"
        h = context(self, lines('os.system("%s")' % secret, 'eval("%s")' % secret))
        python_lang.scan(h.ctx)
        everything = h.buffers.stdout + h.buffers.stderr + repr(h.snapshot())
        self.assertNotIn(secret, everything)

    def test_a_file_named_with_hostile_text_is_recorded_under_its_path_only(self):
        rel = "<img src=x onerror=alert(1)>.py"
        h = context(self, lines("eval(x)"), rel=rel)
        python_lang.scan(h.ctx)
        self.assertEqual(h.messages(), [("WARN", MISSING), ("FAIL", EVAL_EXEC)])
        self.assertNotIn("onerror", "".join(m for _k, m in h.messages()))

    def test_a_large_file_of_ordinary_lines(self):
        data = (b"def f(x):\n    return x + 1\n" * 200_000) + b"os.system(y)\n"
        started = time.perf_counter()
        got, _h = rule_messages(self, data)
        self.assertEqual(got, [OS_COMMAND])
        self.assertLess(time.perf_counter() - started, 10.0)


# ---------------------------------------------------------------------------------------------------------------------------
def grep_matching(patterns: "list[str]", paths: "list[str]") -> "dict[int, set[str]]":
    """For each pattern (by index) the files real GNU grep lists with ``-lE`` (the decision of ``grep_check``), in the C locale."""
    result: "dict[int, set[str]]" = {}
    for index, pattern in enumerate(patterns):
        run = subprocess.run([GREP or "grep", "-lZE", "-e", pattern, "--"] + paths, capture_output=True, timeout=300, env={"LC_ALL": "C"})
        if run.returncode not in (0, 1):
            raise AssertionError("grep failed (%d): %r" % (run.returncode, run.stderr))
        result[index] = {chunk.decode("utf-8", "surrogateescape") for chunk in run.stdout.split(b"\0") if chunk}
    return result


@unittest.skipUnless(HAVE_GNU_GREP, "GNU grep is the oracle")
class OracleTests(unittest.TestCase):
    """What ``scan`` records equals what the bash function finds with the real grep, on every shape the rules have met."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="wp09-python-")
        cls.patterns = [entry["pattern"] for entry in inventory()]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def sample(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def bash_hits(self, paths: "list[str]") -> "dict[str, set[str]]":
        matching = grep_matching(self.patterns, paths)
        return {path: {ROW_MESSAGES[i] for i in range(len(ROW_MESSAGES)) if path in matching[i]} for path in paths}

    def python_hits(self, h: support.Harness, rel: str, data: bytes) -> "set[str]":
        ctx = h.new_context(rel, data=data)
        before = len(h.verdict.log)
        python_lang.scan(ctx)
        return {e[2] for e in h.verdict.log[before:] if e[0] in ("warn", "fail")} - {MISSING}

    def test_every_row_sample_equals_greps_decision(self):
        h = context(self, b"", verdict="fake")
        samples = [text for positives, near in ROW_CASES.values() for text in positives + near]
        paths = [self.sample("row%03d.py" % number, lines(text)) for number, text in enumerate(samples)]
        expected = self.bash_hits(paths)
        for text, path in zip(samples, paths):
            with self.subTest(text=text):
                self.assertEqual(self.python_hits(h, "row.py", lines(text)), expected[path])

    def test_the_inventory_has_one_pattern_per_row(self):
        self.assertEqual(len(self.patterns), len(ROW_MESSAGES))

    def test_random_files_without_a_nul_byte_equal_greps_decision(self):
        """300 files of 1 to 14 lines drawn from every positive, every near miss and junk, in random order, LF or CRLF."""
        rng = random.Random(20261114)
        pool = [text for positives, near in ROW_CASES.values() for text in positives + near]
        pool += ["", "x = 1", "# comment", "def f(): pass", "  ", "import os", "return a + b", "-" * 30, "\tassert is_admin\t", "eval(", ")"]
        samples = []
        for number in range(300):
            picked = [rng.choice(pool) for _ in range(rng.randint(1, 14))]
            sep = rng.choice(["\n", "\n", "\r\n"])
            samples.append((sep.join(picked) + rng.choice(["", sep])).encode("utf-8"))
        paths = [self.sample("rand%03d.py" % n, data) for n, data in enumerate(samples)]
        expected = self.bash_hits(paths)
        h = context(self, b"", verdict="fake")
        mismatches = []
        for number, (data, path) in enumerate(zip(samples, paths)):
            got = self.python_hits(h, "rand.py", data)
            if got != expected[path]:
                mismatches.append((number, sorted(expected[path] ^ got)))
        self.assertEqual(mismatches, [])

    def test_the_fixture_corpus_equals_grep_file_by_file(self):
        """Every python-looking file under tests/fixtures (rules, clean, vulnerable, allowlisted, ignored): equal to bash where there is no NUL byte."""
        paths = sorted(p for p in FIXTURES.rglob("*") if p.is_file() and (p.suffix.lower() == ".py" or p.name == "entrypoint"))
        self.assertGreaterEqual(len(paths), 8)
        expected = self.bash_hits([str(p) for p in paths])
        h = context(self, b"", verdict="fake")
        for path in paths:
            with self.subTest(path=str(path.relative_to(FIXTURES))):
                data = path.read_bytes()
                if b"\0" in data:
                    continue
                self.assertEqual(self.python_hits(h, path.name, data), expected[str(path)])

    def test_this_repositorys_own_python_sources_equal_grep_file_by_file(self):
        """Real Python: the engine, its tests, the build scripts and the helper programs of this repository (a few hundred rule hits and misses)."""
        paths = sorted(set(ROOT.glob("*.py")) | set(ROOT.glob("transit/**/*.py")) | set(ROOT.glob("tests/**/*.py")))
        paths = [p for p in paths if "__pycache__" not in p.parts and p.stat().st_size < 4_000_000]
        self.assertGreaterEqual(len(paths), 50)
        expected = self.bash_hits([str(p) for p in paths])
        h = context(self, b"", verdict="fake")
        problems = []
        for path in paths:
            data = path.read_bytes()
            got = self.python_hits(h, "src.py", data)
            if b"\0" not in data and got != expected[str(path)]:
                problems.append((str(path.relative_to(ROOT)), sorted(got ^ expected[str(path)])))
        self.assertEqual(problems, [])
        self.assertGreaterEqual(len([p for p in paths if expected[str(p)]]), 5)          # the corpus does contain hits, so equality means something

    def test_the_python_standard_library_of_this_host_equals_grep_file_by_file(self):
        """Real-world Python: up to 700 files of the interpreter's own library (``eval``, ``exec``, ``pickle``, ``os.system``, SQL, redirects)."""
        stdlib = sysconfig.get_paths()["stdlib"]
        paths = []
        for dirpath, dirnames, filenames in os.walk(stdlib, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            paths.extend(os.path.join(dirpath, n) for n in sorted(filenames) if n.endswith(".py"))
        paths = [p for p in paths[:700] if os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) < 4_000_000]
        if len(paths) < 50:
            self.skipTest("no Python standard library on this host")
        expected = self.bash_hits(paths)
        h = context(self, b"", verdict="fake")
        problems = []
        for path in paths:
            with open(path, "rb") as handle:
                data = handle.read()
            got = self.python_hits(h, "lib.py", data)
            if b"\0" not in data and got != expected[path]:
                problems.append((path, sorted(got ^ expected[path])))
        self.assertEqual(problems, [])
        hit_rows = set().union(*(expected[p] for p in paths))
        self.assertGreaterEqual(len(hit_rows), 4, hit_rows)               # the corpus exercises most rows, so equality means something

    def test_nul_files_ours_contains_bashs_findings_except_the_line_anchored_row(self):
        """On a file with a NUL byte bash reads the NUL as a line end (``grep`` without ``-a``), the table is searched as text: what bash finds
        by a match that SPANS the NUL we find too, and a row anchored at the line start is the one bash can find after a NUL and we cannot."""
        rng = random.Random(7)
        pool = [text for positives, near in ROW_CASES.values() for text in positives + near]
        samples = []
        for _ in range(200):
            picked = [rng.choice(pool) for _ in range(rng.randint(1, 8))]
            raw = ("\n".join(picked) + "\n").encode("utf-8")
            cut = rng.randrange(len(raw) + 1)
            samples.append(raw[:cut] + b"\0" + raw[cut:])
        paths = [self.sample("nul%03d.py" % n, data) for n, data in enumerate(samples)]
        expected = self.bash_hits(paths)
        h = context(self, b"", verdict="fake")
        problems = []
        for data, path in zip(samples, paths):
            got = self.python_hits(h, "nul.py", data)
            if not expected[path] <= got | {ASSERT}:
                problems.append((data, sorted(expected[path] - got)))
        self.assertEqual(problems, [])

    def test_known_difference_a_match_that_spans_a_nul_byte_is_ours_and_not_bashs(self):
        """``[^,)]+`` and ``[^"]*`` run across a NUL byte under ``grep -a``; bash cuts the line at the NUL and finds nothing (fail closed here)."""
        h = context(self, b"", verdict="fake")
        for data, message in ((b"yaml.load(f\0)y\n", PICKLE), (b'execute("a\0" + b)\n', SQL)):
            path = self.sample("span.py", data)
            with self.subTest(data):
                self.assertNotIn(message, self.bash_hits([path])[path])
                self.assertIn(message, self.python_hits(h, "span.py", data))

    def test_a_nul_byte_between_the_words_of_a_pattern_is_nobodys_match(self):
        """``\\s*`` does not match a NUL: ``os.system<NUL>(x)`` is a finding for neither bash nor us."""
        h = context(self, b"", verdict="fake")
        data = b"os.system\0(x)\n"
        path = self.sample("between.py", data)
        self.assertEqual(self.bash_hits([path])[path], set())
        self.assertEqual(self.python_hits(h, "between.py", data), set())

    def test_known_difference_a_nul_byte_starts_a_line_for_bash_only(self):
        """Pinned, not endorsed: the ``^``-anchored assert row is found by bash after a NUL (a NUL ends a line) and not by the ``grep -a`` view.
        A Python source file cannot hold a NUL byte, so no running program is hidden by this; the fix, if wanted, is central (rules)."""
        h = context(self, b"", verdict="fake")
        data = b"x\0assert is_admin\n"
        path = self.sample("anchored.py", data)
        self.assertEqual(self.bash_hits([path])[path], {ASSERT})
        self.assertEqual(self.python_hits(h, "anchored.py", data), set())


class GoldenTests(unittest.TestCase):
    """The bash engine's own reports (tests/conformance/golden): for every file routed to this scanner, the messages of THIS scanner equal the ones ``scan`` records."""

    OURS = set(ROW_MESSAGES) | {MISSING}

    def routed_to_python(self, view) -> bool:
        seen: "list[str]" = []
        dispatch.classify_file(view, lambda scanner_id, sniffed: seen.append(scanner_id) or True)
        if seen == ["unknown"]:
            return dispatch.shebang_scanner(view.first_line(), first_word_only=True) == "python"
        return seen == ["python"]

    def compare(self, golden_name: str, corpus: Path) -> int:
        golden = json.loads((GOLDEN / golden_name).read_text(encoding="utf-8"))["report"]["file_results"]
        compared = 0
        for rel, entry in sorted(golden.items()):
            path = corpus / rel
            if rel == "__global__" or not path.is_file():
                continue
            h = context(self, path.read_bytes(), rel=rel, verdict="fake")
            if not self.routed_to_python(h.ctx.view):
                continue
            expected = {re.sub(r"^\[(WARN|FAIL)\] ", "", m) for m in entry["messages"]} & self.OURS
            python_lang.scan(h.ctx)
            got = {e[2] for e in h.verdict.log if e[0] in ("warn", "fail")}
            self.assertEqual(got, expected, rel)
            compared += 1
        return compared

    def test_the_rules_corpus(self):
        self.assertGreaterEqual(self.compare("rules_corpus.json", RULE_FIXTURES), 7)

    def test_the_vulnerable_repository(self):
        self.assertEqual(self.compare("vulnerable.json", FIXTURES / "vulnerable"), 1)

    def test_the_clean_repository(self):
        self.assertEqual(self.compare("clean.json", FIXTURES / "clean"), 1)


if __name__ == "__main__":
    unittest.main()
