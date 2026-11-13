"""Tests of transit/scanners/__init__.py (WP-05): the registry, ``ScanContext``, ``invoke`` and ``guard``, and of tests/engine/support.py
(which every scanner package imports). Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_scanners.py"

The registry is exercised with fake scanner modules (injected into ``sys.modules`` and a patched ``pkgutil.iter_modules``, so nothing is
written to the package) and once against the real package. ``ScanContext`` runs over the REAL ``Verdict`` (WP-02), ``FileView`` (WP-03) and
rule machinery (WP-04), with a fake tool locator and fake wrappers (WP-06 is not needed). A token-shaped credential is never written
contiguously in this file.
"""
from __future__ import annotations

import importlib
import json
import os
import pkgutil
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import build_pdf_filetypes  # noqa: E402
from tests.engine import support  # noqa: E402
from transit import rules, rx, scanners  # noqa: E402
from transit.files import FileReadError  # noqa: E402
from transit.findings import Allowlist, parse_allowlist  # noqa: E402
from transit.rules import AllOf, Match, Matcher, Not, RuleRun, RuleSet, RuleSpec, ScanBudgetExceeded  # noqa: E402
from transit.scanners import (KNOWN_SCANNERS, FileToolRun, Registry, RuleOutcome, ScanContext, ScannerSpec, guard,  # noqa: E402
                              invoke, load_registry)
from transit.tools import Record, ToolOutcome  # noqa: E402
from transit.verdict import GLOBAL_FILE, Outcome  # noqa: E402

L5 = "L5_per_language_sast"

# Rule tables are built at import, like a scanner module's (a Match that no RuleSet or Matcher registered cannot be evaluated).
RULES = RuleSet("test_scanners", (
    RuleSpec(id="test_scanners/01-fail", outcome="fail", message="CWE-78:OS_command_injection_risk", cond=Match(r"os\.system"), source="t"),
    RuleSpec(id="test_scanners/02-warn", outcome="warn", message="CWE-601:potential_open_redirect", cond=Match(r"redirect\("), source="t"),
    RuleSpec(id="test_scanners/03-fail", outcome="fail", message="CWE-95:dynamic_code_execution_eval", cond=Match(r"eval\("), source="t"),
    RuleSpec(id="test_scanners/04-low", outcome="fail", message="CWE-327:a_row_that_says_low", severity="LOW", cond=Match("lowrule"),
             source="t"),
))
ALPHA = Matcher("test_scanners/alpha", Match("alpha"))
BETA = Matcher("test_scanners/beta", Match("beta"))
ALPHA_NOT_BETA = AllOf((ALPHA.match, Not(BETA.match)))
FLAT = Matcher("test_scanners/flat", Match("alpha beta", mode="flat"))


def spec(scanner_id: str, fn, *, ported: bool = True, family: "str | None" = None) -> ScannerSpec:
    return ScannerSpec(id=scanner_id, family=family or KNOWN_SCANNERS[scanner_id], fn=fn, bash_function="scan_x", ported=ported)


def passing(ctx: ScanContext) -> bool:
    ctx.record_pass()
    return True


class Stop(BaseException):
    """Stands for the private signal exception of ``pipeline`` (a ``BaseException`` that is not ``SystemExit``)."""


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class SupportTests(unittest.TestCase):
    """tests/engine/support.py is shared by every scanner package: it has to work."""

    def test_temp_repo_writes_views_and_cleans_up(self) -> None:
        repo = support.TempRepo({"a/b.txt": "hello", "c.bin": b"\0\1"})
        root = repo.path
        self.assertTrue(os.path.isdir(root))
        self.assertEqual(repo.view("a/b.txt").data(), b"hello")
        self.assertEqual(repo.recorded("a/b.txt"), root + "/a/b.txt")
        repo.symlink("l", "a/b.txt")
        self.assertTrue(os.path.islink(root + "/l"))
        repo.cleanup()
        self.assertFalse(os.path.exists(root))

    def test_temp_repo_takes_a_name_that_is_not_utf8(self) -> None:
        repo = support.TempRepo()
        self.addCleanup(repo.cleanup)
        name = os.fsdecode(b"bad\xff.txt")
        repo.write(name, b"x")
        self.assertEqual(repo.view(name).data(), b"x")

    def test_stub_tools_run_log_and_hide_the_host(self) -> None:
        with support.StubTools({"bandit": {"stdout": "it's out", "stderr": "err", "exit_code": 3}}, record_env=("DO_NOT_TRACK",)) as stubs:
            env = stubs.environ({"DO_NOT_TRACK": "1"})
            self.assertEqual(env["PATH"], stubs.dir)
            proc = subprocess.run([os.path.join(stubs.dir, "bandit"), "-q", "a b", "", "x\ny"], capture_output=True, env=env, check=False)
            self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (3, b"it's out", b"err"))
            self.assertEqual(stubs.calls("bandit"), [["-q", "a b", "", "x\ny"]])
            self.assertEqual(stubs.env("bandit"), {"DO_NOT_TRACK": "1"})
            self.assertEqual(stubs.calls("nothing"), [])
            with self.assertRaises(ValueError):
                stubs.add("a/b")
            path = stubs.dir
        self.assertFalse(os.path.exists(path))

    def test_stub_tool_with_a_script_still_logs_its_arguments(self) -> None:
        with support.StubTools() as stubs:
            stubs.add("file", script="printf 'text/plain'; exit 0")
            proc = subprocess.run([os.path.join(stubs.dir, "file"), "--mime-type", "-b", "x"], capture_output=True, env=stubs.environ(), check=False)
            self.assertEqual(proc.stdout, b"text/plain")
            self.assertEqual(stubs.calls("file"), [["--mime-type", "-b", "x"]])

    def test_fake_locator_and_wrappers(self) -> None:
        locator = support.FakeLocator({"bandit": "/opt/bin/bandit"})
        self.assertEqual(locator.find("bandit").path, "/opt/bin/bandit")
        self.assertIsNone(locator.find("shellcheck"))
        self.assertEqual(locator.asked, ["bandit", "shellcheck"])
        with self.assertRaises(ValueError):
            locator.find("a/b")
        wrapper = support.StubWrapper("bandit")
        wrappers = support.FakeWrappers(wrapper)
        self.assertIs(wrappers.get("bandit"), wrapper)
        self.assertIsNone(wrappers.get("shellcheck"))
        self.assertEqual(wrapper.layer, L5)

    def test_fake_verdict_records_and_counts(self) -> None:
        v = support.FakeVerdict(outcomes=[Outcome.ALLOWED])
        v.record_pass("/s/a")
        v.record_warn("/s/a", "w")
        self.assertEqual(v.record_fail("/s/a", "f1"), Outcome.ALLOWED)
        self.assertEqual(v.record_fail("/s/a", "f2", severity="LOW", downgradable=False), Outcome.FAILED)
        self.assertTrue(v.record_warn_once("k", None, "once"))
        self.assertFalse(v.record_warn_once("k", None, "once"))
        v.note_incomplete(L5, "r")
        self.assertEqual(v.events, 5)
        self.assertEqual(v.messages("fail"), ["f1", "f2"])
        self.assertEqual(v.of("incomplete"), [("incomplete", L5, "r")])
        self.assertEqual(v.log[3], ("fail", "/s/a", "f2", "LOW", False))
        self.assertEqual(v.log[4], ("warn", GLOBAL_FILE, "once"))

    def test_make_context_builds_a_real_context_and_cleans_up(self) -> None:
        h = support.make_context(None, "src/app.py", b"x = 1\n")
        root = h.repo.path
        self.assertEqual((h.ctx.rel, h.ctx.basename, h.ctx.ext, h.ctx.path), ("src/app.py", "app.py", "py", root + "/src/app.py"))
        self.assertIsInstance(h.ctx, ScanContext)
        h.ctx.record_warn("w")
        self.assertEqual(h.messages(), [("WARN", "w")])
        self.assertEqual(h.status(), "WARN")
        other = h.new_context("src/b.py", data=b"y")
        self.assertEqual(other.path, root + "/src/b.py")
        h.close()
        self.assertFalse(os.path.exists(root))

    def test_make_context_with_a_fake_verdict_and_a_test_cleanup(self) -> None:
        holder = {}

        class Inner(unittest.TestCase):
            def runTest(self) -> None:
                holder["h"] = support.make_context(self, "a.txt", b"", verdict="fake")

        inner = Inner()
        result = unittest.TestResult()
        inner.run(result)
        h = holder["h"]
        self.assertIsInstance(h.verdict, support.FakeVerdict)
        self.assertFalse(os.path.exists(h.repo.path))                  # addCleanup ran
        self.assertTrue(result.wasSuccessful())

    def test_make_registry_uses_the_family_of_the_known_scanners(self) -> None:
        reg = support.make_registry({"python": passing, "powershell.xml": passing})
        self.assertEqual(reg.get("powershell.xml").family, "powershell")
        self.assertTrue(reg.get("python").ported)
        self.assertEqual(support.make_registry({"python": passing}, ported=False).get("python").ported, False)

    def test_parse_file_message(self) -> None:
        self.assertEqual(support.parse_file_message("[WARN] a | [FAIL] b | "), [("WARN", "a"), ("FAIL", "b")])
        self.assertEqual(support.parse_file_message(""), [])

    def test_default_policy_is_the_hardened_one(self) -> None:
        policy = support.default_policy()
        self.assertFalse(policy.excl_nul_blind)
        self.assertEqual(policy.long_line_bytes, 8192)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class KnownScannersTests(unittest.TestCase):
    def test_the_37_ids_and_the_34_families(self) -> None:
        self.assertEqual(len(KNOWN_SCANNERS), 37)
        families = {f["key"] for f in build_pdf_filetypes.FAMILIES}
        self.assertEqual(len(families), 34)
        self.assertEqual(set(KNOWN_SCANNERS.values()), families | {"unknown"})
        self.assertEqual(scanners.PSEUDO_FAMILIES, frozenset({"unknown"}))
        self.assertEqual(scanners.SCRIPT_MODULES, frozenset({"manifests"}))
        for two in ("manifest", "powershell"):
            self.assertEqual(sorted(i for i, f in KNOWN_SCANNERS.items() if f == two).__len__(), 2)


class RegistryTests(unittest.TestCase):
    def _load(self, modules: "dict[str, object]", names: "list[str] | None" = None, *, listed: "list[str] | None" = None):
        """``load_registry`` over fake modules: ``modules`` maps a short name to a module object or an exception to raise at import."""
        imported: "list[str]" = []
        real_import = importlib.import_module

        def fake_import(name: str, package=None):
            imported.append(name)
            short = name.rpartition(".")[2]
            if name.startswith("transit.scanners.") and short in modules:
                entry = modules[short]
                if isinstance(entry, BaseException):
                    raise entry
                return entry
            return real_import(name, package)

        def fake_iter(path=None, prefix=""):
            return [pkgutil.ModuleInfo(None, n, False) for n in (listed if listed is not None else sorted(modules))]

        with mock.patch.object(importlib, "import_module", side_effect=fake_import), mock.patch.object(pkgutil, "iter_modules", side_effect=fake_iter):
            registry = load_registry(names)
        return registry, imported

    @staticmethod
    def module(*specs, **attrs) -> types.ModuleType:
        mod = types.ModuleType("fake")
        mod.SCANNERS = tuple(specs)
        for key, value in attrs.items():
            setattr(mod, key, value)
        return mod

    def test_get_and_unported(self) -> None:
        reg = support.make_registry({"python": passing, "shell": passing}, ported=True)
        self.assertEqual(reg.get("python").id, "python")
        self.assertIsNone(reg.get("jar"))
        self.assertEqual(reg.unported(), tuple(sorted(set(KNOWN_SCANNERS) - {"python", "shell"})))
        part = support.make_registry({"python": spec("python", passing, ported=False), "shell": passing})
        self.assertIn("python", part.unported())
        self.assertNotIn("shell", part.unported())
        everything = support.make_registry({i: passing for i in KNOWN_SCANNERS})
        self.assertEqual(everything.unported(), ())
        self.assertEqual(Registry(specs={}).unported(), tuple(sorted(KNOWN_SCANNERS)))

    def test_discovery_collects_every_spec_and_sorts_nothing_away(self) -> None:
        a = self.module(spec("python", passing), spec("shell", passing))
        b = self.module(spec("jar", passing, ported=False))
        reg, imported = self._load({"fake_a": a, "fake_b": b})
        self.assertEqual(sorted(reg.specs), ["jar", "python", "shell"])
        self.assertEqual(reg.load_errors, ())
        self.assertFalse(reg.get("jar").ported)
        self.assertEqual(imported, ["transit.scanners.fake_a", "transit.scanners.fake_b"])
        with self.assertRaises(TypeError):
            reg.specs["x"] = None                                   # the mapping is read-only

    def test_discovery_skips_the_helper_program_and_private_modules(self) -> None:
        ok = self.module(spec("python", passing))
        reg, imported = self._load({"fake_ok": ok}, listed=["fake_ok", "manifests", "_x", "_private", "fake_missing"])
        self.assertNotIn("transit.scanners.manifests", imported)
        self.assertNotIn("transit.scanners._x", imported)
        self.assertNotIn("transit.scanners._private", imported)
        self.assertEqual(imported, ["transit.scanners.fake_missing", "transit.scanners.fake_ok"])
        self.assertEqual(list(reg.specs), ["python"])
        self.assertEqual(reg.load_errors, ("fake_missing:ModuleNotFoundError",))

    def test_the_helper_program_is_never_imported_even_when_asked_for(self) -> None:
        reg, imported = self._load({}, names=["manifests", "_x"])
        self.assertEqual(imported, [])
        self.assertEqual(reg.load_errors, ())

    def test_explicit_module_names_replace_discovery(self) -> None:
        ok = self.module(spec("python", passing))
        other = self.module(spec("shell", passing))
        reg, imported = self._load({"fake_ok": ok, "fake_other": other}, names=["fake_ok"])
        self.assertEqual(imported, ["transit.scanners.fake_ok"])
        self.assertEqual(list(reg.specs), ["python"])

    def test_a_module_without_scanners_is_a_helper_and_is_ignored(self) -> None:
        helper = types.ModuleType("helper")
        reg, _ = self._load({"fake_helper": helper})
        self.assertEqual((dict(reg.specs), reg.load_errors), ({}, ()))

    def test_an_unknown_id_is_a_load_error_and_the_whole_module_is_refused(self) -> None:
        bad = self.module(spec("python", passing), ScannerSpec(id="frobnicate", family="python", fn=passing, bash_function="x"))
        reg, _ = self._load({"fake_bad": bad, "fake_good": self.module(spec("shell", passing))})
        self.assertEqual(reg.load_errors, ("fake_bad:unknown_scanner_id",))
        self.assertEqual(list(reg.specs), ["shell"])                 # the ids the bad module would have served are not registered
        self.assertIn("python", reg.unported())

    def test_a_family_that_does_not_match_is_a_load_error(self) -> None:
        reg, _ = self._load({"fake_bad": self.module(ScannerSpec(id="python", family="js", fn=passing, bash_function="x"))})
        self.assertEqual(reg.load_errors, ("fake_bad:family_mismatch",))
        self.assertEqual(dict(reg.specs), {})

    def test_a_duplicate_id_is_a_load_error_inside_a_module_and_across_modules(self) -> None:
        inside = self.module(spec("python", passing), spec("python", passing))
        reg, _ = self._load({"fake_inside": inside})
        self.assertEqual(reg.load_errors, ("fake_inside:duplicate_scanner_id",))
        self.assertEqual(dict(reg.specs), {})
        first, second = self.module(spec("python", passing)), self.module(spec("python", passing), spec("shell", passing))
        reg, _ = self._load({"fake_1": first, "fake_2": second})
        self.assertEqual(reg.load_errors, ("fake_2:duplicate_scanner_id",))
        self.assertEqual(list(reg.specs), ["python"])               # the earlier module keeps its id; the later one is refused whole

    def test_an_import_failure_is_a_load_error_and_never_fatal(self) -> None:
        reg, _ = self._load({"fake_value": ValueError("boom with a path /etc/passwd"), "fake_exit": SystemExit(0),
                             "fake_import": ImportError("nope"), "fake_ok": self.module(spec("python", passing))})
        self.assertEqual(reg.load_errors, ("fake_exit:SystemExit", "fake_import:ImportError", "fake_value:ValueError"))
        self.assertEqual(list(reg.specs), ["python"])
        self.assertNotIn("passwd", " ".join(reg.load_errors))        # the message of the exception is never kept

    def test_a_scanners_attribute_that_is_not_a_tuple_of_specs_is_a_load_error(self) -> None:
        for bad in ("python", (object(),), [spec("python", passing)], (spec("python", passing), None), 5):
            mod = types.ModuleType("fake")
            mod.SCANNERS = bad
            reg, _ = self._load({"fake_bad": mod})
            self.assertEqual(reg.load_errors, ("fake_bad:invalid_SCANNERS",), repr(bad))
            self.assertEqual(dict(reg.specs), {})
        notcallable = self.module(ScannerSpec(id="python", family="python", fn=None, bash_function="x"))
        reg, _ = self._load({"fake_nc": notcallable})
        self.assertEqual(reg.load_errors, ("fake_nc:invalid_SCANNERS",))

    def test_the_real_package_loads_without_importing_the_helper_program(self) -> None:
        seen: "list[str]" = []
        real_import = importlib.import_module

        def spy(name: str, package=None):
            seen.append(name)
            return real_import(name, package)

        had = "transit.scanners.manifests" in sys.modules
        with mock.patch.object(importlib, "import_module", side_effect=spy):
            reg = load_registry()
        self.assertFalse([n for n in seen if n.endswith(".manifests")], seen)
        self.assertEqual("transit.scanners.manifests" in sys.modules, had)
        self.assertTrue(set(reg.specs) <= set(KNOWN_SCANNERS))
        self.assertFalse([e for e in reg.load_errors if e.startswith("manifests")])
        self.assertIsInstance(reg, Registry)
        for scanner_id, entry in reg.specs.items():
            self.assertEqual(entry.id, scanner_id)
            self.assertEqual(entry.family, KNOWN_SCANNERS[scanner_id])

    def test_importing_the_package_has_no_side_effect(self) -> None:
        code = ("import sys\nsys.path.insert(0, %r)\nimport transit.scanners\n" % str(ROOT) +
                "print(sorted(m for m in sys.modules if m.startswith('transit.scanners.')))\n"
                "print('transit.layers' in sys.modules, 'transit.dispatch' in sys.modules, 'transit.pipeline' in sys.modules)\n")
        proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "")},
                              check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, "")
        self.assertEqual(proc.stdout.split("\n")[:2], ["[]", "False False False"])

    def test_dispatch_imports_no_scanner_and_no_registry(self) -> None:
        code = "import sys\nsys.path.insert(0, %r)\nimport transit.dispatch\nprint('transit.scanners' in sys.modules)\n" % str(ROOT)
        proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "")},
                              check=False)
        self.assertEqual((proc.returncode, proc.stdout.strip(), proc.stderr), (0, "False", ""))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ContextIdentityTests(unittest.TestCase):
    def test_identity_properties(self) -> None:
        h = support.make_context(self, "sub/dir/Run.PY", b"x", sniffed=True)
        ctx = h.ctx
        self.assertEqual((ctx.rel, ctx.basename, ctx.ext), ("sub/dir/Run.PY", "Run.PY", "py"))
        self.assertEqual(ctx.path, h.repo.path + "/sub/dir/Run.PY")
        self.assertTrue(ctx.sniffed)
        self.assertIs(ctx.view.rel, ctx.rel)
        self.assertIs(ctx.cfg, h.cfg)
        self.assertIs(ctx.temp, h.temp)
        self.assertFalse(support.make_context(self).ctx.sniffed)

    def test_target_is_the_views(self) -> None:
        h = support.make_context(self, "x.py", b"alpha\n")
        target = h.ctx.target()
        self.assertEqual((target.data, target.basename, target.ext), (b"alpha\n", "x.py", "py"))
        derived = h.ctx.target(b"derived")
        self.assertEqual((derived.data, derived.basename, derived.ext), (b"derived", "x.py", "py"))


class RecordingTests(unittest.TestCase):
    def test_every_record_call_is_forwarded_for_this_file(self) -> None:
        h = support.make_context(self, "a.py", b"", verdict="fake")
        v, p = h.verdict, h.ctx.path
        h.ctx.record_pass()
        h.ctx.record_warn("w")
        h.ctx.record_warn("w2", file="/other")
        self.assertEqual(h.ctx.record_fail("f"), Outcome.FAILED)
        h.ctx.record_fail("f2", file="/other", severity="LOW", downgradable=False)
        h.ctx.note_incomplete("r")
        h.ctx.note_incomplete("r2", layer="L4_patterns")
        self.assertEqual(v.log, [("pass", p), ("warn", p, "w"), ("warn", "/other", "w2"), ("fail", p, "f", None, True),
                                 ("fail", "/other", "f2", "LOW", False), ("incomplete", L5, "r"), ("incomplete", "L4_patterns", "r2")])

    def test_record_fail_returns_what_the_verdict_decided(self) -> None:
        h = support.make_context(self, "a.py", b"")
        allow = Allowlist({("CWE-78", "a.py"): "fixture"})
        h2 = support.make_context(self, "a.py", b"", allowlist=allow)
        self.assertEqual(h.ctx.record_fail("CWE-78:OS_command_injection_risk"), Outcome.FAILED)
        self.assertEqual(h2.ctx.record_fail("CWE-78:OS_command_injection_risk"), Outcome.ALLOWED)
        self.assertEqual(h2.messages(), [("WARN", "ALLOWED:CWE-78:OS_command_injection_risk (reason: fixture)")])

    def test_finish_records_a_pass_unless_a_rule_fired(self) -> None:
        h = support.make_context(self, "a.py", b"", verdict="fake")
        h.ctx.finish(True)
        self.assertEqual(h.verdict.log, [])
        h.ctx.finish(False)
        self.assertEqual(h.verdict.log, [("pass", h.ctx.path)])

    def test_the_first_event_decides_the_status_like_bash(self) -> None:
        h = support.make_context(self, "a.py", b"")
        h.ctx.record_warn("bandit missing")
        h.ctx.finish(False)
        self.assertEqual(h.status(), "WARN")                          # first writer: the PASS does not clear the WARN
        self.assertEqual(h.snapshot().counters.pass_, 1)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RunRulesTests(unittest.TestCase):
    ALL = b"os.system(x)\nredirect(y)\neval(z)\n"

    def test_hits_are_recorded_in_table_order_with_the_right_kind(self) -> None:
        h = support.make_context(self, "a.py", self.ALL)
        out = h.ctx.run_rules(RULES)
        self.assertIsInstance(out, RuleOutcome)
        self.assertEqual(h.messages(), [("FAIL", "CWE-78:OS_command_injection_risk"), ("WARN", "CWE-601:potential_open_redirect"),
                                        ("FAIL", "CWE-95:dynamic_code_execution_eval")])
        self.assertTrue(out.fired)
        self.assertFalse(out.incomplete)
        self.assertEqual(out.outcomes, (("test_scanners/01-fail", Outcome.FAILED), ("test_scanners/03-fail", Outcome.FAILED)))
        self.assertEqual(h.status(), "FAIL")
        self.assertEqual(h.verdict.verdict, "FAIL")

    def test_a_clean_file_records_nothing_and_finish_passes_it(self) -> None:
        h = support.make_context(self, "a.py", b"print('hi')\n")
        out = h.ctx.run_rules(RULES)
        self.assertEqual((out.fired, out.outcomes, out.incomplete), (False, (), False))
        self.assertEqual(h.messages(), [])
        h.ctx.finish(out.fired)
        self.assertEqual((h.status(), h.snapshot().counters.pass_), ("PASS", 1))

    def test_a_warn_rule_alone_does_not_fire(self) -> None:
        h = support.make_context(self, "a.py", b"redirect(y)\n")
        out = h.ctx.run_rules(RULES)
        self.assertFalse(out.fired)
        self.assertEqual(out.outcomes, ())
        self.assertEqual(h.messages(), [("WARN", "CWE-601:potential_open_redirect")])

    def test_fired_stays_true_when_the_allowlist_downgrades_the_fail(self) -> None:
        h = support.make_context(self, "a.py", b"os.system(x)\n", allowlist=Allowlist({("CWE-78", "a.py"): "test fixture"}))
        out = h.ctx.run_rules(RULES)
        self.assertTrue(out.fired)
        self.assertEqual(out.outcomes, (("test_scanners/01-fail", Outcome.ALLOWED),))
        self.assertEqual(h.messages(), [("WARN", "ALLOWED:CWE-78:OS_command_injection_risk (reason: test fixture)")])
        h.ctx.finish(out.fired)
        self.assertEqual(h.snapshot().counters.pass_, 0)              # no PASS for a file whose rule fired
        self.assertEqual(h.verdict.verdict, "PASS")

    def test_the_row_severity_is_what_the_threshold_sees(self) -> None:
        h = support.make_context(self, "a.py", b"lowrule\n")
        out = h.ctx.run_rules(RULES)
        self.assertTrue(out.fired)
        self.assertEqual(out.outcomes, (("test_scanners/04-low", Outcome.LOW_SEV),))
        self.assertEqual(h.messages(), [("WARN", "LOW_SEV(below --min-severity high):CWE-327:a_row_that_says_low")])

    def test_data_is_a_derived_view(self) -> None:
        h = support.make_context(self, "a.py", b"eval(z)\n")
        out = h.ctx.run_rules(RULES, data=b"clean derived text\n")
        self.assertFalse(out.fired)
        self.assertEqual(h.messages(), [])
        out = h.ctx.run_rules(RULES, data=b"os.system(x)\n")
        self.assertEqual(out.outcomes, (("test_scanners/01-fail", Outcome.FAILED),))

    def test_a_passed_deadline_is_a_fail_once_not_a_warn(self) -> None:
        h = support.make_context(self, "a.py", self.ALL, deadline=time.monotonic() - 1.0, threshold=4)
        out = h.ctx.run_rules(RULES)
        self.assertTrue(out.incomplete)
        self.assertFalse(out.fired)
        self.assertEqual(h.messages(), [("FAIL", "engine:scan_incomplete:test_scanners:time_budget")])
        self.assertEqual(h.status(), "FAIL")
        self.assertEqual(h.verdict.verdict, "FAIL")
        self.assertEqual(h.snapshot().coverage[L5], "partial:per-file time budget reached")
        self.assertEqual(h.snapshot().findings[0].tool, "engine")

    def test_the_time_budget_fail_cannot_be_allowlisted_or_lowered(self) -> None:
        allow = Allowlist({("engine", "a.py"): "x", ("scan_incomplete", "a.py"): "x"})
        h = support.make_context(self, "a.py", self.ALL, deadline=time.monotonic() - 1.0, allowlist=allow, threshold=4)
        h.ctx.run_rules(RULES)
        self.assertEqual(h.messages(), [("FAIL", "engine:scan_incomplete:test_scanners:time_budget")])

    def test_a_rule_that_timed_out_without_a_linear_matcher_is_a_non_downgradable_fail(self) -> None:
        allow = Allowlist({("engine", "a.py"): "x", ("regex_timeout", "a.py"): "x", ("CWE-78", "a.py"): "x"})
        h = support.make_context(self, "a.py", b"os.system(x)\n", threshold=4, allowlist=allow)
        run = RuleRun(hits=(RULES.rules[0],), skipped=(), timed_out=("test_scanners/03-fail",))
        with mock.patch.object(rules, "run_ruleset", return_value=run):
            out = h.ctx.run_rules(RULES)
        self.assertTrue(out.incomplete)
        self.assertTrue(out.fired)
        self.assertEqual(h.messages(), [("WARN", "ALLOWED:CWE-78:OS_command_injection_risk (reason: x)"),
                                        ("FAIL", "engine:regex_timeout:test_scanners/03-fail")])
        self.assertEqual(h.verdict.verdict, "FAIL")

    def test_skipped_rules_from_the_rule_machinery_give_one_fail(self) -> None:
        h = support.make_context(self, "a.py", b"os.system(x)\n")
        run = RuleRun(hits=(RULES.rules[0],), skipped=("test_scanners/02-warn", "test_scanners/03-fail", "test_scanners/04-low"), timed_out=())
        with mock.patch.object(rules, "run_ruleset", return_value=run) as patched:
            out = h.ctx.run_rules(RULES)
        self.assertEqual(h.messages(), [("FAIL", "CWE-78:OS_command_injection_risk"), ("FAIL", "engine:scan_incomplete:test_scanners:time_budget")])
        self.assertTrue(out.fired and out.incomplete)
        # the table, the file's target, the run's policy and the file's deadline are what the machinery receives
        args, kwargs = patched.call_args
        self.assertIs(args[0], RULES)
        self.assertEqual(args[1].data, b"os.system(x)\n")
        self.assertIs(args[2], h.policy)
        self.assertEqual(kwargs["deadline"], h.deadline)


class SearchAndSpansTests(unittest.TestCase):
    def test_search_evaluates_a_condition_built_from_registered_matches(self) -> None:
        h = support.make_context(self, "a.txt", b"alpha\ngamma\n")
        self.assertTrue(h.ctx.search(ALPHA_NOT_BETA))
        self.assertFalse(h.ctx.search(BETA.match))
        self.assertTrue(h.ctx.search(ALPHA_NOT_BETA, data=b"alpha"))
        self.assertFalse(h.ctx.search(ALPHA_NOT_BETA, data=b"alpha beta"))
        self.assertTrue(h.ctx.search(FLAT.match, data=b"x alpha\nbeta y"))        # flat: the line break is folded

    def test_search_refuses_an_unregistered_match(self) -> None:
        h = support.make_context(self, "a.txt", b"alpha")
        with self.assertRaises(ValueError):
            h.ctx.search(Match("never registered anywhere"))

    def test_search_and_spans_stop_at_the_deadline(self) -> None:
        h = support.make_context(self, "a.txt", b"alpha\n", deadline=time.monotonic() - 1.0)
        with self.assertRaises(ScanBudgetExceeded):
            h.ctx.search(ALPHA.match)
        with self.assertRaises(ScanBudgetExceeded):
            h.ctx.check_deadline()
        live = support.make_context(self, "a.txt", b"alpha\n")
        live.ctx.check_deadline()                                   # not passed: no error

    def test_spans_yield_the_offsets_of_the_matching_lines(self) -> None:
        h = support.make_context(self, "a.txt", b"alpha one\nzzz\nalpha two\n\nalpha")
        self.assertEqual(list(h.ctx.spans(ALPHA)), [(0, 9), (14, 23), (25, 30)])
        self.assertEqual(list(h.ctx.spans(ALPHA, data=b"xx\nalpha")), [(3, 8)])
        self.assertEqual(list(h.ctx.spans(BETA)), [])

    def test_spans_are_lazy_and_check_the_deadline_before_each_item(self) -> None:
        data = b"alpha 1\nalpha 2\nalpha 3\n"
        h = support.make_context(self, "a.txt", data, deadline=5.0)
        ticks: "list[int]" = []

        def clock() -> float:
            ticks.append(1)
            return 0.0 if len(ticks) <= 1 else 10.0

        with mock.patch("time.monotonic", side_effect=clock):
            spans = h.ctx.spans(ALPHA)
            self.assertEqual(ticks, [])                              # nothing is computed until the first item is asked for
            self.assertEqual(next(spans), (0, 7))
            with self.assertRaises(ScanBudgetExceeded):
                next(spans)

    def test_spans_refuse_a_flat_matcher_at_the_call(self) -> None:
        h = support.make_context(self, "a.txt", b"alpha beta")
        with self.assertRaises(ValueError):
            h.ctx.spans(FLAT)                                        # not at the first next(): the call itself


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class FileToolTests(unittest.TestCase):
    def ctx(self, *, found=("bandit", "shellcheck"), wrapper=None, verdict=None, rel="a.py"):
        locator = support.FakeLocator({n: "/opt/bin/" + n for n in found})
        wrappers = support.FakeWrappers(*([wrapper] if wrapper else []))
        h = support.make_context(self, rel, b"import os\n", locator=locator, wrappers=wrappers, verdict=verdict)
        return h, locator

    def test_an_unknown_tool_name_is_a_key_error(self) -> None:
        h, _ = self.ctx()
        with self.assertRaises(KeyError):
            h.ctx.file_tool("nmap")
        with self.assertRaises(KeyError):
            h.ctx.file_tool("gitleaks")                              # a directory tool is not a per-file tool

    def test_missing_is_reported_without_a_word(self) -> None:
        h, locator = self.ctx(found=())
        run = h.ctx.file_tool("bandit")
        self.assertEqual(run, FileToolRun("missing", ()))
        self.assertEqual(locator.asked, ["bandit"])
        self.assertEqual(h.messages(), [])                           # the scanner writes its own `<tool> missing`
        self.assertEqual(h.snapshot().coverage, {})

    def test_the_executable_asked_for_is_the_one_of_file_tools(self) -> None:
        h, locator = self.ctx(found=())
        h.ctx.file_tool("semgrep-js")
        h.ctx.file_tool("file")
        self.assertEqual(locator.asked, ["semgrep", "file"])

    def test_installed_without_a_wrapper_is_not_ported_and_visible(self) -> None:
        h, _ = self.ctx()
        run = h.ctx.file_tool("bandit")
        self.assertEqual(run, FileToolRun("not_ported", ()))
        self.assertEqual(h.messages(GLOBAL_FILE), [("WARN", "engine:tool_not_ported:bandit")])
        self.assertEqual(h.snapshot().coverage[L5], "partial:python engine has not ported bandit yet")
        self.assertEqual(h.messages(), [])                           # nothing on the file itself

    def test_the_not_ported_warn_is_recorded_once_per_run_for_two_files(self) -> None:
        h, _ = self.ctx()
        h.ctx.file_tool("bandit")
        second = h.new_context("b.py", data=b"x")
        self.assertEqual(second.file_tool("bandit").status, "not_ported")
        self.assertEqual(h.messages(GLOBAL_FILE), [("WARN", "engine:tool_not_ported:bandit")])
        self.assertEqual(h.snapshot().counters.warn, 1)
        self.assertEqual(h.snapshot().coverage[L5], "partial:python engine has not ported bandit yet")
        second.file_tool("shellcheck")                               # another tool is another key
        self.assertEqual(h.snapshot().counters.warn, 2)

    def test_the_once_per_run_memory_is_the_verdicts_not_a_module_global(self) -> None:
        for _ in range(2):                                           # two runs in one process: each gets its own WARN
            h, _ = self.ctx()
            h.ctx.file_tool("bandit")
            h.ctx.file_tool("bandit")
            self.assertEqual(h.messages(GLOBAL_FILE), [("WARN", "engine:tool_not_ported:bandit")])
        fake = support.FakeVerdict()
        h, _ = self.ctx(verdict=fake)
        h.ctx.file_tool("bandit")
        self.assertEqual(fake.log, [("warn", GLOBAL_FILE, "engine:tool_not_ported:bandit"), ("incomplete", L5, "python engine has not ported bandit yet")])
        self.assertFalse([n for n in vars(scanners) if "ported" in n.lower() and isinstance(getattr(scanners, n), (set, dict, list))])

    def test_ok_returns_the_records_and_hands_the_wrapper_a_request(self) -> None:
        records = (Record("warn", "", "w"), Record("fail", "", "bandit:Severity: HIGH:B602", "HIGH"))
        wrapper = support.StubWrapper("bandit", ToolOutcome(layer_state=None, records=records))
        h, _ = self.ctx(wrapper=wrapper)
        run = h.ctx.file_tool("bandit")
        self.assertEqual((run.status, run.records), ("ok", records))
        self.assertEqual(len(wrapper.requests), 1)
        request = wrapper.requests[0]
        self.assertEqual(request.target, h.ctx.path)
        self.assertEqual(request.scan_dir, h.repo.path)
        self.assertEqual(request.info.path, "/opt/bin/bandit")
        self.assertIs(request.cfg, h.cfg)
        self.assertIs(request.temp, h.temp)
        self.assertEqual(h.snapshot().coverage, {})                  # a good run notes nothing
        self.assertEqual(h.messages(), [])                           # file_tool does not record: the scanner applies the records

    def test_a_ran_state_is_ok_too(self) -> None:
        wrapper = support.StubWrapper("bandit", ToolOutcome(layer_state="ran"))
        h, _ = self.ctx(wrapper=wrapper)
        self.assertEqual(h.ctx.file_tool("bandit").status, "ok")

    def test_a_wrapper_that_could_not_use_the_tool_is_failed_and_the_layer_is_noted(self) -> None:
        for state, reason in (("skipped:bandit timed out", "bandit timed out"),
                              ("partial:semgrep javascript ruleset not staged for offline use", "semgrep javascript ruleset not staged for offline use"),
                              ("skipped:bandit failed (exit 3)", "bandit failed (exit 3)"), ("failed", "bandit did not complete")):
            records = (Record("warn", "", "bandit unusable"),)
            wrapper = support.StubWrapper("bandit", ToolOutcome(layer_state=state, records=records))
            h, _ = self.ctx(wrapper=wrapper)
            run = h.ctx.file_tool("bandit")
            self.assertEqual((run.status, run.records), ("failed", records), state)
            self.assertEqual(h.snapshot().coverage[L5], "partial:" + reason, state)

    def test_a_timeout_flag_without_a_state_is_still_a_failed_run(self) -> None:
        wrapper = support.StubWrapper("bandit", ToolOutcome(layer_state=None, timed_out=True))
        h, _ = self.ctx(wrapper=wrapper)
        self.assertEqual(h.ctx.file_tool("bandit").status, "failed")
        self.assertEqual(h.snapshot().coverage[L5], "partial:bandit timed out")

    def test_a_wrapper_that_raises_is_not_a_failed_run_the_exception_propagates(self) -> None:
        wrapper = support.StubWrapper("bandit", raises=RuntimeError("wrapper bug"))
        h, _ = self.ctx(wrapper=wrapper)
        with self.assertRaises(RuntimeError):
            h.ctx.file_tool("bandit")
        self.assertEqual(h.snapshot().coverage, {})
        # ... and through invoke it is the file's FAIL
        reg = support.make_registry({"python": lambda ctx: (ctx.file_tool("bandit"), True)[1]})
        h2, _ = self.ctx(wrapper=wrapper)
        ctx = h2.new_context()
        self.assertTrue(invoke(reg, "python", ctx))
        self.assertEqual(h2.messages(), [("FAIL", "engine:scanner_error:python:RuntimeError")])


class ApplyToolRecordsTests(unittest.TestCase):
    def test_a_warn_then_a_fail_are_applied_in_order_and_only_the_fail_counts(self) -> None:
        h = support.make_context(self, "a.py", b"")
        run = FileToolRun("ok", (Record("warn", "", "first"), Record("fail", "", "bandit:Severity: HIGH:B602", "HIGH"), Record("warn", "", "last")))
        self.assertTrue(h.ctx.apply_tool_records(run))
        self.assertEqual(h.messages(), [("WARN", "first"), ("FAIL", "bandit:Severity: HIGH:B602"), ("WARN", "last")])
        self.assertEqual(h.snapshot().findings[0].tool, "bandit")

    def test_warns_alone_return_false(self) -> None:
        h = support.make_context(self, "a.py", b"")
        self.assertFalse(h.ctx.apply_tool_records(FileToolRun("failed", (Record("warn", "", "bandit unusable"),))))
        self.assertEqual(h.messages(), [("WARN", "bandit unusable")])

    def test_missing_and_not_ported_have_no_records_and_return_false(self) -> None:
        h = support.make_context(self, "a.py", b"", verdict="fake")
        self.assertFalse(h.ctx.apply_tool_records(FileToolRun("missing")))
        self.assertFalse(h.ctx.apply_tool_records(FileToolRun("not_ported")))
        self.assertEqual(h.verdict.log, [])

    def test_an_allowlisted_fail_still_counts_as_fired(self) -> None:
        h = support.make_context(self, "a.py", b"", allowlist=Allowlist({("shellcheck", "a.py"): "ok"}))
        self.assertTrue(h.ctx.apply_tool_records(FileToolRun("ok", (Record("fail", "", "shellcheck:warnings"),))))
        self.assertEqual(h.messages(), [("WARN", "ALLOWED:shellcheck:warnings (reason: ok)")])
        h2 = support.make_context(self, "a.py", b"", threshold=4)
        self.assertTrue(h2.ctx.apply_tool_records(FileToolRun("ok", (Record("fail", "", "shellcheck:warnings"),))))   # LOW_SEV downgrade
        self.assertEqual(h2.verdict.verdict, "PASS")

    def test_a_record_names_its_file_or_defaults_to_this_one(self) -> None:
        h = support.make_context(self, "a.py", b"", verdict="fake")
        run = FileToolRun("ok", (Record("warn", "", "w1"), Record("warn", "/s/x", "w2"), Record("fail", GLOBAL_FILE, "f1", "LOW"), Record("fail", "", "f2")))
        h.ctx.apply_tool_records(run)
        self.assertEqual(h.verdict.log, [("warn", h.ctx.path, "w1"), ("warn", "/s/x", "w2"), ("fail", GLOBAL_FILE, "f1", "LOW", True),
                                         ("fail", h.ctx.path, "f2", None, True)])

    def test_a_pass_record_from_a_per_file_wrapper_is_a_bug_and_records_nothing(self) -> None:
        h = support.make_context(self, "a.py", b"", verdict="fake")
        run = FileToolRun("ok", (Record("warn", "", "w"), Record("pass", "", ""), Record("fail", "", "f")))
        with self.assertRaises(ValueError):
            h.ctx.apply_tool_records(run)
        self.assertEqual(h.verdict.log, [])
        with self.assertRaises(ValueError):
            h.ctx.apply_tool_records(FileToolRun("ok", (Record("explode", "", "x"),)))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class InvokeTests(unittest.TestCase):
    def run_one(self, fn, *, ported: bool = True, sniffed: bool = False, scanner_id: str = "python", **make):
        h = support.make_context(self, "a.py", b"x", registry=support.make_registry({scanner_id: spec(scanner_id, fn, ported=ported)}),
                                 sniffed=sniffed, **make)
        result = invoke(h.registry, scanner_id, h.ctx)
        return h, result

    # 1. not ported ----------------------------------------------------------------------------------
    def test_an_id_without_a_spec_is_a_warn_and_a_partial_note_and_handled(self) -> None:
        h = support.make_context(self, "a.py", b"x", registry=support.make_registry({}))
        self.assertTrue(invoke(h.registry, "python", h.ctx))
        self.assertEqual(h.messages(), [("WARN", "engine:scanner_not_ported:python")])
        self.assertEqual(h.snapshot().coverage[L5], "partial:python engine has not ported scanner python yet")
        self.assertEqual(h.verdict.verdict, "PASS")

    def test_a_spec_that_is_not_ported_is_never_called(self) -> None:
        called = []
        h, result = self.run_one(lambda ctx: called.append(1) or True, ported=False)
        self.assertTrue(result)
        self.assertEqual(called, [])
        self.assertEqual(h.messages(), [("WARN", "engine:scanner_not_ported:python")])

    def test_a_sniffed_rtf_that_is_not_ported_is_handled_so_it_is_never_read_as_text(self) -> None:
        h, result = self.run_one(passing, ported=False, sniffed=True, scanner_id="rtf")
        self.assertTrue(result)

    # 2. the scanner is fine ---------------------------------------------------------------------------
    def test_a_scanner_that_records_a_pass_is_just_handled(self) -> None:
        h, result = self.run_one(passing)
        self.assertTrue(result)
        self.assertEqual((h.messages(), h.status(), h.snapshot().counters.pass_), ([], "PASS", 1))

    def test_a_warn_only_scanner_is_an_outcome_too(self) -> None:
        h, result = self.run_one(lambda ctx: (ctx.record_warn("jar:vendored_compiled_code_not_reviewable"), True)[1])
        self.assertTrue(result)
        self.assertEqual(h.messages(), [("WARN", "jar:vendored_compiled_code_not_reviewable")])

    # 3. the time budget ----------------------------------------------------------------------------------
    def test_the_time_budget_is_a_non_downgradable_fail_not_a_warn(self) -> None:
        def slow(ctx):
            raise ScanBudgetExceeded()
        allow = Allowlist({("engine", "a.py"): "x", ("scan_incomplete", "a.py"): "x"})
        h, result = self.run_one(slow, allowlist=allow, threshold=4)
        self.assertTrue(result)
        self.assertEqual(h.messages(), [("FAIL", "engine:scan_incomplete:python:time_budget")])
        self.assertEqual(h.status(), "FAIL")
        self.assertEqual(h.verdict.verdict, "FAIL")
        self.assertEqual(h.snapshot().coverage[L5], "partial:per-file time budget reached")

    def test_a_deadline_that_passed_gives_the_fail_through_check_deadline(self) -> None:
        h, result = self.run_one(lambda ctx: (ctx.check_deadline(), True)[1], deadline=time.monotonic() - 5)
        self.assertEqual(h.messages(), [("FAIL", "engine:scan_incomplete:python:time_budget")])

    # 4. the other contained failures ----------------------------------------------------------------------------
    def test_an_unreadable_file_is_a_fail_with_the_reason_word(self) -> None:
        for reason in ("permission", "too_large", "io", "vanished"):
            def unreadable(ctx, reason=reason):
                raise FileReadError(reason)
            h, result = self.run_one(unreadable)
            self.assertTrue(result)
            self.assertEqual(h.messages(), [("FAIL", "engine:file_unreadable:" + reason)])

    def test_a_reason_that_is_not_a_plain_word_is_not_copied(self) -> None:
        def odd(ctx):
            raise FileReadError("bad\x1b]0;x\x07 /etc/passwd")
        h, _ = self.run_one(odd)
        (level, text), = h.messages()
        self.assertEqual(level, "FAIL")
        self.assertTrue(text.startswith("engine:file_unreadable:"))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("passwd", text)

    def test_a_regex_timeout_is_a_fail_naming_the_scanner(self) -> None:
        def timed(ctx):
            raise rx.RegexTimeout()
        h, result = self.run_one(timed)
        self.assertTrue(result)
        self.assertEqual(h.messages(), [("FAIL", "engine:regex_timeout:python")])

    def test_any_exception_is_a_fail_with_its_class_and_a_traceback_on_stderr_only(self) -> None:
        for exc in (ValueError("v"), NotImplementedError(), MemoryError(), RecursionError(), KeyError("k"), OSError(13, "denied"), AssertionError()):
            def explode(ctx, exc=exc):
                raise exc
            h, result = self.run_one(explode, threshold=4)
            self.assertTrue(result)
            self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:" + type(exc).__name__)], repr(exc))
            self.assertEqual(h.status(), "FAIL")
            self.assertIn(type(exc).__name__, h.buffers.stderr)
            self.assertEqual(h.buffers.stdout, "")

    def test_the_exception_text_never_reaches_the_report(self) -> None:
        hostile = "line1\n\x1b]0;pwned\x07 /etc/passwd <script>alert(1)</script> " + "x" * 300

        def explode(ctx):
            raise ValueError(hostile)
        h, _ = self.run_one(explode)
        (_, text), = h.messages()
        self.assertEqual(text, "engine:scanner_error:python:ValueError")
        self.assertNotIn("passwd", json.dumps([f.__dict__ for f in h.snapshot().findings], default=str))
        raw = support.strip_engine_colours(h.buffers.err.getvalue())
        self.assertNotIn(b"\x1b", raw)                              # the traceback is sanitised on its way out
        self.assertNotIn(b"\x07", raw)

    def test_the_class_name_is_made_safe_before_it_is_put_in_a_message(self) -> None:
        Odd = type("Odd\x1b[31m<b>Error", (Exception,), {})

        def explode(ctx):
            raise Odd()
        h, _ = self.run_one(explode)
        (_, text), = h.messages()
        self.assertTrue(text.startswith("engine:scanner_error:python:Odd"))
        self.assertTrue(all(c.isalnum() or c in "_:" for c in text), text)

    def test_a_system_exit_is_a_fail_for_that_file_and_the_next_file_is_scanned(self) -> None:
        def exits(ctx):
            sys.exit(0)

        for code in (0, 1, "message", None):
            def exits_with(ctx, code=code):
                raise SystemExit(code)
            h, result = self.run_one(exits_with)
            self.assertTrue(result, code)
            self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:SystemExit")], code)
        h, _ = self.run_one(exits)
        self.assertEqual(h.verdict.verdict, "FAIL")
        # the run goes on: a second file of the same run is scanned and passes
        h.registry = support.make_registry({"python": passing})
        second = h.new_context("b.py", data=b"y")
        self.assertTrue(invoke(h.registry, "python", second))
        self.assertEqual(h.messages(second.path), [])
        self.assertEqual(h.status(second.path), "PASS")
        self.assertEqual(h.snapshot().counters.pass_, 1)

    def test_other_base_exceptions_propagate_and_record_nothing(self) -> None:
        for exc in (Stop(), KeyboardInterrupt(), GeneratorExit()):
            def stop(ctx, exc=exc):
                raise exc
            h = support.make_context(self, "a.py", b"x", registry=support.make_registry({"python": stop}))
            with self.assertRaises(type(exc)):
                invoke(h.registry, "python", h.ctx)
            self.assertEqual(h.messages(), [])
            self.assertEqual(h.verdict.verdict, "PASS")

    # 5. the outcome rule ----------------------------------------------------------------------------------
    def test_handled_without_an_event_is_a_fail(self) -> None:
        h, result = self.run_one(lambda ctx: True)
        self.assertTrue(result)
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:no_outcome")])

    def test_an_event_recorded_by_a_delegate_counts(self) -> None:
        reg = support.make_registry({"python": lambda ctx: ctx.delegate("shell") or True, "shell": passing})
        h = support.make_context(self, "a.py", b"x", registry=reg)
        self.assertTrue(invoke(reg, "python", h.ctx))
        self.assertEqual(h.messages(), [])
        self.assertEqual(h.status(), "PASS")

    def test_returning_false_when_not_sniffed_is_a_fail(self) -> None:
        h, result = self.run_one(lambda ctx: (ctx.record_pass(), False)[1])
        self.assertTrue(result)
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:returned_not_mine")])
        h, result = self.run_one(lambda ctx: False)
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:returned_not_mine")])

    def test_returning_false_when_sniffed_is_not_mine_and_records_nothing(self) -> None:
        h, result = self.run_one(lambda ctx: False, sniffed=True, scanner_id="rtf")
        self.assertIs(result, False)
        self.assertEqual(h.messages(), [])
        self.assertIsNone(h.status())
        self.assertEqual(h.verdict.events, 0)

    def test_a_sniffed_scanner_that_takes_the_file_returns_true(self) -> None:
        h, result = self.run_one(passing, sniffed=True, scanner_id="rtf")
        self.assertIs(result, True)

    def test_a_scanner_that_returns_none_is_judged_by_the_events_it_recorded(self) -> None:
        h, result = self.run_one(lambda ctx: ctx.record_pass())
        self.assertTrue(result)
        self.assertEqual(h.messages(), [])
        h, result = self.run_one(lambda ctx: None)
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:no_outcome")])

    def test_an_error_after_a_recorded_outcome_adds_the_fail(self) -> None:
        def half(ctx):
            ctx.record_pass()
            raise ValueError()
        h, _ = self.run_one(half)
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:ValueError")])
        self.assertEqual(h.status(), "FAIL")                         # a FAIL always sets the status, whatever came first
        self.assertEqual(h.verdict.verdict, "FAIL")

    def test_the_failure_is_recorded_against_the_file(self) -> None:
        h = support.make_context(self, "a.py", b"x", registry=support.make_registry({"python": lambda ctx: 1 / 0}), verdict="fake")
        invoke(h.registry, "python", h.ctx)
        self.assertEqual(h.verdict.log, [("fail", h.ctx.path, "engine:scanner_error:python:ZeroDivisionError", None, False)])


class GuardTests(unittest.TestCase):
    def guarded(self, fn, **kwargs):
        h = support.make_context(self, "a.py", b"x")
        return h, guard("universal", fn, h.ctx, **kwargs)

    def test_the_universal_layer_may_record_nothing(self) -> None:
        h, result = self.guarded(lambda ctx: True, requires_outcome=False)
        self.assertTrue(result)
        self.assertEqual(h.messages(), [])
        self.assertIsNone(h.status())

    def test_the_default_requires_an_outcome(self) -> None:
        h, _ = self.guarded(lambda ctx: True)
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:universal:no_outcome")])

    def test_it_records_what_the_function_records(self) -> None:
        h, result = self.guarded(lambda ctx: (ctx.record_warn("CWE-327:weak_crypto_algorithm"), True)[1], requires_outcome=False)
        self.assertTrue(result)
        self.assertEqual(h.messages(), [("WARN", "CWE-327:weak_crypto_algorithm")])

    def test_every_failure_of_invoke_is_contained_under_the_label(self) -> None:
        cases = [(ValueError(), "engine:scanner_error:universal:ValueError"), (SystemExit(0), "engine:scanner_error:universal:SystemExit"),
                 (ScanBudgetExceeded(), "engine:scan_incomplete:universal:time_budget"), (FileReadError("io"), "engine:file_unreadable:io"),
                 (rx.RegexTimeout(), "engine:regex_timeout:universal")]
        for exc, message in cases:
            def explode(ctx, exc=exc):
                raise exc
            h, result = self.guarded(explode, requires_outcome=False)
            self.assertTrue(result)
            self.assertEqual(h.messages(), [("FAIL", message)], repr(exc))

    def test_a_signal_exception_propagates(self) -> None:
        def stop(ctx):
            raise Stop()
        h = support.make_context(self, "a.py", b"x")
        with self.assertRaises(Stop):
            guard("universal", stop, h.ctx, requires_outcome=False)

    def test_returning_false_is_the_same_fail_as_in_invoke(self) -> None:
        h, result = self.guarded(lambda ctx: False, requires_outcome=False)
        self.assertTrue(result)
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:universal:returned_not_mine")])

    def test_none_is_tolerated_for_a_function_that_has_no_return_value(self) -> None:
        h, result = self.guarded(lambda ctx: None, requires_outcome=False)
        self.assertTrue(result)
        self.assertEqual(h.messages(), [])


class DelegateTests(unittest.TestCase):
    def test_delegate_runs_the_other_scanner_on_the_same_file_through_invoke(self) -> None:
        seen = []

        def rtf(ctx):
            seen.append((ctx.path, ctx.sniffed))
            ctx.record_pass()
            return True

        reg = support.make_registry({"docs": lambda ctx: ctx.delegate("rtf", sniffed=True) or True, "rtf": rtf})
        h = support.make_context(self, "n.md", b"x", registry=reg)
        self.assertTrue(invoke(reg, "docs", h.ctx))
        self.assertEqual(seen, [(h.ctx.path, True)])
        self.assertEqual(h.status(), "PASS")

    def test_delegate_returns_what_invoke_returns(self) -> None:
        answers = []
        reg = support.make_registry({"docs": lambda ctx: (answers.append(ctx.delegate("rtf", sniffed=True)), ctx.record_pass(), True)[2],
                                     "rtf": lambda ctx: False})
        h = support.make_context(self, "n.md", b"x", registry=reg)
        invoke(reg, "docs", h.ctx)
        self.assertEqual(answers, [False])                           # a sniffed "not mine" reaches the caller
        self.assertEqual(h.messages(), [])

    def test_delegating_without_sniffed_to_a_scanner_that_says_not_mine_is_a_fail(self) -> None:
        reg = support.make_registry({"unknown": lambda ctx: (ctx.delegate("python"), ctx.record_pass(), True)[2], "python": lambda ctx: False})
        h = support.make_context(self, "x", b"x", registry=reg)
        invoke(reg, "unknown", h.ctx)
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:returned_not_mine")])

    def test_delegate_to_an_id_that_is_not_ported_records_the_warn_and_returns_true(self) -> None:
        reg = support.make_registry({"unknown": lambda ctx: (ctx.delegate("python"), True)[1]})
        h = support.make_context(self, "x", b"x", registry=reg)
        self.assertTrue(invoke(reg, "unknown", h.ctx))
        self.assertEqual(h.messages(), [("WARN", "engine:scanner_not_ported:python")])

    def test_delegation_is_limited_to_three_levels(self) -> None:
        depths = []

        def loop(ctx):
            depths.append(ctx.sniffed)
            ctx.delegate("python")
            ctx.record_pass()
            return True

        reg = support.make_registry({"python": loop})
        h = support.make_context(self, "a.py", b"x", registry=reg)
        self.assertTrue(invoke(reg, "python", h.ctx))
        self.assertEqual(len(depths), 4)                              # the context of the file plus three delegations
        self.assertEqual(h.messages(), [("FAIL", "engine:scanner_error:python:RuntimeError")])

    def test_a_context_at_depth_three_refuses_to_delegate(self) -> None:
        h = support.make_context(self, "a.py", b"x", registry=support.make_registry({"python": passing}), depth=3)
        with self.assertRaises(RuntimeError):
            h.ctx.delegate("python")
        h2 = support.make_context(self, "a.py", b"x", registry=support.make_registry({"python": passing}), depth=2)
        self.assertTrue(h2.ctx.delegate("python"))

    def test_the_delegated_context_keeps_the_files_deadline(self) -> None:
        def inner(ctx):
            ctx.check_deadline()
            return True

        reg = support.make_registry({"unknown": lambda ctx: (ctx.delegate("python"), ctx.record_pass(), True)[2], "python": inner})
        h = support.make_context(self, "x", b"x", registry=reg, deadline=time.monotonic() - 1)
        invoke(reg, "unknown", h.ctx)
        self.assertEqual(h.messages(), [("FAIL", "engine:scan_incomplete:python:time_budget")])


class HostileNameTests(unittest.TestCase):
    def test_a_hostile_file_name_cannot_reach_the_terminal_through_a_failing_scanner(self) -> None:
        name = "x\x1b]0;pwned\x07<script>alert(1)</script>\n[FAIL] fake.py"
        h = support.make_context(self, name, b"x", registry=support.make_registry({"python": lambda ctx: 1 / 0}))
        invoke(h.registry, "python", h.ctx)
        raw = support.strip_engine_colours(h.buffers.err.getvalue())
        self.assertNotIn(b"\x1b", raw)
        self.assertNotIn(b"\x07", raw)
        for line in raw.decode("utf-8").split("\n"):
            self.assertTrue(line == "" or line.startswith(("[FAIL]", "    ")), line)    # no line a name could forge
        self.assertEqual(sum(1 for line in raw.decode("utf-8").split("\n") if line.startswith("[FAIL]")), 2)
        self.assertEqual(h.snapshot().counters.fail, 1)


if __name__ == "__main__":
    unittest.main()
