"""Tests of transit/layers.py (WP-06): ``search_policy``, ``file_deadline``, ``run_slot``, layers 1, 2, 3 and 6, ``run_file_layers`` (layers 4
and 5), ``finalise`` and ``run_all``. Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_layers.py"

What is real and what is not. The ``Verdict``, the ``Console`` (over in-memory buffers), the ``FileView``, ``files.files_for_scan``,
``dispatch.classify_file``, ``scanners.invoke`` / ``guard`` and ``ScanContext`` are the real modules. The doubles are the ones the design
allows: a ``FakeLocator`` for ``ToolLocator``, a ``DirStub`` wrapper that returns a canned ``ToolOutcome`` (the real wrappers are Phase 4),
and plain functions for the scanners and for the universal layer (``run_file_layers`` takes both as parameters so that a test can inject them).
The texts a layer writes are compared with ``scan_pipeline.sh`` itself and with the golden reports of the hardened bash engine, not with
copies made for this test. A token-shaped credential is never written contiguously in this file.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.engine import support  # noqa: E402
from transit import layers  # noqa: E402
from transit.cli import Args  # noqa: E402
from transit.config import COVERAGE_LAYERS, DEFAULT_EXCLUDE_DIRS  # noqa: E402
from transit.console import Console  # noqa: E402
from transit.dispatch import classify_file  # noqa: E402
from transit.files import (DiffSelection, Exclusions, FileReadError, FileView, ScanList, TempArea,  # noqa: E402
                           files_for_scan, load_exclusions)
from transit.findings import Allowlist, join_scan_path  # noqa: E402
from transit.layers import (LAYER1_SLOTS, LAYER2_SLOTS, LAYER3_DISABLED, LAYER3_SLOTS, LAYER6_DISABLED, LAYER6_SLOTS,  # noqa: E402
                            FileLayerSummary, RunEnv, file_deadline, finalise, run_all, run_file_layers, run_layer1,
                            run_layer2, run_layer3, run_layer6, run_slot, search_policy)
from transit.rules import Match, RuleSet, RuleSpec, ScanBudgetExceeded, SearchPolicy  # noqa: E402
from transit.tools import DIRECTORY_TOOLS, Record, ToolInfo, ToolOutcome, ToolRequest, ToolWrapper  # noqa: E402
from transit.verdict import GLOBAL_FILE, Outcome, Verdict  # noqa: E402

BASH = (ROOT / "scan_pipeline.sh").read_text(encoding="utf-8")
GOLDEN = ROOT / "tests" / "conformance" / "golden"
CLEAN_FIXTURE = ROOT / "tests" / "fixtures" / "clean"
MIB = 1 << 20

#: The two notes of layer 3 (bash ``scan_dependencies``; each has an em dash U+2014).
OFFLINE_PYTHON = ("OFFLINE:Python dependency CVE scan unavailable (pip-audit and safety both require a network advisory service) "
                  "— rely on the staged trivy database for Python CVEs")
OFFLINE_JS = ("OFFLINE:JavaScript dependency CVE scan unavailable (npm audit requires the registry) "
              "— rely on the staged trivy database for JS CVEs")

LAYER_OF = {"gitleaks": "L1_secrets_gitleaks", "detect-secrets": "L1_secrets_entropy", "clamscan": "L1_malware", "yara": "L1_ioc_yara",
            "semgrep": "L2_owasp_cwe", "trivy": "L3_dependency_cve", "scancode": "L6_licence"}
ALL_SLOTS = LAYER1_SLOTS + LAYER2_SLOTS + LAYER3_SLOTS + LAYER6_SLOTS


def golden(name: str) -> dict:
    return json.loads((GOLDEN / (name + ".json")).read_text(encoding="utf-8"))["report"]


class Stop(BaseException):
    """Stands for the private signal exception of ``pipeline`` (a ``BaseException`` that is not ``SystemExit``)."""


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# doubles and the environment builder
# ═══════════════════════════════════════════════════════════════════════════════════════════════
class DirStub(ToolWrapper):
    """A whole-directory wrapper that returns a canned outcome (or raises), remembers every request and logs its name in ``log``."""
    scope = "directory"

    def __init__(self, name: str, outcome: "object" = None, *, raises: "BaseException | None" = None, log: "list | None" = None) -> None:
        self.name = name
        self.binary = DIRECTORY_TOOLS[name]
        self.layer = LAYER_OF[name]
        self.outcome = ToolOutcome(layer_state="ran") if outcome is None else outcome
        self.raises = raises
        self.log = log
        self.requests: "list[ToolRequest]" = []

    def run(self, request: ToolRequest) -> ToolOutcome:
        self.requests.append(request)
        if self.log is not None:
            self.log.append(self.name)
        if self.raises is not None:
            raise self.raises
        return self.outcome  # type: ignore[return-value]


def pass_record(file: str) -> Record:
    return Record("pass", file)


def make_env(test: unittest.TestCase, *, files: "dict | None" = None, environ: "dict | None" = None,
             installed: "tuple[str, ...]" = (), wrappers: "tuple[ToolWrapper, ...]" = (), registry: "object | None" = None,
             allowlist: "Allowlist | None" = None, threshold: int = 3, min_severity: str = "high",
             patterns: "tuple[str, ...]" = (), diff: "DiffSelection | None" = None, verbosity: str = "normal",
             err_is_tty: bool = False, work_files: "dict | None" = None) -> RunEnv:
    """A ``RunEnv`` over a fresh temporary repository (``files``), a fresh ``WORK_DIR`` (``work_files`` are written under it) and a real
    ``Verdict`` and ``Console`` over buffers. ``installed``: the executables (``DIRECTORY_TOOLS`` values) the locator finds."""
    repo = support.TempRepo(files or {})
    test.addCleanup(repo.cleanup)
    work = tempfile.TemporaryDirectory(prefix="transit-test-work-")
    test.addCleanup(work.cleanup)
    work_dir = os.path.realpath(work.name)
    for rel, data in (work_files or {}).items():
        target = os.path.join(work_dir, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        Path(target).write_bytes(data if isinstance(data, bytes) else data.encode())
    cfg = support.make_config({"WORK_DIR": work_dir, **(environ or {})})
    out, err = io.BytesIO(), io.BytesIO()
    console = Console(verbosity, out=out, err=err, err_is_tty=err_is_tty)
    verdict = Verdict(repo.path, allowlist if allowlist is not None else Allowlist({}), threshold=threshold, min_severity=min_severity,
                      console=console, first_writer=True)
    temp = TempArea(tempfile.gettempdir())
    test.addCleanup(temp.cleanup)
    env = RunEnv(cfg=cfg, args=Args(scan_dir=repo.path, report_dir=None, scanning_name=None), scan_dir=repo.path, console=console,
                 verdict=verdict, tools=support.FakeLocator({name: "/opt/bin/" + name for name in installed}),  # type: ignore[arg-type]
                 wrappers=support.FakeWrappers(*wrappers),  # type: ignore[arg-type]
                 registry=registry if registry is not None else support.make_registry({}),  # type: ignore[arg-type]
                 temp=temp, exclusions=Exclusions(dir_names=DEFAULT_EXCLUDE_DIRS, patterns=tuple(patterns)),
                 diff=diff if diff is not None else DiffSelection(active=False, keys=frozenset(), stale_ignored=False, unresolved=0))
    env.repo = repo  # type: ignore[attr-defined]
    env.out, env.err = out, err  # type: ignore[attr-defined]
    return env


def state(env: RunEnv) -> "object":
    return env.verdict.snapshot()


def coverage(env: RunEnv) -> "dict[str, str]":
    return dict(env.verdict.snapshot().coverage)


def messages(env: RunEnv, file: str = GLOBAL_FILE) -> "list[tuple[str, str]]":
    return support.parse_file_message(env.verdict.snapshot().file_message.get(file, ""))


def recorded_path(env: RunEnv, file: str) -> str:
    """The recorded path of the ``file`` field of a finding record, which is relative to the scan directory (``.`` for the directory itself)."""
    if file == GLOBAL_FILE or file.startswith("/"):
        return file
    return env.scan_dir if file == "." else join_scan_path(env.scan_dir, file)


def fail_messages(env: RunEnv) -> "list[tuple[str, str]]":
    """``(recorded path, message)`` of every surviving FAIL, in the order recorded."""
    return [(recorded_path(env, record.file), record.message) for record in env.verdict.snapshot().findings]


def stderr(env: RunEnv) -> str:
    return env.err.getvalue().decode("utf-8", "replace")  # type: ignore[attr-defined]


def stdout(env: RunEnv) -> str:
    return env.out.getvalue().decode("utf-8", "replace")  # type: ignore[attr-defined]


def scan_of(env: RunEnv) -> ScanList:
    return files_for_scan(env.scan_dir, env.exclusions, env.diff)


def no_universal(ctx) -> bool:
    return True


def scan_with(env: RunEnv, **kwargs):
    """``run_file_layers`` over the real file listing of the environment's repository."""
    kwargs.setdefault("universal", no_universal)
    kwargs.setdefault("dispatch_file", classify_file)
    return run_file_layers(env, scan_of(env), **kwargs)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class SearchPolicyTests(unittest.TestCase):
    def test_carries_the_budget_and_the_long_line_limit_of_the_configuration(self) -> None:
        cfg = support.make_config()
        policy = search_policy(cfg)
        self.assertIsInstance(policy, SearchPolicy)
        self.assertEqual((policy.rule_budget_s, policy.long_line_bytes), (cfg.limits.rule_budget_s, cfg.limits.long_line_bytes))
        self.assertEqual((policy.rule_budget_s, policy.long_line_bytes), (0.25, 8192))

    def test_the_limits_come_from_the_configuration_and_not_from_constants(self) -> None:
        policy = search_policy(support.make_config(TRANSIT_RULE_BUDGET_S="0.75", TRANSIT_LONG_LINE_BYTES="4096"))
        self.assertEqual((policy.rule_budget_s, policy.long_line_bytes), (0.75, 4096))

    def test_an_exclusion_rule_is_not_blind_to_a_file_with_a_nul_byte(self) -> None:
        # D-029 is closed in bash: the frozen default of SearchPolicy (True, the pre-hardening behaviour) is NOT what the engine runs with
        self.assertTrue(SearchPolicy(rule_budget_s=1.0, long_line_bytes=10).excl_nul_blind, "the frozen default of the class")
        self.assertFalse(search_policy(support.make_config()).excl_nul_blind)

    def test_the_d029_switch_of_the_old_design_is_not_read(self) -> None:
        self.assertFalse(search_policy(support.make_config(TRANSIT_FIXES="D-029")).excl_nul_blind)

    def test_is_the_policy_the_scanner_tests_assume(self) -> None:
        cfg = support.make_config()
        self.assertEqual(search_policy(cfg), support.default_policy(cfg))


class FileDeadlineTests(unittest.TestCase):
    def test_an_empty_file_gets_the_fixed_part(self) -> None:
        self.assertAlmostEqual(file_deadline(support.make_config(), 0, now=1000.0), 1120.0)

    def test_the_allowance_grows_ten_seconds_per_mebibyte(self) -> None:
        cfg = support.make_config()
        self.assertAlmostEqual(file_deadline(cfg, MIB, now=1000.0), 1130.0)
        self.assertAlmostEqual(file_deadline(cfg, 5 * MIB, now=0.0), 170.0)
        self.assertAlmostEqual(file_deadline(cfg, MIB // 2, now=0.0), 125.0)
        self.assertAlmostEqual(file_deadline(cfg, 512 * MIB, now=0.0), 120.0 + 5120.0)

    def test_two_files_of_different_sizes_get_different_deadlines(self) -> None:
        cfg = support.make_config()
        self.assertLess(file_deadline(cfg, MIB, now=5.0), file_deadline(cfg, 100 * MIB, now=5.0))

    def test_the_budgets_are_the_ones_of_the_configuration(self) -> None:
        cfg = support.make_config(TRANSIT_FILE_BUDGET_S="5", TRANSIT_FILE_BUDGET_S_PER_MB="2")
        self.assertAlmostEqual(file_deadline(cfg, 3 * MIB, now=100.0), 100.0 + 5.0 + 6.0)

    def test_the_start_of_the_file_is_the_clock_value_given(self) -> None:
        cfg = support.make_config()
        self.assertAlmostEqual(file_deadline(cfg, 0, now=2.0) - file_deadline(cfg, 0, now=1.0), 1.0)

    def test_now_is_keyword_only(self) -> None:
        with self.assertRaises(TypeError):
            file_deadline(support.make_config(), 0, 1.0)  # type: ignore[misc]

    def test_a_size_below_zero_does_not_shorten_the_budget(self) -> None:
        self.assertAlmostEqual(file_deadline(support.make_config(), -5 * MIB, now=0.0), 120.0)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class SlotTextsTests(unittest.TestCase):
    """The texts of the slot tables are the texts of ``scan_pipeline.sh``, character for character, and of the golden reports."""

    def test_there_are_seven_slots_on_the_seven_tools_that_scan_a_whole_directory(self) -> None:
        self.assertEqual([slot.tool for slot in ALL_SLOTS],
                         ["gitleaks", "detect-secrets", "clamscan", "yara", "semgrep", "trivy", "scancode"])
        self.assertEqual({slot.tool for slot in ALL_SLOTS}, set(DIRECTORY_TOOLS))
        self.assertEqual([slot.layer_id for slot in ALL_SLOTS], [LAYER_OF[slot.tool] for slot in ALL_SLOTS])
        for slot in ALL_SLOTS:
            self.assertIn(slot.layer_id, COVERAGE_LAYERS)
            self.assertEqual(slot.missing_file, GLOBAL_FILE)

    def test_the_layers_hold_the_slots_of_the_bash_order(self) -> None:
        self.assertEqual([slot.tool for slot in LAYER1_SLOTS], ["gitleaks", "detect-secrets", "clamscan", "yara"])
        self.assertEqual([slot.tool for slot in LAYER2_SLOTS], ["semgrep"])
        self.assertEqual([slot.tool for slot in LAYER3_SLOTS], ["trivy"])
        self.assertEqual([slot.tool for slot in LAYER6_SLOTS], ["scancode"])

    def test_only_yara_needs_a_directory_below_the_work_directory(self) -> None:
        self.assertEqual({slot.tool: slot.requires_dir for slot in ALL_SLOTS if slot.requires_dir}, {"yara": "yara-rules"})

    def test_every_missing_text_occurs_in_the_bash_script_as_the_arguments_of_the_same_calls(self) -> None:
        for slot in ALL_SLOTS:
            self.assertIn('record_warn "__global__" "%s"' % slot.missing_message, BASH, slot.tool)
            self.assertIn('record_layer %s "%s"' % (slot.layer_id, slot.missing_state), BASH, slot.tool)

    def test_the_two_disabled_texts_occur_in_the_bash_script(self) -> None:
        self.assertEqual(LAYER3_DISABLED, "skipped:disabled (RUN_SCA is not true)")
        self.assertEqual(LAYER6_DISABLED, "skipped:disabled (RUN_SCANCODE is not true)")
        self.assertIn('record_layer L3_dependency_cve "%s"' % LAYER3_DISABLED, BASH)
        self.assertIn('record_layer L6_licence "%s"' % LAYER6_DISABLED, BASH)

    def test_the_two_offline_notes_of_layer_3_occur_in_the_bash_script(self) -> None:
        self.assertIn('"%s"' % OFFLINE_PYTHON, BASH)
        self.assertIn('"%s"' % OFFLINE_JS, BASH)

    def test_the_missing_texts_are_the_ones_of_the_golden_reports(self) -> None:
        clean, layers_on = golden("clean"), golden("layers_on")
        for slot in LAYER1_SLOTS + LAYER2_SLOTS:
            self.assertEqual(clean["coverage"][slot.layer_id], slot.missing_state, slot.tool)
            self.assertIn("[WARN] " + slot.missing_message, clean["file_results"][GLOBAL_FILE]["messages"], slot.tool)
        for slot in LAYER3_SLOTS + LAYER6_SLOTS:
            self.assertEqual(layers_on["coverage"][slot.layer_id], slot.missing_state, slot.tool)
            self.assertIn("[WARN] " + slot.missing_message, layers_on["file_results"][GLOBAL_FILE]["messages"], slot.tool)
        self.assertEqual(clean["coverage"]["L3_dependency_cve"], LAYER3_DISABLED)
        self.assertEqual(clean["coverage"]["L6_licence"], LAYER6_DISABLED)
        self.assertIn("[WARN] " + OFFLINE_PYTHON, layers_on["file_results"][GLOBAL_FILE]["messages"])

    def test_a_slot_is_a_frozen_row(self) -> None:
        with self.assertRaises(Exception):
            LAYER1_SLOTS[0].tool = "x"  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RunSlotTests(unittest.TestCase):
    """One whole-directory tool: not installed, not ported, run, and a wrapper that fails."""

    GITLEAKS = LAYER1_SLOTS[0]

    # -- not installed
    def test_a_tool_that_is_not_installed_is_a_warn_on_global_and_a_skipped_layer(self) -> None:
        env = make_env(self)
        run_slot(env, self.GITLEAKS)
        self.assertEqual(messages(env), [("WARN", "gitleaks missing — secret scan skipped")])
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:gitleaks not installed"})
        self.assertEqual(env.verdict.verdict, "PASS")

    def test_every_slot_says_its_own_texts_when_its_tool_is_missing(self) -> None:
        for slot in ALL_SLOTS:
            with self.subTest(tool=slot.tool):
                env = make_env(self)
                run_slot(env, slot)
                self.assertEqual(messages(env), [("WARN", slot.missing_message)])
                self.assertEqual(coverage(env), {slot.layer_id: slot.missing_state})

    def test_a_missing_tool_never_reaches_its_wrapper(self) -> None:
        wrapper = DirStub("gitleaks")
        env = make_env(self, wrappers=(wrapper,))
        run_slot(env, self.GITLEAKS)
        self.assertEqual(wrapper.requests, [])

    def test_the_executable_asked_for_is_the_one_of_the_tool_table(self) -> None:
        env = make_env(self)
        for slot in ALL_SLOTS:
            run_slot(env, slot)
        self.assertEqual(env.tools.asked, [DIRECTORY_TOOLS[slot.tool] for slot in ALL_SLOTS])  # type: ignore[attr-defined]

    # -- yara needs a rules directory as well
    def test_yara_without_its_rules_directory_counts_as_missing(self) -> None:
        env = make_env(self, installed=("yara",), wrappers=(DirStub("yara"),))
        run_slot(env, LAYER1_SLOTS[3])
        self.assertEqual(messages(env), [("WARN", "yara or rules directory missing")])
        self.assertEqual(coverage(env), {"L1_ioc_yara": "skipped:yara or rules directory missing"})

    def test_a_rules_directory_that_is_a_file_is_not_a_directory(self) -> None:
        wrapper = DirStub("yara")
        env = make_env(self, installed=("yara",), wrappers=(wrapper,), work_files={"yara-rules": "not a directory"})
        run_slot(env, LAYER1_SLOTS[3])
        self.assertEqual(coverage(env), {"L1_ioc_yara": "skipped:yara or rules directory missing"})
        self.assertEqual(wrapper.requests, [])

    def test_yara_with_its_rules_directory_runs_its_wrapper(self) -> None:
        wrapper = DirStub("yara")
        env = make_env(self, installed=("yara",), wrappers=(wrapper,), work_files={"yara-rules/a.yar": "rule a { condition: false }"})
        run_slot(env, LAYER1_SLOTS[3])
        self.assertEqual(len(wrapper.requests), 1)
        self.assertEqual(coverage(env), {"L1_ioc_yara": "ran"})

    def test_the_rules_directory_is_below_the_work_directory_of_the_configuration(self) -> None:
        wrapper = DirStub("yara")
        env = make_env(self, installed=("yara",), wrappers=(wrapper,))
        other = tempfile.mkdtemp(prefix="transit-test-other-")
        self.addCleanup(shutil.rmtree, other, True)
        os.mkdir(os.path.join(other, "yara-rules"))                       # exists, but it is not WORK_DIR/yara-rules
        run_slot(env, LAYER1_SLOTS[3])
        self.assertEqual(wrapper.requests, [])

    # -- installed, no wrapper
    def test_an_installed_tool_without_a_wrapper_is_reported_not_skipped_silently(self) -> None:
        env = make_env(self, installed=("gitleaks",))
        run_slot(env, self.GITLEAKS)
        self.assertEqual(messages(env), [("WARN", "engine:tool_not_ported:gitleaks")])
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:python engine has not ported gitleaks yet"})
        self.assertEqual(env.verdict.verdict, "PASS")

    def test_every_tool_without_a_wrapper_gets_its_own_name_in_both_texts(self) -> None:
        for slot in ALL_SLOTS:
            with self.subTest(tool=slot.tool):
                env = make_env(self, installed=tuple(DIRECTORY_TOOLS.values()), work_files={"yara-rules/a.yar": "x"})
                run_slot(env, slot)
                self.assertEqual(messages(env), [("WARN", "engine:tool_not_ported:" + slot.tool)])
                self.assertEqual(coverage(env), {slot.layer_id: "skipped:python engine has not ported %s yet" % slot.tool})

    def test_a_wrapper_for_another_tool_is_not_used(self) -> None:
        other = DirStub("trivy")
        env = make_env(self, installed=("gitleaks", "trivy"), wrappers=(other,))
        run_slot(env, self.GITLEAKS)
        self.assertEqual(other.requests, [])
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:python engine has not ported gitleaks yet"})

    # -- installed, with a wrapper
    def test_the_wrapper_gets_a_request_that_describes_the_run(self) -> None:
        wrapper = DirStub("semgrep")
        env = make_env(self, installed=("semgrep",), wrappers=(wrapper,), patterns=("docs", "*.log"))
        run_slot(env, LAYER2_SLOTS[0])
        (request,) = wrapper.requests
        self.assertIsInstance(request, ToolRequest)
        self.assertIs(request.cfg, env.cfg)
        self.assertEqual(request.scan_dir, env.scan_dir)
        self.assertIsNone(request.target)
        self.assertIs(request.temp, env.temp)
        self.assertEqual(request.exclude_dirs, env.exclusions.semgrep_dirs())
        self.assertEqual(request.exclude_dirs, tuple(DEFAULT_EXCLUDE_DIRS) + ("docs", "*.log"))
        self.assertEqual(request.info, ToolInfo("semgrep", "/opt/bin/semgrep"))

    def test_the_path_the_locator_found_is_the_path_the_wrapper_gets(self) -> None:
        with support.StubTools({"gitleaks": {"exit_code": 0}}) as stubs:
            wrapper = DirStub("gitleaks")
            env = make_env(self, wrappers=(wrapper,), environ=stubs.environ())
            from transit.tools import ToolLocator
            env.tools = ToolLocator(env.cfg)
            run_slot(env, self.GITLEAKS)
            self.assertEqual(wrapper.requests[0].info, ToolInfo("gitleaks", os.path.join(stubs.dir, "gitleaks")))

    def test_a_wrapper_that_runs_a_real_stub_program_end_to_end(self) -> None:
        from transit.tools import ToolLocator, child_env, run_process

        class RunsTheStub(DirStub):
            def run(self, request: ToolRequest) -> ToolOutcome:
                result = run_process([request.info.path, "scan", request.scan_dir], env=child_env(request.cfg), timeout_s=30)
                if result.status != "ok" or result.returncode not in (0, 1):
                    return ToolOutcome(layer_state="skipped:gitleaks failed (exit %s)" % result.returncode)
                records = (Record("fail", request.scan_dir, "gitleaks:secrets_detected"),) if result.returncode == 1 else ()
                return ToolOutcome(layer_state="ran", records=records, exit_code=result.returncode)

        with support.StubTools({"gitleaks": {"exit_code": 1}}, record_env=("LC_ALL", "PIP_NO_INDEX")) as stubs:
            env = make_env(self, wrappers=(RunsTheStub("gitleaks"),), environ=stubs.environ())
            env.tools = ToolLocator(env.cfg)
            run_slot(env, self.GITLEAKS)
            self.assertEqual(stubs.calls("gitleaks"), [["scan", env.scan_dir]])
            self.assertEqual(stubs.env("gitleaks"), {"LC_ALL": "C", "PIP_NO_INDEX": "1"})
        self.assertEqual(fail_messages(env), [(env.scan_dir, "gitleaks:secrets_detected")])
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "ran"})
        self.assertEqual(env.verdict.verdict, "FAIL")

    def test_the_state_of_the_wrapper_is_the_state_of_the_layer(self) -> None:
        for given in ("ran", "skipped:gitleaks failed (exit 7)", "partial:rulesets missing (secrets)"):
            with self.subTest(state=given):
                env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", ToolOutcome(layer_state=given)),))
                run_slot(env, self.GITLEAKS)
                self.assertEqual(coverage(env), {"L1_secrets_gitleaks": given})

    def test_the_records_are_applied_in_order_with_the_calls_they_name(self) -> None:
        env = make_env(self, installed=("gitleaks",))
        file = env.scan_dir + "/a.py"
        records = (Record("warn", GLOBAL_FILE, "gitleaks:note one"), pass_record(file), Record("warn", file, "gitleaks:note two"),
                   Record("fail", file, "gitleaks:aws-key:line3"))
        env.wrappers = support.FakeWrappers(DirStub("gitleaks", ToolOutcome(layer_state="ran", records=records)))  # type: ignore[assignment]
        run_slot(env, self.GITLEAKS)
        self.assertEqual(messages(env), [("WARN", "gitleaks:note one")])
        self.assertEqual(messages(env, file), [("WARN", "gitleaks:note two"), ("FAIL", "gitleaks:aws-key:line3")])
        self.assertEqual(env.verdict.status_of(file), "FAIL", "a FAIL sets the status whatever came first")
        counters = env.verdict.counters
        self.assertEqual((counters.pass_, counters.warn, counters.fail), (1, 2, 1))
        self.assertEqual(env.verdict.verdict, "FAIL")
        self.assertEqual(fail_messages(env), [(file, "gitleaks:aws-key:line3")])

    def test_a_pass_record_marks_the_file_it_names(self) -> None:
        env = make_env(self, installed=("clamscan",))
        env.wrappers = support.FakeWrappers(DirStub("clamscan", ToolOutcome(layer_state="ran", records=(pass_record(env.scan_dir),))))  # type: ignore[assignment]
        run_slot(env, LAYER1_SLOTS[2])
        self.assertEqual(env.verdict.status_of(env.scan_dir), "PASS")
        self.assertEqual(env.verdict.counters.pass_, 1)

    def test_a_fail_record_goes_through_the_allowlist_like_a_rule_does(self) -> None:
        allow = Allowlist({("aws-key", "a.py"): "a test fixture"})
        env = make_env(self, installed=("gitleaks",), allowlist=allow)
        file = env.scan_dir + "/a.py"
        env.wrappers = support.FakeWrappers(DirStub("gitleaks", ToolOutcome(layer_state="ran", records=(Record("fail", file, "gitleaks:aws-key:line3"),))))  # type: ignore[assignment]
        run_slot(env, self.GITLEAKS)
        self.assertEqual(env.verdict.verdict, "PASS")
        self.assertEqual(messages(env, file), [("WARN", "ALLOWED:gitleaks:aws-key:line3 (reason: a test fixture)")])

    def test_a_fail_record_goes_through_the_threshold_with_the_severity_the_tool_gave(self) -> None:
        records = (Record("fail", "F", "semgrep[x]:rule:line1:INFO:m", "LOW"),)
        env = make_env(self, installed=("semgrep",))
        file = env.scan_dir + "/a.py"
        env.wrappers = support.FakeWrappers(DirStub("semgrep", ToolOutcome(layer_state="ran", records=tuple(
            Record(r.kind, file, r.message, r.severity) for r in records))))  # type: ignore[assignment]
        run_slot(env, LAYER2_SLOTS[0])
        self.assertEqual(env.verdict.verdict, "PASS", "LOW is below the default threshold HIGH")
        self.assertEqual(messages(env, file)[0][1], "LOW_SEV(below --min-severity high):semgrep[x]:rule:line1:INFO:m")

    def test_the_severity_of_a_record_reaches_the_finding(self) -> None:
        env = make_env(self, installed=("semgrep",))
        file = env.scan_dir + "/a.py"
        env.wrappers = support.FakeWrappers(DirStub("semgrep", ToolOutcome(layer_state="ran", records=(  # type: ignore[assignment]
            Record("fail", file, "semgrep[x]:rule:line1:ERROR:m", "CRITICAL"),))))
        run_slot(env, LAYER2_SLOTS[0])
        (record,) = env.verdict.snapshot().findings
        self.assertEqual((record.severity, record.tool), ("CRITICAL", "semgrep"))

    def test_the_notes_of_a_wrapper_are_console_lines_and_never_events(self) -> None:
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", ToolOutcome(layer_state="ran", notes=("gitleaks: no secrets",))),))
        before = env.verdict.events
        run_slot(env, self.GITLEAKS)
        self.assertIn("gitleaks: no secrets", stdout(env))
        self.assertEqual(env.verdict.events, before)

    def test_a_note_with_control_bytes_is_printed_sanitised(self) -> None:
        note = "x\x1b]0;pwned\x07\r‮y"
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", ToolOutcome(layer_state="ran", notes=(note,))),))
        run_slot(env, self.GITLEAKS)
        printable = support.strip_engine_colours(env.out.getvalue())  # type: ignore[attr-defined]
        self.assertFalse([b for b in printable if b < 0x20 and b != 0x0A], printable)
        self.assertNotIn("‮", stdout(env))

    def test_the_run_is_announced_on_the_info_channel_only_when_the_tool_runs(self) -> None:
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks"),))
        run_slot(env, self.GITLEAKS)
        self.assertIn("gitleaks", stdout(env))
        quiet = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks"),), verbosity="quiet")
        run_slot(quiet, self.GITLEAKS)
        self.assertEqual(stdout(quiet), "")

    # -- a wrapper that fails
    def test_a_wrapper_that_raises_is_a_fail_and_the_layer_did_not_run(self) -> None:
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", raises=KeyError("secret path /etc/shadow")),))
        run_slot(env, self.GITLEAKS)
        self.assertEqual(fail_messages(env), [(env.scan_dir, "engine:tool_error:gitleaks:KeyError")])
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:gitleaks wrapper failed"})
        self.assertEqual(env.verdict.verdict, "FAIL")

    def test_the_text_of_the_exception_is_never_in_the_report(self) -> None:
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", raises=RuntimeError("/etc/shadow <img src=x onerror=1>")),))
        run_slot(env, self.GITLEAKS)
        snap = env.verdict.snapshot()
        everything = json.dumps([dict(snap.file_message), dict(snap.fail_messages), [r.message for r in snap.findings], dict(snap.coverage)])
        self.assertNotIn("shadow", everything)
        self.assertNotIn("onerror", everything)

    def test_the_traceback_goes_to_the_console_sanitised(self) -> None:
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", raises=RuntimeError("boom\x1b]0;pwned\x07")),))
        run_slot(env, self.GITLEAKS)
        self.assertIn("RuntimeError", stderr(env))
        raw = support.strip_engine_colours(env.err.getvalue())  # type: ignore[attr-defined]
        self.assertFalse([b for b in raw if b < 0x20 and b != 0x0A], raw)

    def test_a_system_exit_in_a_wrapper_is_a_fail_for_that_tool_and_not_the_end_of_the_run(self) -> None:
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", raises=SystemExit(0)),))
        run_slot(env, self.GITLEAKS)
        self.assertEqual(fail_messages(env), [(env.scan_dir, "engine:tool_error:gitleaks:SystemExit")])
        self.assertEqual(env.verdict.verdict, "FAIL")

    def test_a_signal_exception_is_not_swallowed(self) -> None:
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", raises=Stop()),))
        with self.assertRaises(Stop):
            run_slot(env, self.GITLEAKS)
        self.assertEqual(env.verdict.events, 0)

    def test_a_wrapper_that_returns_no_state_is_a_fail_never_ran(self) -> None:
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", ToolOutcome(layer_state=None)),))
        run_slot(env, self.GITLEAKS)
        self.assertEqual(fail_messages(env), [(env.scan_dir, "engine:tool_error:gitleaks:no_layer_state")])
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:gitleaks wrapper failed"})

    def test_a_wrapper_that_returns_something_else_is_a_fail(self) -> None:
        for bogus in (None, "ran", 3, {"layer_state": "ran"}):
            with self.subTest(bogus=bogus):
                wrapper = DirStub("gitleaks")
                wrapper.outcome = bogus                                          # DirStub treats None as "the default": set it afterwards
                env = make_env(self, installed=("gitleaks",), wrappers=(wrapper,))
                run_slot(env, self.GITLEAKS)
                self.assertEqual(fail_messages(env), [(env.scan_dir, "engine:tool_error:gitleaks:bad_outcome")])
                self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:gitleaks wrapper failed"})

    def test_a_state_outside_the_grammar_is_a_fail_and_applies_none_of_the_records(self) -> None:
        env = make_env(self, installed=("gitleaks",))
        records = (Record("warn", GLOBAL_FILE, "gitleaks:a note"),)
        env.wrappers = support.FakeWrappers(DirStub("gitleaks", ToolOutcome(layer_state="banana", records=records)))  # type: ignore[assignment]
        run_slot(env, self.GITLEAKS)
        self.assertEqual(fail_messages(env), [(env.scan_dir, "engine:tool_error:gitleaks:bad_layer_state")])
        self.assertEqual(messages(env), [])
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:gitleaks wrapper failed"})

    def test_a_record_that_is_not_one_is_a_fail_and_applies_none_of_the_records(self) -> None:
        good = Record("warn", GLOBAL_FILE, "gitleaks:a note")
        for bad in (Record("note", GLOBAL_FILE, "x"), Record("fail", GLOBAL_FILE, "x", "SEVERE"), "text", None):
            with self.subTest(bad=bad):
                env = make_env(self, installed=("gitleaks",))
                env.wrappers = support.FakeWrappers(DirStub("gitleaks", ToolOutcome(layer_state="ran", records=(good, bad))))  # type: ignore[assignment]
                run_slot(env, self.GITLEAKS)
                self.assertEqual(fail_messages(env), [(env.scan_dir, "engine:tool_error:gitleaks:bad_record")])
                self.assertEqual(messages(env), [])
                self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:gitleaks wrapper failed"})

    def test_a_run_that_timed_out_is_never_ran(self) -> None:
        for flag in (True, 1):
            with self.subTest(flag=flag):
                env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", ToolOutcome(layer_state="ran", timed_out=flag)),))  # type: ignore[arg-type]
                run_slot(env, self.GITLEAKS)
                self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:gitleaks timed out"})
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", ToolOutcome(layer_state="ran", timed_out=False)),))
        run_slot(env, self.GITLEAKS)
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "ran"}, "a run that did not time out keeps its state")

    def test_a_timeout_the_wrapper_already_reported_keeps_its_own_state(self) -> None:
        outcome = ToolOutcome(layer_state="skipped:gitleaks timed out", records=(Record("warn", GLOBAL_FILE, "gitleaks:scan_timed_out"),), timed_out=True)
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", outcome),))
        run_slot(env, self.GITLEAKS)
        self.assertEqual(coverage(env), {"L1_secrets_gitleaks": "skipped:gitleaks timed out"})
        self.assertEqual(messages(env), [("WARN", "gitleaks:scan_timed_out")])

    def test_the_tool_error_cannot_be_allowlisted_or_lowered(self) -> None:
        allow = Allowlist({("engine", "."): "x", ("tool_error", "."): "x", ("engine", ""): "x"})
        env = make_env(self, installed=("gitleaks",), wrappers=(DirStub("gitleaks", raises=KeyError("k")),), allowlist=allow, threshold=4,
                       min_severity="critical")
        run_slot(env, self.GITLEAKS)
        self.assertEqual(env.verdict.verdict, "FAIL")
        self.assertEqual(env.verdict.counters.fail, 1)

    def test_a_failed_slot_does_not_stop_the_next_one(self) -> None:
        log: "list[str]" = []
        env = make_env(self, installed=("gitleaks", "detect-secrets"),
                       wrappers=(DirStub("gitleaks", raises=KeyError("k"), log=log), DirStub("detect-secrets", log=log)))
        run_layer1(env)
        self.assertEqual(log, ["gitleaks", "detect-secrets"])
        self.assertEqual(coverage(env)["L1_secrets_entropy"], "ran")

    def test_a_layer_is_never_left_without_a_state(self) -> None:
        # every outcome of run_slot sets the state of its layer: missing, not ported, ran, skipped, wrapper failed
        for installed, wrappers in (((), ()), (("trivy",), ()), (("trivy",), (DirStub("trivy"),)),
                                    (("trivy",), (DirStub("trivy", raises=ValueError()),)),
                                    (("trivy",), (DirStub("trivy", ToolOutcome(layer_state=None)),))):
            env = make_env(self, installed=installed, wrappers=wrappers)
            run_slot(env, LAYER3_SLOTS[0])
            self.assertIn("L3_dependency_cve", coverage(env))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class LayerFunctionsTests(unittest.TestCase):
    def test_layer_1_runs_its_four_tools_in_bash_order(self) -> None:
        log: "list[str]" = []
        every = tuple(DirStub(name, log=log) for name in ("yara", "clamscan", "detect-secrets", "gitleaks"))
        env = make_env(self, installed=("gitleaks", "detect-secrets", "clamscan", "yara"), wrappers=every, work_files={"yara-rules/a.yar": "x"})
        run_layer1(env)
        self.assertEqual(log, ["gitleaks", "detect-secrets", "clamscan", "yara"])
        self.assertEqual({k: v for k, v in coverage(env).items()}, {LAYER_OF[n]: "ran" for n in ("gitleaks", "detect-secrets", "clamscan", "yara")})

    def test_layer_1_with_nothing_installed_is_the_four_warns_and_states_of_the_clean_golden(self) -> None:
        env = make_env(self)
        run_layer1(env)
        want = golden("clean")
        self.assertEqual([text for _level, text in messages(env)],
                         ["gitleaks missing — secret scan skipped", "detect-secrets missing", "clamscan missing",
                          "yara or rules directory missing"])
        for layer in ("L1_secrets_gitleaks", "L1_secrets_entropy", "L1_malware", "L1_ioc_yara"):
            self.assertEqual(coverage(env)[layer], want["coverage"][layer])

    def test_layer_1_announces_itself(self) -> None:
        env = make_env(self)
        run_layer1(env)
        self.assertIn("Layer 1", stdout(env))

    def test_layer_2_is_semgrep(self) -> None:
        log: "list[str]" = []
        env = make_env(self, installed=("semgrep",), wrappers=(DirStub("semgrep", log=log),))
        run_layer2(env)
        self.assertEqual(log, ["semgrep"])
        self.assertEqual(coverage(env), {"L2_owasp_cwe": "ran"})
        self.assertIn("Layer 2", stdout(env))

    def test_layer_2_with_semgrep_missing(self) -> None:
        env = make_env(self)
        run_layer2(env)
        self.assertEqual(messages(env), [("WARN", "semgrep missing — OWASP/CWE layer skipped (pip install semgrep)")])
        self.assertEqual(coverage(env), {"L2_owasp_cwe": "skipped:semgrep not installed"})

    # -- layer 3
    def test_layer_3_is_off_unless_run_sca_is_exactly_true(self) -> None:
        for value in (None, "", "false", "TRUE", "True", "1", "yes", "true "):
            with self.subTest(value=value):
                log: "list[str]" = []
                environ = {} if value is None else {"RUN_SCA": value}
                env = make_env(self, environ=environ, installed=("trivy",), wrappers=(DirStub("trivy", log=log),),
                               files={"requirements.txt": "x\n"})
                run_layer3(env)
                self.assertEqual(coverage(env), {"L3_dependency_cve": LAYER3_DISABLED})
                self.assertEqual(log, [], "a disabled layer does not run its tool")
                self.assertEqual(env.verdict.events, 0, "a disabled layer records no event and no note")
                self.assertEqual(messages(env), [])

    def test_a_disabled_layer_3_says_so_on_the_info_channel(self) -> None:
        env = make_env(self)
        run_layer3(env)
        self.assertIn("RUN_SCA=true", stdout(env))

    def test_layer_3_on_runs_trivy(self) -> None:
        log: "list[str]" = []
        env = make_env(self, environ={"RUN_SCA": "true"}, installed=("trivy",), wrappers=(DirStub("trivy", log=log),))
        run_layer3(env)
        self.assertEqual(log, ["trivy"])
        self.assertEqual(coverage(env), {"L3_dependency_cve": "ran"})
        self.assertEqual(messages(env), [])

    def test_layer_3_with_trivy_missing_and_a_requirements_file_is_the_two_warns_of_the_layers_on_golden(self) -> None:
        env = make_env(self, environ={"RUN_SCA": "true"}, files={"requirements.txt": "flask\n", "src/app.py": "x = 1\n"})
        run_layer3(env)
        self.assertEqual([text for _level, text in messages(env)], ["trivy missing — dependency CVE scan skipped", OFFLINE_PYTHON])
        self.assertEqual(coverage(env), {"L3_dependency_cve": "skipped:trivy not installed"})
        self.assertEqual(golden("layers_on")["coverage"]["L3_dependency_cve"], "skipped:trivy not installed")

    def test_the_python_note_is_for_requirements_pipfile_lock_and_pyproject(self) -> None:
        for name in ("requirements.txt", "requirements-dev.txt", "requirements_x.txt", "requirements.txt.txt", "Pipfile.lock", "pyproject.toml",
                     "sub/dir/requirements.txt", "a/b/c/pyproject.toml", ".hidden/Pipfile.lock"):
            with self.subTest(name=name):
                env = make_env(self, environ={"RUN_SCA": "true"}, files={name: "x\n"})
                run_layer3(env)
                self.assertIn(("WARN", OFFLINE_PYTHON), messages(env))
                self.assertNotIn(("WARN", OFFLINE_JS), messages(env))

    def test_no_python_note_for_files_that_only_look_like_them(self) -> None:
        for name in ("requirement.txt", "requirements.md", "requirements", "my-requirements.txt", "Pipfile", "Pipfile.lock.bak", "pyproject.toml.in",
                     "pyproject.yaml", "README.md"):
            with self.subTest(name=name):
                env = make_env(self, environ={"RUN_SCA": "true"}, files={name: "x\n"})
                run_layer3(env)
                self.assertNotIn(("WARN", OFFLINE_PYTHON), messages(env))

    def test_the_javascript_note_is_for_package_lock_and_yarn_lock(self) -> None:
        for name in ("package-lock.json", "yarn.lock", "web/package-lock.json", "a/b/yarn.lock"):
            with self.subTest(name=name):
                env = make_env(self, environ={"RUN_SCA": "true"}, files={name: "{}\n"})
                run_layer3(env)
                self.assertIn(("WARN", OFFLINE_JS), messages(env))
                self.assertNotIn(("WARN", OFFLINE_PYTHON), messages(env))

    def test_no_javascript_note_for_package_json_alone(self) -> None:
        for name in ("package.json", "pnpm-lock.yaml", "package-lock.json.bak", "yarn.lock.old"):
            with self.subTest(name=name):
                env = make_env(self, environ={"RUN_SCA": "true"}, files={name: "{}\n"})
                run_layer3(env)
                self.assertNotIn(("WARN", OFFLINE_JS), messages(env))

    def test_both_notes_come_python_first_after_the_trivy_text(self) -> None:
        env = make_env(self, environ={"RUN_SCA": "true"}, files={"requirements.txt": "x\n", "package-lock.json": "{}\n"})
        run_layer3(env)
        self.assertEqual([text for _level, text in messages(env)],
                         ["trivy missing — dependency CVE scan skipped", OFFLINE_PYTHON, OFFLINE_JS])

    def test_each_note_is_written_once_however_many_files_there_are(self) -> None:
        files = {"a/requirements.txt": "x", "b/requirements.txt": "x", "c/pyproject.toml": "x", "d/package-lock.json": "{}", "e/yarn.lock": ""}
        env = make_env(self, environ={"RUN_SCA": "true"}, files=files)
        run_layer3(env)
        self.assertEqual([text for _l, text in messages(env)].count(OFFLINE_PYTHON), 1)
        self.assertEqual([text for _l, text in messages(env)].count(OFFLINE_JS), 1)

    def test_no_note_for_a_repository_without_those_files(self) -> None:
        env = make_env(self, environ={"RUN_SCA": "true"}, installed=("trivy",), wrappers=(DirStub("trivy"),), files={"src/app.py": "x = 1\n"})
        run_layer3(env)
        self.assertEqual(messages(env), [])

    def test_the_search_is_not_pruned_like_the_file_listing_is(self) -> None:
        # bash: find "$SCAN_DIR" -name "requirements*.txt" ... has no -prune: node_modules and .transitignore do not hide a manifest from it
        env = make_env(self, environ={"RUN_SCA": "true"}, files={"node_modules/x/requirements.txt": "x\n"}, patterns=("node_modules",))
        run_layer3(env)
        self.assertIn(("WARN", OFFLINE_PYTHON), messages(env))

    def test_a_directory_with_the_name_counts_as_find_has_no_type_test(self) -> None:
        env = make_env(self, environ={"RUN_SCA": "true"}, files={"requirements.txt/inner": "x"})
        run_layer3(env)
        self.assertIn(("WARN", OFFLINE_PYTHON), messages(env))

    def test_a_symlink_with_the_name_counts_and_is_not_followed(self) -> None:
        env = make_env(self, environ={"RUN_SCA": "true"}, files={"other/x": "y"})
        env.repo.symlink("pyproject.toml", "/nonexistent/elsewhere")  # type: ignore[attr-defined]
        env.repo.symlink("loop", ".")  # type: ignore[attr-defined]
        run_layer3(env)
        self.assertIn(("WARN", OFFLINE_PYTHON), messages(env))

    def test_a_link_to_a_directory_outside_is_not_followed_to_find_a_manifest(self) -> None:
        outside = tempfile.mkdtemp(prefix="transit-test-outside-")
        self.addCleanup(shutil.rmtree, outside, True)
        Path(outside, "requirements.txt").write_text("flask\n")
        Path(outside, "package-lock.json").write_text("{}\n")
        env = make_env(self, environ={"RUN_SCA": "true"}, files={"src/app.py": "x = 1\n"})
        env.repo.symlink("vendored", outside)  # type: ignore[attr-defined]
        env.repo.symlink("src/inner", "..")  # type: ignore[attr-defined]
        run_layer3(env)
        self.assertEqual([text for _level, text in messages(env)], ["trivy missing \u2014 dependency CVE scan skipped"])

    def test_a_tree_that_cannot_be_listed_is_not_a_crash(self) -> None:
        env = make_env(self, environ={"RUN_SCA": "true"}, files={"a/b/c.txt": "x"})
        with mock.patch.object(os, "scandir", side_effect=PermissionError(13, "denied")):
            run_layer3(env)
        self.assertEqual(coverage(env), {"L3_dependency_cve": "skipped:trivy not installed"})

    def test_a_very_deep_tree_is_searched_without_running_out_of_descriptors(self) -> None:
        env = make_env(self, environ={"RUN_SCA": "true"})
        current = os.open(env.scan_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for _ in range(300):
                os.mkdir("d", dir_fd=current)
                following = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=current)
                os.close(current)
                current = following
            leaf = os.open("requirements.txt", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=current)
            os.write(leaf, b"x\n")
            os.close(leaf)
        finally:
            os.close(current)
        run_layer3(env)
        self.assertIn(("WARN", OFFLINE_PYTHON), messages(env))

    # -- layer 6
    def test_layer_6_is_off_unless_run_scancode_is_exactly_true(self) -> None:
        for value in (None, "", "false", "TRUE", "1"):
            with self.subTest(value=value):
                log: "list[str]" = []
                environ = {} if value is None else {"RUN_SCANCODE": value}
                env = make_env(self, environ=environ, installed=("scancode",), wrappers=(DirStub("scancode", log=log),))
                run_layer6(env)
                self.assertEqual(coverage(env), {"L6_licence": LAYER6_DISABLED})
                self.assertEqual((log, env.verdict.events), ([], 0))
                self.assertIn("RUN_SCANCODE=true", stdout(env))

    def test_layer_6_on_runs_scancode(self) -> None:
        log: "list[str]" = []
        env = make_env(self, environ={"RUN_SCANCODE": "true"}, installed=("scancode",), wrappers=(DirStub("scancode", log=log),))
        run_layer6(env)
        self.assertEqual(log, ["scancode"])
        self.assertEqual(coverage(env), {"L6_licence": "ran"})
        self.assertIn("Layer 6", stdout(env))

    def test_layer_6_with_scancode_missing(self) -> None:
        env = make_env(self, environ={"RUN_SCANCODE": "true"})
        run_layer6(env)
        self.assertEqual(messages(env), [("WARN", "scancode missing — licence/copyright layer skipped (pip install scancode-toolkit)")])
        self.assertEqual(coverage(env), {"L6_licence": "skipped:scancode not installed"})


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# the per-file loop
# ═══════════════════════════════════════════════════════════════════════════════════════════════
NUL_RULES = RuleSet("test_layers", (
    RuleSpec(id="test_layers/01-excl-with-nul", outcome="fail", message="CWE-78:OS_command_injection_risk", cond=Match(r"danger", excl=r"safe")),
))


def excl_scanner(ctx) -> bool:
    ctx.finish(ctx.run_rules(NUL_RULES).fired)
    return True


def pass_scanner(ctx) -> bool:
    ctx.record_pass()
    return True


class RunFileLayersTests(unittest.TestCase):
    # -- order, views, contexts
    def test_each_file_is_scanned_by_the_universal_layer_and_then_by_its_scanner_in_the_byte_order_of_the_names(self) -> None:
        log: "list[tuple]" = []

        def universal(ctx) -> bool:
            log.append(("universal", ctx.rel, ctx.sniffed))
            return True

        def python(ctx) -> bool:
            log.append(("python", ctx.rel, ctx.sniffed))
            ctx.record_pass()
            return True

        registry = support.make_registry({"python": python, "docs": pass_scanner, "unknown": pass_scanner})
        env = make_env(self, registry=registry, files={"b.py": "x = 1\n", "a/z.py": "x = 2\n", "a.py": "x = 3\n", "README.md": "# t\n"})
        summary = scan_with(env, universal=universal)
        self.assertEqual([entry for entry in log if entry[0] == "universal"],
                         [("universal", rel, False) for rel in ("README.md", "a.py", "a/z.py", "b.py")])
        self.assertEqual(log[:3], [("universal", "README.md", False), ("universal", "a.py", False), ("python", "a.py", False)])
        self.assertEqual(summary, FileLayerSummary(scanned=4, vanished=0, unreadable=0))

    def test_a_scanner_is_called_with_a_fresh_context_that_says_whether_the_file_was_sniffed(self) -> None:
        seen: "list[tuple]" = []

        def fake_dispatch(view, run) -> None:
            seen.append(("first", run("python", False)))
            seen.append(("second", run("rtf", True)))

        def python(ctx) -> bool:
            seen.append(("python", ctx.sniffed, ctx.rel, ctx.path))
            ctx.record_pass()
            return True

        def rtf(ctx) -> bool:
            seen.append(("rtf", ctx.sniffed))
            return False                                                   # "not mine": legal because the context is sniffed

        env = make_env(self, registry=support.make_registry({"python": python, "rtf": rtf}), files={"a.py": "x = 1\n"})
        scan_with(env, dispatch_file=fake_dispatch)
        self.assertEqual(seen, [("python", False, "a.py", env.repo.recorded("a.py")), ("first", True),  # type: ignore[attr-defined]
                                ("rtf", True), ("second", False)])
        self.assertEqual(env.verdict.status_of(env.repo.recorded("a.py")), "PASS")  # type: ignore[attr-defined]

    def test_the_real_classifier_routes_by_name_through_the_registry(self) -> None:
        calls: "list[str]" = []

        def maker(name):
            def scan(ctx) -> bool:
                calls.append("%s:%s" % (name, ctx.rel))
                ctx.record_pass()
                return True
            return scan

        registry = support.make_registry({name: maker(name) for name in ("python", "shell", "docs", "manifest.requirements", "json", "unknown")})
        env = make_env(self, registry=registry, files={"a.py": "", "b.sh": "", "c.md": "", "requirements.txt": "", "d.json": "", "e.xyz": ""})
        scan_with(env)
        self.assertEqual(sorted(calls), sorted(["python:a.py", "shell:b.sh", "docs:c.md", "manifest.requirements:requirements.txt",
                                                "json:d.json", "unknown:e.xyz"]))

    def test_a_scanner_that_is_not_ported_is_reported_and_the_layer_is_partial(self) -> None:
        env = make_env(self, files={"a.py": "x = 1\n"})
        scan_with(env)
        file = env.repo.recorded("a.py")  # type: ignore[attr-defined]
        self.assertEqual(messages(env, file), [("WARN", "engine:scanner_not_ported:python")])
        self.assertEqual(coverage(env)["L4_patterns"], "ran")
        self.assertEqual(coverage(env)["L5_per_language_sast"], "partial:python engine has not ported scanner python yet")

    def test_one_search_policy_is_built_for_the_run_and_it_is_the_hardened_one(self) -> None:
        built: "list[SearchPolicy]" = []
        real = layers.search_policy

        def spy(cfg):
            policy = real(cfg)
            built.append(policy)
            return policy

        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x", "b.py": "y", "c.py": "z"})
        with mock.patch.object(layers, "search_policy", spy):
            scan_with(env)
        self.assertEqual(len(built), 1)
        self.assertFalse(built[0].excl_nul_blind)

    def test_an_exclusion_rule_still_fires_on_a_file_with_a_nul_byte(self) -> None:
        # D-029, end to end: the policy the loop hands to every context decides it (the bash engine was hardened, the pre-hardening policy is blind)
        env = make_env(self, registry=support.make_registry({"python": excl_scanner}),
                       files={"a.py": b"danger here\n\x00\nmore\n", "b.py": b"danger but safe\n\x00\n", "c.py": b"danger here\n"})
        scan_with(env)
        self.assertEqual({rel: env.verdict.status_of(env.repo.recorded(rel)) for rel in ("a.py", "b.py", "c.py")},  # type: ignore[attr-defined]
                         {"a.py": "FAIL", "b.py": "PASS", "c.py": "FAIL"})

    # -- the deadline
    def test_one_deadline_is_computed_per_file_from_its_size_and_the_start_of_the_file(self) -> None:
        seen: "list[tuple]" = []
        real = layers.file_deadline

        def spy(cfg, size, *, now):
            seen.append((size, now))
            return real(cfg, size, now=now)

        env = make_env(self, registry=support.make_registry({"python": pass_scanner, "shell": pass_scanner}),
                       files={"a.py": b"x" * 10, "b.sh": b"y" * 3000, "empty.py": b""})

        def twice(view, run) -> None:
            run("python", False)
            run("shell", False)

        before = time.monotonic()
        with mock.patch.object(layers, "file_deadline", spy):
            scan_with(env, dispatch_file=twice)
        after = time.monotonic()
        self.assertEqual([size for size, _now in seen], [10, 3000, 0], "once per file, with the size the listing gave, never once per scanner call")
        for _size, now in seen:
            self.assertTrue(before <= now <= after, "the clock of the start of the file is time.monotonic()")

    def test_the_universal_layer_and_every_scanner_of_a_file_share_that_deadline(self) -> None:
        outcomes: "list[str]" = []

        def probe(label):
            def fn(ctx) -> bool:
                try:
                    ctx.check_deadline()
                    outcomes.append(label + ":open")
                except ScanBudgetExceeded:
                    outcomes.append(label + ":expired")
                ctx.record_pass()
                return True
            return fn

        def twice(view, run) -> None:
            run("python", False)
            run("shell", False)

        registry = support.make_registry({"python": probe("python"), "shell": probe("shell")})
        for when, want in ((time.monotonic() + 1000.0, "open"), (time.monotonic() - 1000.0, "expired")):
            outcomes.clear()
            env = make_env(self, registry=registry, files={"a.py": "x"})
            with mock.patch.object(layers, "file_deadline", lambda cfg, size, *, now, when=when: when):
                scan_with(env, universal=probe("universal"), dispatch_file=twice)
            self.assertEqual(outcomes, ["universal:" + want, "python:" + want, "shell:" + want])

    def test_a_deadline_that_has_passed_is_a_fail_for_the_file_and_never_a_warn(self) -> None:
        def slow(ctx) -> bool:
            time.sleep(0.01)
            ctx.check_deadline()
            ctx.record_pass()
            return True

        env = make_env(self, environ={"TRANSIT_FILE_BUDGET_S": "0.001", "TRANSIT_FILE_BUDGET_S_PER_MB": "0.000001"},
                       registry=support.make_registry({"python": slow}), files={"a.py": "x = 1\n"})
        scan_with(env)
        file = env.repo.recorded("a.py")  # type: ignore[attr-defined]
        self.assertEqual(fail_messages(env), [(file, "engine:scan_incomplete:python:time_budget")])
        self.assertEqual(env.verdict.status_of(file), "FAIL")
        self.assertEqual(env.verdict.verdict, "FAIL")
        self.assertEqual(coverage(env)["L5_per_language_sast"], "partial:per-file time budget reached")

    def test_a_deadline_that_has_passed_cannot_be_allowlisted_or_lowered(self) -> None:
        def slow(ctx) -> bool:
            time.sleep(0.01)
            ctx.check_deadline()
            return True

        allow = Allowlist({("engine", "a.py"): "x", ("scan_incomplete", "a.py"): "x"})
        env = make_env(self, environ={"TRANSIT_FILE_BUDGET_S": "0.001", "TRANSIT_FILE_BUDGET_S_PER_MB": "0.000001"}, allowlist=allow, threshold=4,
                       min_severity="critical", registry=support.make_registry({"python": slow}), files={"a.py": "x = 1\n"})
        scan_with(env)
        self.assertEqual(env.verdict.verdict, "FAIL")

    def test_a_large_file_gets_a_longer_deadline_than_a_small_one(self) -> None:
        deadlines: "list[float]" = []
        real = layers.file_deadline

        def spy(cfg, size, *, now):
            value = real(cfg, size, now=now)
            deadlines.append(value - now)
            return value

        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a_small.py": b"x", "b_large.py": b"y" * (2 * MIB)})
        with mock.patch.object(layers, "file_deadline", spy):
            scan_with(env)
        self.assertEqual(len(deadlines), 2)
        self.assertAlmostEqual(deadlines[0], 120.0, places=3)
        self.assertAlmostEqual(deadlines[1], 120.0 + 20.0, places=3)

    # -- the universal layer is guarded
    def test_an_exception_in_the_universal_layer_is_a_fail_for_that_file_and_the_scan_goes_on(self) -> None:
        def universal(ctx) -> bool:
            if ctx.rel == "a.py":
                raise RuntimeError("path /etc/shadow")
            return True

        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x", "b.py": "y"})
        summary = scan_with(env, universal=universal)
        a, b = env.repo.recorded("a.py"), env.repo.recorded("b.py")  # type: ignore[attr-defined]
        self.assertEqual(fail_messages(env), [(a, "engine:scanner_error:universal:RuntimeError")])
        self.assertEqual(env.verdict.status_of(a), "FAIL")
        self.assertEqual(env.verdict.status_of(b), "PASS")
        self.assertEqual(summary.scanned, 2)
        self.assertNotIn("shadow", json.dumps(dict(env.verdict.snapshot().file_message)))

    def test_the_family_scanner_still_runs_after_a_failed_universal_layer(self) -> None:
        ran: "list[str]" = []

        def universal(ctx) -> bool:
            raise ValueError("x")

        def python(ctx) -> bool:
            ran.append(ctx.rel)
            ctx.record_pass()
            return True

        env = make_env(self, registry=support.make_registry({"python": python}), files={"a.py": "x"})
        scan_with(env, universal=universal)
        self.assertEqual(ran, ["a.py"])

    def test_a_system_exit_in_the_universal_layer_does_not_end_the_run(self) -> None:
        def universal(ctx) -> bool:
            raise SystemExit(0)

        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x"})
        scan_with(env, universal=universal)
        self.assertEqual(fail_messages(env), [(env.repo.recorded("a.py"), "engine:scanner_error:universal:SystemExit")])  # type: ignore[attr-defined]
        self.assertEqual(env.verdict.verdict, "FAIL")

    def test_the_universal_layer_may_record_nothing(self) -> None:
        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x"})
        scan_with(env, universal=lambda ctx: True)
        self.assertEqual(fail_messages(env), [])
        self.assertEqual(env.verdict.status_of(env.repo.recorded("a.py")), "PASS")  # type: ignore[attr-defined]

    def test_a_signal_exception_in_a_scanner_travels_up_and_the_view_is_released(self) -> None:
        released: "list[str]" = []

        class WatchedView(FileView):
            def release(self) -> None:
                released.append(self.rel)
                super().release()

        def python(ctx) -> bool:
            raise Stop()

        env = make_env(self, registry=support.make_registry({"python": python}), files={"a.py": "x"})
        with mock.patch.object(layers, "FileView", WatchedView):
            with self.assertRaises(Stop):
                scan_with(env)
        self.assertEqual(released, ["a.py"])

    def test_the_classifier_failing_is_not_swallowed(self) -> None:
        env = make_env(self, files={"a.py": "x"})

        def broken(view, run) -> None:
            raise KeyError("bug in the dispatcher")

        with self.assertRaises(KeyError):
            scan_with(env, dispatch_file=broken)

    # -- views
    def test_one_view_per_file_is_released_after_the_file(self) -> None:
        created: "list[FileView]" = []
        released: "list[str]" = []

        class WatchedView(FileView):
            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **kwargs)
                created.append(self)

            def release(self) -> None:
                released.append(self.rel)
                super().release()

        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x", "b.py": "y"})
        with mock.patch.object(layers, "FileView", WatchedView):
            scan_with(env)
        self.assertEqual([view.rel for view in created], ["a.py", "b.py"])
        self.assertEqual(released, ["a.py", "b.py"])
        for view in created:
            self.assertIsNone(view._data, "the bytes of a file are dropped before the next file")  # noqa: SLF001

    def test_a_file_is_read_once_for_the_universal_layer_and_the_scanner(self) -> None:
        reads: "list[str]" = []
        real = FileView.data

        def counting(self):
            if self._data is None:  # noqa: SLF001
                reads.append(self.rel)
            return real(self)

        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x = 1\n"})
        with mock.patch.object(FileView, "data", counting):
            scan_with(env, universal=lambda ctx: bool(ctx.view.data()))
        self.assertEqual(reads, ["a.py"])

    def test_a_file_that_vanished_is_skipped_without_a_trace(self) -> None:
        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x", "gone.py": "y", "z.py": "z"})
        scan = scan_of(env)
        os.unlink(os.path.join(env.scan_dir, "gone.py"))
        summary = run_file_layers(env, scan, universal=no_universal, dispatch_file=classify_file)
        self.assertEqual(summary, FileLayerSummary(scanned=2, vanished=1, unreadable=0))
        self.assertIsNone(env.verdict.status_of(env.repo.recorded("gone.py")))  # type: ignore[attr-defined]
        self.assertEqual(env.verdict.status_of(env.repo.recorded("z.py")), "PASS")  # type: ignore[attr-defined]
        self.assertEqual(env.verdict.verdict, "PASS")

    def test_a_file_replaced_by_a_directory_or_a_link_has_vanished(self) -> None:
        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x", "b.py": "y"})
        scan = scan_of(env)
        os.unlink(os.path.join(env.scan_dir, "a.py"))
        os.mkdir(os.path.join(env.scan_dir, "a.py"))
        os.unlink(os.path.join(env.scan_dir, "b.py"))
        os.symlink("/etc/passwd", os.path.join(env.scan_dir, "b.py"))
        summary = run_file_layers(env, scan, universal=no_universal, dispatch_file=classify_file)
        self.assertEqual((summary.scanned, summary.vanished), (0, 2))

    def test_a_file_that_cannot_be_read_is_a_fail_with_the_reason_and_the_scan_goes_on(self) -> None:
        class Refusing(FileView):
            def data(self) -> bytes:
                if self.rel == "bad.py":
                    raise FileReadError("permission")
                return super().data()

        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"bad.py": "x", "ok.py": "y"})
        with mock.patch.object(layers, "FileView", Refusing):
            summary = scan_with(env)
        bad = env.repo.recorded("bad.py")  # type: ignore[attr-defined]
        self.assertEqual(fail_messages(env), [(bad, "engine:file_unreadable:permission")])
        self.assertEqual(summary, FileLayerSummary(scanned=1, vanished=0, unreadable=1))
        self.assertEqual(env.verdict.status_of(env.repo.recorded("ok.py")), "PASS")  # type: ignore[attr-defined]

    def test_every_reason_of_an_unreadable_file_reaches_the_message(self) -> None:
        for reason in ("permission", "io", "too_large"):
            with self.subTest(reason=reason):
                class Refusing(FileView):
                    def data(self) -> bytes:
                        raise FileReadError(reason)

                env = make_env(self, files={"a.py": "x"})
                with mock.patch.object(layers, "FileView", Refusing):
                    scan_with(env)
                self.assertEqual(fail_messages(env), [(env.repo.recorded("a.py"), "engine:file_unreadable:" + reason)])  # type: ignore[attr-defined]

    def test_a_reason_that_is_not_a_word_never_reaches_a_message(self) -> None:
        class Refusing(FileView):
            def data(self) -> bytes:
                raise FileReadError("/etc/shadow: denied\n[FAIL] forged")

        env = make_env(self, files={"a.py": "x"})
        with mock.patch.object(layers, "FileView", Refusing):
            scan_with(env)
        self.assertEqual(fail_messages(env), [(env.repo.recorded("a.py"), "engine:file_unreadable:unknown")])  # type: ignore[attr-defined]

    def test_a_file_the_host_cannot_hold_is_a_fail_for_that_file_and_the_scan_goes_on(self) -> None:
        class Heavy(FileView):
            def data(self) -> bytes:
                if self.rel == "big.bin":
                    raise MemoryError()
                return super().data()

        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"big.bin": "x", "ok.py": "y"})
        with mock.patch.object(layers, "FileView", Heavy):
            summary = scan_with(env)
        self.assertEqual(fail_messages(env), [(env.repo.recorded("big.bin"), "engine:file_unreadable:memory")])  # type: ignore[attr-defined]
        self.assertEqual(summary.unreadable, 1)
        self.assertEqual(env.verdict.status_of(env.repo.recorded("ok.py")), "PASS")  # type: ignore[attr-defined]

    def test_a_file_over_the_size_limit_is_the_non_downgradable_fail_too_large(self) -> None:
        allow = Allowlist({("engine", "big.py"): "x", ("file_unreadable", "big.py"): "x"})
        env = make_env(self, environ={"TRANSIT_MAX_FILE_MB": "0.00001"}, files={"big.py": b"x" * 100, "tiny.py": b"y"}, allowlist=allow, threshold=4,
                       min_severity="critical", registry=support.make_registry({"python": pass_scanner}))
        summary = scan_with(env)
        self.assertEqual(fail_messages(env), [(env.repo.recorded("big.py"), "engine:file_unreadable:too_large")])  # type: ignore[attr-defined]
        self.assertEqual(summary.unreadable, 1)
        self.assertEqual(env.verdict.status_of(env.repo.recorded("tiny.py")), "PASS")  # type: ignore[attr-defined]

    # -- coverage and summary
    def test_zero_files_is_ran_for_both_layers_and_no_event(self) -> None:
        env = make_env(self)
        summary = run_file_layers(env, ScanList(entries=(), errors=()), universal=no_universal, dispatch_file=classify_file)
        self.assertEqual(summary, FileLayerSummary(0, 0, 0))
        self.assertEqual(coverage(env), {"L4_patterns": "ran", "L5_per_language_sast": "ran"})
        self.assertEqual(env.verdict.events, 0)
        self.assertIn("Layer 5: 0 files scanned", stdout(env))

    def test_a_diff_run_with_no_changed_file_is_ran_and_clean(self) -> None:
        diff = DiffSelection(active=True, keys=frozenset(), stale_ignored=False, unresolved=0)
        env = make_env(self, files={"a.py": "x", "b.py": "y"}, diff=diff)
        scan_with(env)
        self.assertEqual(coverage(env), {"L4_patterns": "ran", "L5_per_language_sast": "ran"})
        self.assertEqual(env.verdict.events, 0)
        self.assertEqual(golden("diff_mode_zero_files")["coverage"]["L4_patterns"], "ran")

    def test_the_files_scanned_line_counts_the_files_that_were_scanned(self) -> None:
        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x", "b.py": "y", "c.py": "z"})
        scan_with(env)
        self.assertIn("Layer 5: 3 files scanned", stdout(env))

    def test_the_noted_reasons_of_the_loop_fold_into_the_state_of_layer_5_only(self) -> None:
        def python(ctx) -> bool:
            ctx.note_incomplete("a tool could not do its job")
            ctx.record_pass()
            return True

        env = make_env(self, registry=support.make_registry({"python": python}), files={"a.py": "x"})
        scan_with(env)
        self.assertEqual(coverage(env), {"L4_patterns": "ran", "L5_per_language_sast": "partial:a tool could not do its job"})

    def test_the_layers_say_ran_after_the_loop_whatever_the_files_said(self) -> None:
        def failing(ctx) -> bool:
            ctx.record_fail("CWE-78:OS_command_injection_risk")
            return True

        env = make_env(self, registry=support.make_registry({"python": failing}), files={"a.py": "x"})
        scan_with(env)
        self.assertEqual(env.verdict.verdict, "FAIL")
        self.assertEqual(coverage(env), {"L4_patterns": "ran", "L5_per_language_sast": "ran"})

    # -- symlinks
    def link_env(self, **kwargs) -> RunEnv:
        env = make_env(self, registry=support.make_registry({"python": pass_scanner, "docs": pass_scanner}), **kwargs)
        return env

    def test_a_link_with_an_absolute_target_is_a_fail_on_the_link(self) -> None:
        env = self.link_env(files={"a.py": "x"})
        env.repo.symlink("abs", "/etc/passwd")  # type: ignore[attr-defined]
        scan_with(env)
        self.assertEqual(fail_messages(env), [(env.repo.recorded("abs"), "symlink:target_outside_the_scanned_directory")])  # type: ignore[attr-defined]
        self.assertEqual(env.verdict.verdict, "FAIL")

    def test_a_relative_link_that_climbs_above_the_root_is_a_fail(self) -> None:
        env = self.link_env(files={"a.py": "x", "sub/b.py": "y"})
        env.repo.symlink("up", "../outside")  # type: ignore[attr-defined]
        env.repo.symlink("sub/up2", "../../outside")  # type: ignore[attr-defined]
        env.repo.symlink("sub/ok", "../a.py")  # type: ignore[attr-defined]
        scan_with(env)
        self.assertEqual(sorted(fail_messages(env)), sorted([
            (env.repo.recorded("up"), "symlink:target_outside_the_scanned_directory"),  # type: ignore[attr-defined]
            (env.repo.recorded("sub/up2"), "symlink:target_outside_the_scanned_directory")]))  # type: ignore[attr-defined]

    def test_any_other_link_is_a_warn_and_is_never_followed(self) -> None:
        env = self.link_env(files={"a.py": "x", "sub/b.py": "y"})
        env.repo.symlink("inner", "a.py")  # type: ignore[attr-defined]
        env.repo.symlink("sub/dir", "../sub")  # type: ignore[attr-defined]
        env.repo.symlink("dangling", "nowhere")  # type: ignore[attr-defined]
        scan_with(env)
        warn = "symlink:not_followed_its_target_is_not_scanned_through_the_link"
        for rel in ("inner", "sub/dir", "dangling"):
            self.assertEqual(messages(env, env.repo.recorded(rel)), [("WARN", warn)], rel)  # type: ignore[attr-defined]
        self.assertEqual(env.verdict.verdict, "PASS")
        self.assertEqual(fail_messages(env), [])

    def test_the_target_text_is_what_decides_not_where_it_leads(self) -> None:
        env = self.link_env(files={"a.py": "x"})
        outside = tempfile.mkdtemp(prefix="transit-test-outside-")
        self.addCleanup(shutil.rmtree, outside, True)
        env.repo.symlink("to_outside", outside)  # type: ignore[attr-defined]
        env.repo.symlink("to_inside", os.path.join(env.scan_dir, "a.py"))  # type: ignore[attr-defined]
        scan_with(env)
        self.assertEqual({f for f, _m in fail_messages(env)}, {env.repo.recorded("to_outside"), env.repo.recorded("to_inside")})  # type: ignore[attr-defined]

    def test_a_link_fail_is_allowlisted_and_lowered_like_any_other_finding(self) -> None:
        env = self.link_env(files={"a.py": "x"}, allowlist=Allowlist({("symlink", "abs"): "vendored"}))
        env.repo.symlink("abs", "/etc/passwd")  # type: ignore[attr-defined]
        scan_with(env)
        self.assertEqual(env.verdict.verdict, "PASS")
        self.assertEqual(messages(env, env.repo.recorded("abs")),  # type: ignore[attr-defined]
                         [("WARN", "ALLOWED:symlink:target_outside_the_scanned_directory (reason: vendored)")])

    def test_a_link_with_a_hostile_name_is_printable_on_both_streams(self) -> None:
        env = self.link_env(files={"a.py": "x"})
        env.repo.symlink("raw\x1b]0;pwned\x07\u202e", "/etc/passwd")  # type: ignore[attr-defined]
        env.repo.symlink("other\x1b[31m", "a.py")  # type: ignore[attr-defined]
        scan_with(env)
        self.assertEqual(env.verdict.counters.fail, 1)
        for stream in (env.out, env.err):  # type: ignore[attr-defined]
            raw = support.strip_engine_colours(stream.getvalue())
            self.assertFalse([b for b in raw if b < 0x20 and b != 0x0A], raw)
        self.assertNotIn("\u202e", stderr(env))

    def test_a_link_is_not_subject_to_the_diff_selection(self) -> None:
        diff = DiffSelection(active=True, keys=frozenset(), stale_ignored=False, unresolved=0)
        env = self.link_env(files={"a.py": "x"}, diff=diff)
        env.repo.symlink("abs", "/etc/passwd")  # type: ignore[attr-defined]
        scan_with(env)
        self.assertEqual(len(fail_messages(env)), 1)

    def test_the_content_a_link_points_at_is_not_scanned_through_it(self) -> None:
        seen: "list[str]" = []

        def recording(ctx) -> bool:
            seen.append(ctx.rel)
            ctx.record_pass()
            return True

        env = make_env(self, registry=support.make_registry({"python": recording}), files={"real.py": "x"})
        env.repo.symlink("alias.py", "real.py")  # type: ignore[attr-defined]
        scan_with(env)
        self.assertEqual(seen, ["real.py"])

    # -- the listing did not complete
    def failed_listing(self, env: RunEnv, errors: "tuple[tuple[str, str], ...]", **extra) -> FileLayerSummary:
        scan = ScanList(entries=extra.pop("entries", ()), errors=errors, listing_exit=1, **extra)
        return run_file_layers(env, scan, universal=no_universal, dispatch_file=classify_file)

    def test_an_unlistable_directory_is_the_fail_on_global_and_the_two_layers_are_skipped(self) -> None:
        env = make_env(self)
        self.failed_listing(env, (("sub", "permission"),))
        self.assertIn(("FAIL", "engine:file_listing_failed"), messages(env))
        self.assertEqual(env.verdict.verdict, "FAIL")
        want = "skipped:file listing failed (find exit 1)"
        self.assertEqual(coverage(env), {"L4_patterns": want, "L5_per_language_sast": want})

    def test_each_unlistable_directory_is_a_fail_on_the_directory_never_a_warn(self) -> None:
        env = make_env(self)
        self.failed_listing(env, (("a", "permission"), ("b/c", "io"), ("d", "too_deep")))
        self.assertEqual(fail_messages(env), [
            (GLOBAL_FILE, "engine:file_listing_failed"),
            (env.repo.recorded("a"), "engine:directory_unreadable:permission"),  # type: ignore[attr-defined]
            (env.repo.recorded("b/c"), "engine:directory_unreadable:io"),  # type: ignore[attr-defined]
            (env.repo.recorded("d"), "engine:directory_unreadable:too_deep")])  # type: ignore[attr-defined]
        for rel in ("a", "b/c", "d"):
            self.assertEqual(env.verdict.status_of(env.repo.recorded(rel)), "FAIL")  # type: ignore[attr-defined]
        self.assertEqual(env.verdict.counters.warn, 0)

    def test_the_listing_fail_is_not_allowlisted_and_not_lowered(self) -> None:
        allow = Allowlist({("engine", "."): "x", ("directory_unreadable", "sub"): "x", ("file_listing_failed", "."): "x", ("engine", "sub"): "x"})
        env = make_env(self, allowlist=allow, threshold=4, min_severity="critical")
        self.failed_listing(env, (("sub", "permission"),))
        self.assertEqual(env.verdict.counters.fail, 2)

    def test_the_root_that_cannot_be_opened_is_a_fail_on_the_scan_directory_itself(self) -> None:
        env = make_env(self)
        self.failed_listing(env, ((".", "permission"),))
        self.assertIn((env.scan_dir, "engine:directory_unreadable:permission"), fail_messages(env))

    def test_the_first_two_hundred_are_listed_and_the_rest_summarised(self) -> None:
        for count, want_summary in ((200, None), (201, "engine:directory_unreadable:more_not_listed_1"),
                                    (250, "engine:directory_unreadable:more_not_listed_50")):
            with self.subTest(count=count):
                env = make_env(self)
                self.failed_listing(env, tuple(("d%03d" % i, "io") for i in range(count)))
                fails = fail_messages(env)
                unreadable = [(f, m) for f, m in fails if m.startswith("engine:directory_unreadable:")]
                self.assertEqual(len(unreadable), min(count, 200) + (1 if want_summary else 0))
                self.assertEqual([f for f, m in unreadable[:200]], [env.repo.recorded("d%03d" % i) for i in range(min(count, 200))])  # type: ignore[attr-defined]
                if want_summary:
                    self.assertEqual(unreadable[-1], (env.scan_dir, want_summary))
                else:
                    self.assertFalse([m for _f, m in unreadable if "more_not_listed" in m])

    def test_the_files_that_were_listed_are_still_scanned_when_the_listing_failed(self) -> None:
        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x"})
        scan = scan_of(env)
        scan = ScanList(entries=scan.entries, errors=(("lost", "permission"),), listing_exit=1)
        summary = run_file_layers(env, scan, universal=no_universal, dispatch_file=classify_file)
        self.assertEqual(summary.scanned, 1)
        self.assertEqual(env.verdict.status_of(env.repo.recorded("a.py")), "PASS")  # type: ignore[attr-defined]

    def test_a_listing_exit_status_without_a_directory_is_still_a_failed_listing(self) -> None:
        env = make_env(self)
        run_file_layers(env, ScanList(entries=(), errors=(), listing_exit=2), universal=no_universal, dispatch_file=classify_file)
        self.assertIn(("FAIL", "engine:file_listing_failed"), messages(env))
        self.assertEqual(coverage(env)["L4_patterns"], "skipped:file listing failed (find exit 2)")

    def test_a_directory_error_without_an_exit_status_is_still_a_failed_listing(self) -> None:
        env = make_env(self)
        run_file_layers(env, ScanList(entries=(), errors=(("x", "io"),)), universal=no_universal, dispatch_file=classify_file)
        self.assertEqual(coverage(env)["L5_per_language_sast"], "skipped:file listing failed (find exit 1)")

    def test_a_reason_that_is_not_a_word_never_reaches_a_directory_message(self) -> None:
        env = make_env(self)
        self.failed_listing(env, (("x", "permission denied: /etc/shadow"),))
        self.assertIn((env.repo.recorded("x"), "engine:directory_unreadable:unknown"), fail_messages(env))  # type: ignore[attr-defined]

    def test_a_directory_named_like_a_control_sequence_is_a_path_not_text_of_the_message(self) -> None:
        env = make_env(self)
        self.failed_listing(env, (("x\x1b]0;pwned\x07", "io"),))
        raw = support.strip_engine_colours(env.err.getvalue())  # type: ignore[attr-defined]
        self.assertFalse([b for b in raw if b < 0x20 and b != 0x0A], raw)

    def test_a_real_tree_that_is_too_deep_gives_the_fail_through_the_real_listing(self) -> None:
        env = make_env(self, registry=support.make_registry({"python": pass_scanner}), files={"a.py": "x"})
        deepest = os.path.join(env.scan_dir, *(["d"] * 515))
        os.makedirs(deepest)
        scan_with(env)
        self.assertIn((GLOBAL_FILE, "engine:file_listing_failed"), fail_messages(env))
        self.assertTrue([m for _f, m in fail_messages(env) if m == "engine:directory_unreadable:too_deep"])
        self.assertEqual(coverage(env)["L4_patterns"], "skipped:file listing failed (find exit 1)")
        self.assertEqual(env.verdict.status_of(env.repo.recorded("a.py")), "PASS")  # type: ignore[attr-defined]

    # -- nothing scanned
    def exclusions_of(self, env: RunEnv) -> Exclusions:
        exclusions, _notes = load_exclusions(env.scan_dir, cfg=env.cfg)
        return exclusions

    def test_a_transitignore_that_removed_every_file_is_the_fail_on_global_and_the_layers_are_skipped(self) -> None:
        env = make_env(self, files={".transitignore": "*\n", "a.py": "x", "b/c.py": "y"})
        env.exclusions = self.exclusions_of(env)
        scan_with(env)
        self.assertEqual(fail_messages(env), [(GLOBAL_FILE, "engine:nothing_scanned")])
        want = "skipped:nothing scanned (every file excluded)"
        self.assertEqual(coverage(env), {"L4_patterns": want, "L5_per_language_sast": want})
        self.assertEqual(env.verdict.verdict, "FAIL")
        self.assertEqual(golden("transitignore_everything")["coverage"]["L4_patterns"], want)

    def test_the_console_says_how_many_patterns_removed_everything(self) -> None:
        env = make_env(self, files={".transitignore": "*\n# c\n*.log\n", "a.py": "x"})
        env.exclusions = self.exclusions_of(env)
        scan_with(env)
        self.assertIn(".transitignore removed every file from the scan (2 pattern(s)): nothing was examined", stderr(env))

    def test_the_message_and_the_file_are_the_ones_of_the_golden_report(self) -> None:
        report = golden("transitignore_everything")
        self.assertEqual([(f["file"], f["message"]) for f in report["findings"]], [(GLOBAL_FILE, "engine:nothing_scanned")])
        self.assertIn("[FAIL] engine:nothing_scanned", report["file_results"][GLOBAL_FILE]["messages"])

    def test_the_control_files_do_not_count_as_something_that_was_examined(self) -> None:
        # [!.]* keeps only the dot files: the repository's own .transitignore is all that is left, and it is scanned, but nothing else was
        env = make_env(self, files={".transitignore": "[!.]*\n", "a.py": "x", "b.py": "y"}, registry=support.make_registry({"unknown": pass_scanner}))
        env.exclusions = self.exclusions_of(env)
        scan = scan_of(env)
        self.assertEqual([entry.rel for entry in scan.entries], [".transitignore"])
        run_file_layers(env, scan, universal=no_universal, dispatch_file=classify_file)
        self.assertIn((GLOBAL_FILE, "engine:nothing_scanned"), fail_messages(env))
        self.assertEqual(env.verdict.status_of(env.repo.recorded(".transitignore")), "PASS", "the control file is still scanned")  # type: ignore[attr-defined]
        self.assertEqual(coverage(env)["L4_patterns"], "skipped:nothing scanned (every file excluded)")

    def test_a_diff_run_whose_changed_files_were_all_excluded_is_nothing_scanned_too(self) -> None:
        env = make_env(self, files={".transitignore": "a.py\n", "a.py": "x", "b.py": "y"})
        keys = frozenset({env.repo.recorded("a.py")})  # type: ignore[attr-defined]
        env.diff = DiffSelection(active=True, keys=keys, stale_ignored=False, unresolved=0)
        env.exclusions = self.exclusions_of(env)
        scan = scan_of(env)
        self.assertEqual(scan.entries, ())
        self.assertTrue(scan.nothing_scanned)
        run_file_layers(env, scan, universal=no_universal, dispatch_file=classify_file)
        self.assertEqual(fail_messages(env), [(GLOBAL_FILE, "engine:nothing_scanned")])

    def test_a_diff_run_with_a_changed_file_that_survived_is_not(self) -> None:
        env = make_env(self, files={".transitignore": "a.py\n", "a.py": "x", "b.py": "y"}, registry=support.make_registry({"python": pass_scanner}))
        keys = frozenset({env.repo.recorded("a.py"), env.repo.recorded("b.py")})  # type: ignore[attr-defined]
        env.diff = DiffSelection(active=True, keys=keys, stale_ignored=False, unresolved=0)
        env.exclusions = self.exclusions_of(env)
        scan_with(env)
        self.assertEqual(fail_messages(env), [])
        self.assertEqual(coverage(env)["L4_patterns"], "ran")

    def test_the_flag_of_the_listing_is_what_decides_not_the_count_of_the_entries(self) -> None:
        # a repository whose patterns removed only an empty directory or a control file has entries == () and excluded_by_patterns > 0 and is NOT
        # nothing scanned; the listing says so by the flag
        env = make_env(self)
        run_file_layers(env, ScanList(entries=(), errors=(), excluded_by_patterns=3, nothing_scanned=False), universal=no_universal,
                        dispatch_file=classify_file)
        self.assertEqual(fail_messages(env), [])
        self.assertEqual(coverage(env), {"L4_patterns": "ran", "L5_per_language_sast": "ran"})

    def test_a_flag_with_files_still_in_the_list_is_the_fail(self) -> None:
        env = make_env(self, files={"a.py": "x"}, registry=support.make_registry({"python": pass_scanner}))
        scan = scan_of(env)
        scan = ScanList(entries=scan.entries, errors=(), excluded_by_patterns=1, nothing_scanned=True)
        run_file_layers(env, scan, universal=no_universal, dispatch_file=classify_file)
        self.assertIn((GLOBAL_FILE, "engine:nothing_scanned"), fail_messages(env))

    def test_nothing_scanned_cannot_be_allowlisted_or_lowered(self) -> None:
        allow = Allowlist({("engine", "."): "x", ("nothing_scanned", "."): "x", ("engine", GLOBAL_FILE): "x", ("nothing_scanned", GLOBAL_FILE): "x"})
        env = make_env(self, files={".transitignore": "*\n", "a.py": "x"}, allowlist=allow, threshold=4, min_severity="critical")
        env.exclusions = self.exclusions_of(env)
        scan_with(env)
        self.assertEqual(env.verdict.verdict, "FAIL")
        self.assertEqual(env.verdict.counters.fail, 1)

    def test_a_listing_failure_takes_precedence_over_nothing_scanned_as_in_bash(self) -> None:
        env = make_env(self)
        scan = ScanList(entries=(), errors=(("x", "io"),), listing_exit=1, nothing_scanned=True)
        run_file_layers(env, scan, universal=no_universal, dispatch_file=classify_file)
        self.assertNotIn((GLOBAL_FILE, "engine:nothing_scanned"), fail_messages(env))
        self.assertEqual(coverage(env)["L4_patterns"], "skipped:file listing failed (find exit 1)")

    def test_an_empty_repository_a_builtin_exclusion_and_no_pattern_are_ran(self) -> None:
        for files in ({}, {"node_modules/x/a.js": "x"}, {"a.py": "x"}):
            with self.subTest(files=sorted(files)):
                env = make_env(self, files=files, registry=support.make_registry({"python": pass_scanner, "js": pass_scanner}))
                scan_with(env)
                self.assertEqual(fail_messages(env), [])
                self.assertEqual(coverage(env), {"L4_patterns": "ran", "L5_per_language_sast": "ran"})

    def test_files_removed_by_a_pattern_while_others_survive_are_ran(self) -> None:
        env = make_env(self, files={".transitignore": "docs\n", "docs/x.py": "x", "a.py": "y"}, registry=support.make_registry({"python": pass_scanner}))
        env.exclusions = self.exclusions_of(env)
        scan_with(env)
        self.assertEqual(fail_messages(env), [])
        self.assertEqual(coverage(env)["L4_patterns"], "ran")

    # -- the console
    def test_the_progress_line_is_drawn_for_each_file_and_every_byte_is_printable(self) -> None:
        hostile = "raw\x1b]0;pwned\x07‮<img src=x onerror=1>.txt"
        env = make_env(self, files={hostile: "x", "plain.txt": "y"}, err_is_tty=True, registry=support.make_registry({"docs": pass_scanner}))
        scan_with(env)
        raw = env.err.getvalue()  # type: ignore[attr-defined]
        self.assertIn(b"[L5]", raw)
        self.assertIn(b"[1/2]", raw)
        self.assertIn(b"[2/2]", raw)
        text = support.strip_engine_colours(raw).replace(b"\r\x1b[K", b"")
        self.assertFalse([b for b in text if b < 0x20 and b != 0x0A], text)
        self.assertNotIn("‮".encode(), text)

    def test_the_progress_line_is_not_drawn_when_stderr_is_not_a_terminal_or_when_quiet(self) -> None:
        env = make_env(self, files={"a.txt": "x"}, err_is_tty=False, registry=support.make_registry({"docs": pass_scanner}))
        scan_with(env)
        self.assertNotIn(b"[L5]", env.err.getvalue())  # type: ignore[attr-defined]
        quiet = make_env(self, files={"a.txt": "x"}, err_is_tty=True, verbosity="quiet", registry=support.make_registry({"docs": pass_scanner}))
        scan_with(quiet)
        self.assertEqual(quiet.err.getvalue(), b"")  # type: ignore[attr-defined]

    def test_the_progress_line_is_erased_before_the_summary(self) -> None:
        env = make_env(self, files={"a.txt": "x"}, err_is_tty=True, registry=support.make_registry({"docs": pass_scanner}))
        scan_with(env)
        self.assertTrue(env.err.getvalue().endswith(b"\r\x1b[K"))  # type: ignore[attr-defined]
        self.assertIn("Layer 5: 1 files scanned", stdout(env))

    def test_a_hostile_file_name_in_a_finding_is_printable_on_both_streams(self) -> None:
        hostile = "raw\x1b]0;pwned\x07.txt"

        def universal(ctx) -> bool:
            ctx.record_fail("CWE-798:hardcoded_credential")
            return True

        env = make_env(self, files={hostile: "x"}, registry=support.make_registry({"docs": pass_scanner}))
        scan_with(env, universal=universal)
        for stream in (env.out, env.err):  # type: ignore[attr-defined]
            raw = support.strip_engine_colours(stream.getvalue())
            self.assertFalse([b for b in raw if b < 0x20 and b != 0x0A], raw)

    # -- the allowlist applies to what the loop records
    def test_a_rule_fail_of_a_scanner_still_goes_through_the_allowlist_and_the_threshold(self) -> None:
        def failing(ctx) -> bool:
            ctx.record_fail("CWE-78:OS_command_injection_risk")
            return True

        env = make_env(self, registry=support.make_registry({"python": failing}), files={"a.py": "x"},
                       allowlist=Allowlist({("CWE-78", "a.py"): "reviewed"}))
        scan_with(env)
        self.assertEqual(env.verdict.verdict, "PASS")
        self.assertEqual(env.verdict.snapshot().counters.warn, 1)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class AskedNotToDowngradeTests(unittest.TestCase):
    """The ``Verdict`` exempts every ``engine:`` message from the allowlist and the threshold by its prefix, so a real one cannot tell whether the
    layer ASKED for a non-downgradable FAIL. A recording verdict can: each FAIL of the engine itself says ``downgradable=False``, each finding that
    comes from a tool or from the repository leaves it True (an allowlist entry can lower those)."""

    def recording(self, **kwargs) -> RunEnv:
        env = make_env(self, **kwargs)
        env.verdict = support.FakeVerdict()  # type: ignore[assignment]
        return env

    def fails(self, env: RunEnv) -> "list[tuple]":
        return [(entry[1], entry[2], entry[3], entry[4]) for entry in env.verdict.of("fail")]  # type: ignore[attr-defined]

    def test_a_tool_error(self) -> None:
        env = self.recording(installed=("gitleaks",), wrappers=(DirStub("gitleaks", raises=KeyError("x")),))
        run_slot(env, LAYER1_SLOTS[0])
        self.assertEqual(self.fails(env), [(env.scan_dir, "engine:tool_error:gitleaks:KeyError", None, False)])

    def test_the_findings_of_a_tool_stay_downgradable_and_carry_their_severity(self) -> None:
        env = self.recording(installed=("semgrep",))
        records = (Record("fail", env.scan_dir + "/a.py", "semgrep[x]:r:line1:ERROR:m", "HIGH"),)
        env.wrappers = support.FakeWrappers(DirStub("semgrep", ToolOutcome(layer_state="ran", records=records)))  # type: ignore[assignment]
        run_slot(env, LAYER2_SLOTS[0])
        self.assertEqual(self.fails(env), [(env.scan_dir + "/a.py", "semgrep[x]:r:line1:ERROR:m", "HIGH", True)])

    def test_the_listing_failure_and_every_unlistable_directory_and_the_summary(self) -> None:
        env = self.recording()
        errors = tuple(("d%03d" % i, "permission") for i in range(201))
        run_file_layers(env, ScanList(entries=(), errors=errors, listing_exit=1), universal=no_universal, dispatch_file=classify_file)
        fails = self.fails(env)
        self.assertEqual(len(fails), 1 + 201)
        self.assertEqual(fails[0], (GLOBAL_FILE, "engine:file_listing_failed", None, False))
        self.assertEqual(fails[-1], (env.scan_dir, "engine:directory_unreadable:more_not_listed_1", None, False))
        self.assertTrue(all(entry[3] is False for entry in fails), fails)

    def test_nothing_scanned(self) -> None:
        env = self.recording()
        run_file_layers(env, ScanList(entries=(), errors=(), nothing_scanned=True), universal=no_universal, dispatch_file=classify_file)
        self.assertEqual(self.fails(env), [(GLOBAL_FILE, "engine:nothing_scanned", None, False)])

    def test_a_file_that_cannot_be_read(self) -> None:
        class Refusing(FileView):
            def data(self) -> bytes:
                raise FileReadError("io")

        env = self.recording(files={"a.py": "x"})
        with mock.patch.object(layers, "FileView", Refusing):
            scan_with(env)
        self.assertEqual(self.fails(env), [(env.repo.recorded("a.py"), "engine:file_unreadable:io", None, False)])  # type: ignore[attr-defined]

    def test_a_file_the_host_cannot_hold(self) -> None:
        class Heavy(FileView):
            def data(self) -> bytes:
                raise MemoryError()

        env = self.recording(files={"a.py": "x"})
        with mock.patch.object(layers, "FileView", Heavy):
            scan_with(env)
        self.assertEqual(self.fails(env), [(env.repo.recorded("a.py"), "engine:file_unreadable:memory", None, False)])  # type: ignore[attr-defined]

    def test_a_symbolic_link_stays_downgradable(self) -> None:
        env = self.recording(files={"a.py": "x"})
        env.repo.symlink("abs", "/etc/passwd")  # type: ignore[attr-defined]
        scan_with(env)
        self.assertEqual(self.fails(env), [(env.repo.recorded("abs"), "symlink:target_outside_the_scanned_directory", None, True)])  # type: ignore[attr-defined]


class FinaliseTests(unittest.TestCase):
    def test_nothing_is_recorded_when_everything_loaded(self) -> None:
        env = make_env(self)
        finalise(env)
        self.assertEqual(env.verdict.events, 0)
        self.assertEqual(coverage(env), {})

    def test_a_scanner_module_that_failed_to_load_is_a_warn_and_makes_layer_5_partial(self) -> None:
        env = make_env(self, registry=support.make_registry({}, load_errors=("shell:ImportError", "go:duplicate_scanner_id")))
        env.verdict.record_layer("L5_per_language_sast", "ran")
        finalise(env)
        self.assertEqual(messages(env), [("WARN", "engine:scanner_load_error:shell:ImportError"),
                                         ("WARN", "engine:scanner_load_error:go:duplicate_scanner_id")])
        self.assertEqual(coverage(env), {"L5_per_language_sast": "partial:scanner module failed to load"})
        self.assertEqual(env.verdict.verdict, "PASS")

    def test_a_wrapper_module_that_failed_to_load_is_a_warn_and_makes_layer_5_partial(self) -> None:
        env = make_env(self)
        env.wrappers = support.FakeWrappers(load_errors=("gitleaks_wrapper:SyntaxError",))  # type: ignore[assignment]
        env.verdict.record_layer("L5_per_language_sast", "ran")
        finalise(env)
        self.assertEqual(messages(env), [("WARN", "engine:wrapper_load_error:gitleaks_wrapper:SyntaxError")])
        self.assertEqual(coverage(env), {"L5_per_language_sast": "partial:scanner module failed to load"})

    def test_scanner_errors_come_before_wrapper_errors_and_each_once(self) -> None:
        env = make_env(self, registry=support.make_registry({}, load_errors=("a:E1", "b:E2")))
        env.wrappers = support.FakeWrappers(load_errors=("c_wrapper:E3",))  # type: ignore[assignment]
        finalise(env)
        self.assertEqual([text for _l, text in messages(env)],
                         ["engine:scanner_load_error:a:E1", "engine:scanner_load_error:b:E2", "engine:wrapper_load_error:c_wrapper:E3"])
        self.assertEqual(env.verdict.counters.warn, 3)

    def test_a_load_error_is_a_warn_and_never_a_fail(self) -> None:
        env = make_env(self, registry=support.make_registry({}, load_errors=("a:E1",)))
        finalise(env)
        self.assertEqual((env.verdict.verdict, env.verdict.counters.fail), ("PASS", 0))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RunAllTests(unittest.TestCase):
    def test_the_order_is_the_one_of_the_bash_main_block(self) -> None:
        env = make_env(self)
        log: "list[str]" = []
        scan = ScanList(entries=(), errors=())
        summary = FileLayerSummary(7, 8, 9)

        def recorder(name, result=None):
            def fn(*args, **kwargs):
                log.append(name)
                if name == "files":
                    self.assertIs(args[0], env)
                    self.assertIs(args[1], scan)
                    kwargs_seen.update(kwargs)
                return result
            return fn

        kwargs_seen: dict = {}
        with contextlib.ExitStack() as stack:
            for name in ("run_layer1", "run_layer2", "run_layer3", "run_layer6", "finalise"):
                stack.enter_context(mock.patch.object(layers, name, recorder(name)))
            stack.enter_context(mock.patch.object(layers, "run_file_layers", recorder("files", summary)))
            self.assertIs(run_all(env, scan), summary)
        self.assertEqual(log, ["run_layer1", "run_layer2", "run_layer3", "files", "run_layer6", "finalise"])

    def test_the_universal_layer_and_the_classifier_are_the_real_ones(self) -> None:
        from transit.scanners import universal
        env = make_env(self)
        seen: dict = {}

        def files(env_, scan_, **kwargs):
            seen.update(kwargs)
            return FileLayerSummary(0, 0, 0)

        with mock.patch.object(layers, "run_file_layers", files):
            run_all(env, ScanList(entries=(), errors=()))
        self.assertIs(seen["universal"], universal.scan)
        self.assertIs(seen["dispatch_file"], classify_file)

    def test_a_patched_universal_layer_is_what_runs(self) -> None:
        from transit.scanners import universal
        calls: "list[str]" = []

        def fake(ctx) -> bool:
            calls.append(ctx.rel)
            return True

        env = make_env(self, files={"a.py": "x"}, registry=support.make_registry({"python": pass_scanner}))
        with mock.patch.object(universal, "scan", fake):
            run_all(env, scan_of(env))
        self.assertEqual(calls, ["a.py"])

    def test_the_clean_fixture_reproduces_the_golden_report_state(self) -> None:
        from transit.scanners import universal

        def python(ctx) -> bool:
            if ctx.file_tool("bandit").status == "missing":
                ctx.record_warn("bandit missing")
            ctx.finish(False)
            return True

        def shell(ctx) -> bool:
            if ctx.file_tool("shellcheck").status == "missing":
                ctx.record_warn("shellcheck missing")
            ctx.finish(False)
            return True

        registry = support.make_registry({"python": python, "shell": shell, "docs": pass_scanner, "manifest.requirements": pass_scanner})
        env = make_env(self, registry=registry)
        shutil.rmtree(env.scan_dir)
        shutil.copytree(CLEAN_FIXTURE, env.scan_dir)
        with mock.patch.object(universal, "scan", no_universal):
            summary = run_all(env, scan_of(env))
        want = golden("clean")
        snap = env.verdict.snapshot()
        self.assertEqual(dict(snap.coverage), want["coverage"])
        self.assertEqual(summary, FileLayerSummary(4, 0, 0))
        self.assertEqual((snap.counters.pass_, snap.counters.warn, snap.counters.fail), (want["summary"]["pass"], want["summary"]["warn"], 0))
        self.assertEqual(snap.verdict, want["verdict"])
        got = {}
        for path, status in snap.file_status.items():
            rel = GLOBAL_FILE if path == GLOBAL_FILE else path[len(env.scan_dir) + 1:]
            got[rel] = {"status": status, "messages": sorted(m for m in
                        ("[%s] %s" % pair for pair in support.parse_file_message(snap.file_message.get(path, ""))))}
        for rel, wanted in want["file_results"].items():
            self.assertEqual(got[rel]["status"], wanted["status"], rel)
            self.assertEqual(got[rel]["messages"], sorted(wanted["messages"]), rel)
        self.assertEqual(sorted(got), sorted(want["file_results"]))

    def golden_run(self, name: str, fixture: str, *, ignore: "str | None" = None, diff_active: bool = False):
        """``run_all`` over a copy of a fixture with nothing installed, the way ``pipeline`` would drive it (it records the ``.transitignore`` WARN of its
        step 8 itself), and the golden report of the hardened bash engine to compare with."""
        from transit.scanners import universal
        env = make_env(self)
        shutil.rmtree(env.scan_dir)
        shutil.copytree(ROOT / "tests" / "fixtures" / fixture, env.scan_dir)
        if ignore is not None:
            Path(env.scan_dir, ".transitignore").write_text(ignore)
            env.exclusions, _notes = load_exclusions(env.scan_dir, cfg=env.cfg)
            env.verdict.record_warn(GLOBAL_FILE, "transitignore:exclusions_applied(%d pattern(s))" % len(env.exclusions.patterns))
        if diff_active:
            env.diff = DiffSelection(active=True, keys=frozenset(), stale_ignored=False, unresolved=0)
        with mock.patch.object(universal, "scan", no_universal):
            summary = run_all(env, scan_of(env))
        return env, summary, golden(name)

    def test_the_transitignore_everything_golden_is_reproduced(self) -> None:
        env, _summary, want = self.golden_run("transitignore_everything", "vulnerable", ignore="*\n")
        snap = env.verdict.snapshot()
        self.assertEqual(dict(snap.coverage), want["coverage"])
        self.assertEqual(sorted("[%s] %s" % pair for pair in messages(env)), sorted(want["file_results"][GLOBAL_FILE]["messages"]))
        self.assertEqual([{k: v for k, v in record.to_json().items() if k != "column"} for record in snap.findings], want["findings"])  # the normaliser drops column
        self.assertEqual((snap.counters.pass_, snap.counters.warn, snap.counters.fail), (want["summary"]["pass"], want["summary"]["warn"], want["summary"]["fail"]))
        self.assertEqual(snap.verdict, "FAIL")
        self.assertEqual(sorted(snap.file_status), [GLOBAL_FILE], "nothing was examined: no file has a status")

    def test_the_diff_mode_zero_files_golden_is_reproduced(self) -> None:
        env, summary, want = self.golden_run("diff_mode_zero_files", "clean", diff_active=True)
        snap = env.verdict.snapshot()
        self.assertEqual(dict(snap.coverage), want["coverage"])
        self.assertEqual(sorted("[%s] %s" % pair for pair in messages(env)), sorted(want["file_results"][GLOBAL_FILE]["messages"]))
        self.assertEqual(snap.findings, ())
        self.assertEqual((snap.counters.pass_, snap.counters.warn, snap.counters.fail), (want["summary"]["pass"], want["summary"]["warn"], want["summary"]["fail"]))
        self.assertEqual((snap.verdict, summary), ("PASS", FileLayerSummary(0, 0, 0)))

    def test_every_required_layer_has_a_state_after_a_run_with_the_layers_on_and_nothing_installed(self) -> None:
        from transit.scanners import universal
        env = make_env(self, environ={"RUN_SCA": "true", "RUN_SCANCODE": "true"}, files={"requirements.txt": "x\n"},
                       registry=support.make_registry({"manifest.requirements": pass_scanner}))
        with mock.patch.object(universal, "scan", no_universal):
            run_all(env, scan_of(env))
        got = coverage(env)
        self.assertEqual(sorted(got), sorted(COVERAGE_LAYERS))
        self.assertEqual(got, golden("layers_on")["coverage"])

    def test_the_layers_on_golden_messages_of_global_are_reproduced(self) -> None:
        from transit.scanners import universal
        env = make_env(self, environ={"RUN_SCA": "true", "RUN_SCANCODE": "true"}, files={"requirements.txt": "x\n"},
                       registry=support.make_registry({"manifest.requirements": pass_scanner}))
        with mock.patch.object(universal, "scan", no_universal):
            run_all(env, scan_of(env))
        want = sorted(golden("layers_on")["file_results"][GLOBAL_FILE]["messages"])
        self.assertEqual(sorted("[%s] %s" % pair for pair in messages(env)), want)

    def test_the_load_errors_are_reported_last_and_after_the_loop_has_set_layer_5(self) -> None:
        from transit.scanners import universal
        env = make_env(self, registry=support.make_registry({}, load_errors=("shell:ImportError",)))
        with mock.patch.object(universal, "scan", no_universal):
            run_all(env, scan_of(env))
        self.assertEqual(coverage(env)["L5_per_language_sast"], "partial:scanner module failed to load")
        self.assertEqual(messages(env)[-1], ("WARN", "engine:scanner_load_error:shell:ImportError"))

    def test_a_system_exit_raised_by_a_layer_is_not_caught_here(self) -> None:
        env = make_env(self)
        with mock.patch.object(layers, "run_layer1", side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                run_all(env, ScanList(entries=(), errors=()))


class ModuleHygieneTests(unittest.TestCase):
    def test_the_summary_is_a_frozen_value(self) -> None:
        summary = FileLayerSummary(1, 2, 3)
        self.assertEqual((summary.scanned, summary.vanished, summary.unreadable), (1, 2, 3))
        with self.assertRaises(Exception):
            summary.scanned = 5  # type: ignore[misc]

    def test_the_run_env_is_a_plain_mutable_record_of_the_eleven_collaborators(self) -> None:
        import dataclasses
        self.assertEqual([f.name for f in dataclasses.fields(RunEnv)],
                         ["cfg", "args", "scan_dir", "console", "verdict", "tools", "wrappers", "registry", "temp", "exclusions", "diff"])

    def test_a_layer_function_returns_nothing(self) -> None:
        env = make_env(self)
        self.assertIsNone(run_layer1(env))
        self.assertIsNone(run_layer2(env))
        self.assertIsNone(run_layer3(env))
        self.assertIsNone(run_layer6(env))
        self.assertIsNone(finalise(env))

    def test_the_module_writes_nothing_below_the_scanned_directory(self) -> None:
        env = make_env(self, files={"a.py": "x", "requirements.txt": "y"}, environ={"RUN_SCA": "true"},
                       registry=support.make_registry({"python": pass_scanner, "manifest.requirements": pass_scanner}))
        before = sorted(str(p.relative_to(env.scan_dir)) for p in Path(env.scan_dir).rglob("*"))
        stamps = {p: p.stat().st_mtime_ns for p in Path(env.scan_dir).rglob("*")}
        run_layer1(env)
        run_layer3(env)
        scan_with(env)
        self.assertEqual(sorted(str(p.relative_to(env.scan_dir)) for p in Path(env.scan_dir).rglob("*")), before)
        self.assertEqual({p: p.stat().st_mtime_ns for p in Path(env.scan_dir).rglob("*")}, stamps)


if __name__ == "__main__":
    unittest.main()
