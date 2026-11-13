"""Tests of transit/config.py (WP-01): contract 2, the environment, parsed once. Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_config.py"

Oracles. The MIN_SEVERITY threshold expression is cut out of ``scan_pipeline.sh`` and run by real bash (so the table of
expected values cannot drift from what the reference engine does), and the ``JAR_*`` knob rule is the ``_knob`` function of
``transit/containers/jar.py``, compiled from its source with ``ast`` (the helper is a program and is never imported).
A token-shaped credential is never written contiguously in this file.
"""
from __future__ import annotations

import ast
import dataclasses
import datetime as dt
import os
import shutil
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from transit import config  # noqa: E402
from transit.config import Config, Limits, Notice, env_number, load_config  # noqa: E402

BASH = shutil.which("bash")
SCRIPT = ROOT / "scan_pipeline.sh"
JAR_HELPER = ROOT / "transit" / "containers" / "jar.py"

NOW = dt.datetime(2026, 11, 13, 9, 5, 7)
OFFLINE_TEXT = "OFFLINE={} ignored: scan_pipeline.sh has no online mode"


def cfg_of(env=None, **kw):
    return load_config(dict(env or {}), now=NOW, **kw)


def texts(cfg):
    return [n.text for n in cfg.notices]


# ── oracles ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def bash_thresholds(values):
    """Run the threshold expression of scan_pipeline.sh (its ``declare -A _SEV_NUM`` and ``SEV_THRESHOLD=`` lines) on each value."""
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    decl = next(x for x in lines if x.startswith("declare -A _SEV_NUM="))
    dflt = next(x for x in lines if x.startswith('MIN_SEVERITY="${MIN_SEVERITY:-high}"'))
    expr = next(x for x in lines if x.startswith("SEV_THRESHOLD="))
    prog = (decl + "\n" + 'while IFS= read -r -d "" MIN_SEVERITY; do ' + dflt.split("#")[0] + "; " + expr
            + '; printf "%s\\n" "$SEV_THRESHOLD"; done\n')
    data = b"".join(os.fsencode(v) + b"\0" for v in values)
    res = subprocess.run([BASH, "-c", prog], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}, check=True)
    return [int(x) for x in res.stdout.decode().split()]


def helper_knob():
    """``_knob`` of transit/containers/jar.py, compiled from the source without importing the program."""
    tree = ast.parse(JAR_HELPER.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_knob")
    ns = {"os": types.SimpleNamespace(environ={})}
    exec(compile(ast.Module([fn], []), str(JAR_HELPER), "exec"), ns)  # noqa: S102  (test oracle, our own file)
    return ns["_knob"], ns["os"].environ


class Defaults(unittest.TestCase):
    def test_every_default_of_contract_2(self):
        c = cfg_of()
        self.assertEqual(c.work_dir, "/opt/ai-transit")
        self.assertEqual(c.verbosity, "normal")
        self.assertEqual(c.min_severity, "high")
        self.assertEqual(c.sev_threshold, 3)
        self.assertEqual(c.since_commit, "")
        self.assertIs(c.run_sca, False)
        self.assertIs(c.run_scancode, False)
        self.assertEqual(c.offline_cache, "/opt/ai-transit/offline-cache")
        self.assertEqual(c.semgrep_rules_dir, "/opt/ai-transit/offline-cache/semgrep-rules")
        self.assertEqual(c.trivy_cache_dir, "/opt/ai-transit/offline-cache/trivy-db")
        self.assertEqual(c.clamav_db_dir, "/opt/ai-transit/offline-cache/clamav")
        self.assertEqual(c.repo_input, "")
        self.assertEqual(c.tmpdir, "/tmp")
        self.assertEqual(c.fixes, frozenset())
        self.assertEqual(c.notices, ())
        self.assertEqual(c.limits, Limits())

    def test_constants_the_other_modules_rely_on(self):
        self.assertEqual(config.DEFAULT_WORK_DIR, "/opt/ai-transit")
        self.assertEqual((config.EXIT_PASS, config.EXIT_FAIL), (0, 1))
        self.assertEqual(config.MIN_PYTHON, (3, 10))
        self.assertEqual(dict(config.SEVERITY_THRESHOLDS), {"low": 1, "medium": 2, "high": 3, "critical": 4})
        self.assertEqual(len(config.DEFAULT_EXCLUDE_DIRS), 14)
        self.assertEqual(len(config.COVERAGE_REQUIRED), 7)
        self.assertEqual(len(config.COVERAGE_OPTIONAL), 2)
        self.assertEqual(config.COVERAGE_LAYERS, tuple(sorted(config.COVERAGE_REQUIRED + config.COVERAGE_OPTIONAL)))
        self.assertEqual(len(config.STANDARDS_HEAD), 3)
        self.assertEqual(len(config.STANDARDS_TAIL), 12)
        self.assertNotIn("D-004", config.KNOWN_FIXES)
        self.assertEqual(config.KNOWN_FIXES, frozenset({"D-003", "D-009", "D-010", "D-011", "D-012", "D-014", "D-029", "D-031"}))

    @unittest.skipUnless(BASH, "bash is the oracle")
    def test_excluded_directories_equal_the_bash_list(self):
        text = SCRIPT.read_text(encoding="utf-8")
        start = text.index("DEFAULT_EXCLUDE_DIRS=(")
        body = text[start + len("DEFAULT_EXCLUDE_DIRS=("):text.index(")", start)]
        self.assertEqual(tuple(body.split()), config.DEFAULT_EXCLUDE_DIRS)


class Overrides(unittest.TestCase):
    def test_every_variable_can_be_set(self):
        c = cfg_of({
            "WORK_DIR": "/w", "VERBOSITY": "quiet", "MIN_SEVERITY": "medium", "SINCE_COMMIT": "abc1234",
            "RUN_SCA": "true", "RUN_SCANCODE": "true", "OFFLINE_CACHE": "/cache", "SEMGREP_RULES_DIR": "/sg",
            "TRIVY_CACHE_DIR": "/tv", "CLAMAV_DB_DIR": "/cl", "REPO_INPUT": "https://example.org/r", "TMPDIR": "/scratch"})
        self.assertEqual((c.work_dir, c.verbosity, c.min_severity, c.sev_threshold), ("/w", "quiet", "medium", 2))
        self.assertEqual(c.since_commit, "abc1234")
        self.assertIs(c.run_sca, True)
        self.assertIs(c.run_scancode, True)
        self.assertEqual((c.offline_cache, c.semgrep_rules_dir, c.trivy_cache_dir, c.clamav_db_dir),
                         ("/cache", "/sg", "/tv", "/cl"))
        self.assertEqual((c.repo_input, c.tmpdir), ("https://example.org/r", "/scratch"))

    def test_staged_data_directories_follow_work_dir_and_offline_cache(self):
        c = cfg_of({"WORK_DIR": "/w"})
        self.assertEqual(c.offline_cache, "/w/offline-cache")
        self.assertEqual(c.semgrep_rules_dir, "/w/offline-cache/semgrep-rules")
        self.assertEqual(c.trivy_cache_dir, "/w/offline-cache/trivy-db")
        self.assertEqual(c.clamav_db_dir, "/w/offline-cache/clamav")
        c = cfg_of({"WORK_DIR": "/w", "OFFLINE_CACHE": "/elsewhere"})
        self.assertEqual(c.offline_cache, "/elsewhere")
        self.assertEqual(c.semgrep_rules_dir, "/elsewhere/semgrep-rules")
        self.assertEqual(c.trivy_cache_dir, "/elsewhere/trivy-db")
        self.assertEqual(c.clamav_db_dir, "/elsewhere/clamav")
        c = cfg_of({"WORK_DIR": "/w", "TRIVY_CACHE_DIR": "/only/trivy"})
        self.assertEqual(c.trivy_cache_dir, "/only/trivy")
        self.assertEqual(c.semgrep_rules_dir, "/w/offline-cache/semgrep-rules")

    def test_paths_are_kept_as_written_like_bash_default_expansion(self):
        c = cfg_of({"WORK_DIR": "rel/dir/"})
        self.assertEqual(c.work_dir, "rel/dir/")
        self.assertEqual(c.offline_cache, "rel/dir//offline-cache")

    def test_an_empty_value_means_unset_for_every_variable(self):
        empty = {k: "" for k in ("WORK_DIR", "VERBOSITY", "MIN_SEVERITY", "SINCE_COMMIT", "RUN_SCA", "RUN_SCANCODE", "OFFLINE",
                                 "OFFLINE_CACHE", "SEMGREP_RULES_DIR", "TRIVY_CACHE_DIR", "CLAMAV_DB_DIR", "REPO_INPUT",
                                 "TMPDIR", "TRANSIT_FIXES")}
        c = cfg_of(empty)
        base = cfg_of()
        for f in dataclasses.fields(Config):
            if f.name == "environ":
                continue
            self.assertEqual(getattr(c, f.name), getattr(base, f.name), f.name)
        self.assertEqual(c.notices, ())

    def test_environ_is_a_snapshot_and_read_only(self):
        src = {"PATH": "/x", "FOO": "1"}
        c = load_config(src, now=NOW)
        self.assertEqual(dict(c.environ), src)
        src["FOO"] = "2"
        src["NEW"] = "3"
        self.assertEqual(c.environ["FOO"], "1")
        self.assertNotIn("NEW", c.environ)
        with self.assertRaises(TypeError):
            c.environ["FOO"] = "9"  # type: ignore[index]

    def test_a_real_os_environ_mapping_is_accepted_and_only_the_given_mapping_is_read(self):
        with mock.patch.dict(os.environ, {"WORK_DIR": "/from-os-environ", "VERBOSITY": "quiet"}):
            c = load_config({}, now=NOW)
            self.assertEqual((c.work_dir, c.verbosity), ("/opt/ai-transit", "normal"))
            c = load_config(os.environ, now=NOW)
            self.assertEqual((c.work_dir, c.verbosity), ("/from-os-environ", "quiet"))

    def test_no_file_system_access(self):
        with mock.patch("builtins.open", side_effect=AssertionError("open")), \
             mock.patch("os.stat", side_effect=AssertionError("stat")), \
             mock.patch("os.mkdir", side_effect=AssertionError("mkdir")), \
             mock.patch("os.makedirs", side_effect=AssertionError("makedirs")):
            load_config({"WORK_DIR": "/does/not/exist", "TMPDIR": "/nor/this"}, now=NOW)

    def test_values_with_undecodable_bytes_pass_through(self):
        odd = os.fsdecode(b"/w/\xff\xfe")
        self.assertEqual(cfg_of({"WORK_DIR": odd}).work_dir, odd)


class MinSeverity(unittest.TestCase):
    # E15 and the design's list: bogus, HIGH, " high", Critical, empty, unset -> 3, 3, 3, 4, 3, 3
    def test_the_e15_table(self):
        got = [cfg_of({"MIN_SEVERITY": v}).sev_threshold for v in ("bogus", "HIGH", " high", "Critical", "")]
        self.assertEqual(got, [3, 3, 3, 4, 3])
        self.assertEqual(cfg_of().sev_threshold, 3)

    def test_each_word_in_any_case(self):
        for word, num in (("low", 1), ("medium", 2), ("high", 3), ("critical", 4)):
            for spelling in (word, word.upper(), word.capitalize(), word.swapcase()):
                self.assertEqual(cfg_of({"MIN_SEVERITY": spelling}).sev_threshold, num, spelling)

    def test_lower_casing_is_what_makes_critical_four(self):
        # mutation guard: without .lower() only the exactly lower-case spelling is found
        self.assertEqual(cfg_of({"MIN_SEVERITY": "CRITICAL"}).sev_threshold, 4)
        self.assertEqual(cfg_of({"MIN_SEVERITY": "LOW"}).sev_threshold, 1)
        self.assertEqual(cfg_of({"MIN_SEVERITY": "Medium"}).sev_threshold, 2)

    def test_the_text_is_kept_as_given_for_the_low_sev_message(self):
        self.assertEqual(cfg_of({"MIN_SEVERITY": "Critical"}).min_severity, "Critical")
        self.assertEqual(cfg_of({"MIN_SEVERITY": " high"}).min_severity, " high")
        self.assertEqual(cfg_of({"MIN_SEVERITY": ""}).min_severity, "high")
        self.assertEqual(cfg_of().min_severity, "high")

    def test_thresholds_are_the_published_mapping(self):
        for word, num in config.SEVERITY_THRESHOLDS.items():
            self.assertEqual(cfg_of({"MIN_SEVERITY": word}).sev_threshold, num)

    def test_a_rejected_non_empty_value_gets_a_notice_naming_it(self):
        for bad in ("bogus", " high", "high ", "hi", "4", "Höch"):
            c = cfg_of({"MIN_SEVERITY": bad})
            self.assertEqual(len(c.notices), 1, bad)
            self.assertEqual(c.notices[0].level, "warn")
            self.assertIn(bad, c.notices[0].text)
            self.assertIn("MIN_SEVERITY", c.notices[0].text)
            self.assertEqual(c.sev_threshold, 3)

    def test_an_accepted_or_empty_value_gets_no_notice(self):
        for ok in ("", "high", "HIGH", "Critical", "low", "MEDIUM"):
            self.assertEqual(cfg_of({"MIN_SEVERITY": ok}).notices, (), ok)
        self.assertEqual(cfg_of().notices, ())

    @unittest.skipUnless(BASH, "bash is the oracle")
    def test_against_the_expression_of_scan_pipeline_sh(self):
        values = ["low", "medium", "high", "critical", "LOW", "Medium", "HIGH", "CrItIcAl", "bogus", " high", "high ", "", "hi",
                  "HİGH", "ＨＩＧＨ", "critıcal", "Kow", "low\n", "4", "highest", "medïum"]
        want = bash_thresholds(values)
        got = [cfg_of({"MIN_SEVERITY": v}).sev_threshold for v in values]
        self.assertEqual(got, want, list(zip(values, got, want)))


class Verbosity(unittest.TestCase):
    def test_only_quiet_has_an_effect(self):
        self.assertEqual(cfg_of({"VERBOSITY": "quiet"}).verbosity, "quiet")
        for v in ("normal", "verbose", "", "bogus", "QUIET", "Quiet", " quiet"):
            self.assertEqual(cfg_of({"VERBOSITY": v}).verbosity, "normal", v)
        self.assertEqual(cfg_of().verbosity, "normal")

    def test_notices_for_values_outside_the_three_words(self):
        for ok in ("quiet", "normal", "verbose", ""):
            self.assertEqual(cfg_of({"VERBOSITY": ok}).notices, (), ok)
        for bad in ("bogus", "QUIET", " quiet", "loud"):
            c = cfg_of({"VERBOSITY": bad})
            self.assertEqual(len(c.notices), 1, bad)
            self.assertEqual(c.notices[0].level, "warn")
            self.assertIn(bad, c.notices[0].text)
            self.assertIn("VERBOSITY", c.notices[0].text)

    def test_verbose_is_a_synonym_of_normal_and_silent(self):
        a, b = cfg_of({"VERBOSITY": "verbose"}), cfg_of({"VERBOSITY": "normal"})
        self.assertEqual(dataclasses.replace(a, environ=b.environ), b)


class Offline(unittest.TestCase):
    def test_a_value_other_than_true_is_ignored_with_the_golden_text(self):
        for v in ("false", "0", "no", "TRUE", "True", " true", "true ", "1"):
            c = cfg_of({"OFFLINE": v})
            self.assertEqual(texts(c), [OFFLINE_TEXT.format(v)], v)
            self.assertEqual(c.notices[0].level, "warn")

    def test_true_unset_and_empty_are_silent(self):
        for env in ({}, {"OFFLINE": "true"}, {"OFFLINE": ""}):
            self.assertEqual(cfg_of(env).notices, (), env)

    def test_offline_is_not_a_switch(self):
        base = cfg_of()
        c = cfg_of({"OFFLINE": "false"})
        for f in dataclasses.fields(Config):
            if f.name in ("environ", "notices"):
                continue
            self.assertEqual(getattr(c, f.name), getattr(base, f.name), f.name)
        self.assertFalse(hasattr(c, "offline"))

    def test_notice_text_matches_the_bash_warning(self):
        # the string of scan_pipeline.sh: warn "OFFLINE=${OFFLINE} ignored: scan_pipeline.sh has no online mode"
        src = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('warn "OFFLINE=${OFFLINE} ignored: scan_pipeline.sh has no online mode"', src)

    def test_notices_come_in_a_fixed_order(self):
        c = cfg_of({"OFFLINE": "false", "VERBOSITY": "loud", "MIN_SEVERITY": "bogus"})
        self.assertEqual(len(c.notices), 3)
        self.assertEqual(c.notices, cfg_of({"OFFLINE": "false", "VERBOSITY": "loud", "MIN_SEVERITY": "bogus"}).notices)
        self.assertTrue(all(isinstance(n, Notice) for n in c.notices))


class RunLayers(unittest.TestCase):
    def test_true_only_for_exactly_true(self):
        for name, attr in (("RUN_SCA", "run_sca"), ("RUN_SCANCODE", "run_scancode")):
            self.assertIs(getattr(cfg_of({name: "true"}), attr), True)
            for v in ("TRUE", "True", "1", "yes", "on", " true", "true ", "false", "", "tru"):
                self.assertIs(getattr(cfg_of({name: v}), attr), False, (name, v))
            self.assertIs(getattr(cfg_of(), attr), False)

    def test_the_two_are_independent(self):
        c = cfg_of({"RUN_SCA": "true"})
        self.assertEqual((c.run_sca, c.run_scancode), (True, False))
        c = cfg_of({"RUN_SCANCODE": "true"})
        self.assertEqual((c.run_sca, c.run_scancode), (False, True))


class Fixes(unittest.TestCase):
    def test_default_is_all_off(self):
        c = cfg_of()
        for fid in config.KNOWN_FIXES:
            self.assertIs(c.fix(fid), False, fid)

    def test_a_listed_fix_is_on_and_the_others_stay_off(self):
        c = cfg_of({"TRANSIT_FIXES": "D-003,D-012"})
        self.assertEqual(c.fixes, frozenset({"D-003", "D-012"}))
        self.assertIs(c.fix("D-003"), True)
        self.assertIs(c.fix("D-012"), True)
        self.assertIs(c.fix("D-031"), False)

    def test_every_known_id_can_be_enabled(self):
        c = cfg_of({"TRANSIT_FIXES": ",".join(sorted(config.KNOWN_FIXES))})
        self.assertEqual(c.fixes, config.KNOWN_FIXES)
        self.assertTrue(all(c.fix(f) for f in config.KNOWN_FIXES))

    def test_spaces_around_ids_and_empty_items_are_tolerated(self):
        c = cfg_of({"TRANSIT_FIXES": " D-003 , D-012,, ,D-003,"})
        self.assertEqual(c.fixes, frozenset({"D-003", "D-012"}))

    def test_an_unknown_id_raises_value_error(self):
        for bad in ("D-999", "d-003", "D-004", "D-0030", "bogus", "D-003,D-998", "D-003;D-012", "D-003 D-012"):
            with self.assertRaises(ValueError, msg=bad):
                cfg_of({"TRANSIT_FIXES": bad})

    def test_d_004_is_no_longer_a_switch(self):
        with self.assertRaises(ValueError):
            cfg_of({"TRANSIT_FIXES": "D-004"})

    def test_the_error_names_the_id(self):
        with self.assertRaises(ValueError) as cm:
            cfg_of({"TRANSIT_FIXES": "D-003,D-998"})
        self.assertIn("D-998", str(cm.exception))

    def test_asking_for_an_unknown_switch_in_code_is_an_error_not_a_silent_false(self):
        with self.assertRaises(ValueError):
            cfg_of().fix("D-0012")
        with self.assertRaises(ValueError):
            cfg_of().fix("D-004")


class LimitsFromEnvironment(unittest.TestCase):
    FLOATS = (("TRANSIT_RULE_BUDGET_S", "rule_budget_s", 0.25), ("TRANSIT_FILE_BUDGET_S", "file_budget_s", 120.0),
              ("TRANSIT_FILE_BUDGET_S_PER_MB", "file_budget_s_per_mb", 10.0),
              ("TRANSIT_TOOL_TIMEOUT_S", "tool_timeout_s", 1800.0), ("TRANSIT_HELPER_TIMEOUT_S", "helper_timeout_s", 300.0))

    def test_defaults_are_the_documented_values(self):
        lim = cfg_of().limits
        self.assertEqual((lim.rule_budget_s, lim.file_budget_s, lim.file_budget_s_per_mb), (0.25, 120.0, 10.0))
        self.assertEqual((lim.long_line_bytes, lim.max_file_bytes), (8192, 512 * 1024 * 1024))
        self.assertEqual((lim.tool_timeout_s, lim.helper_timeout_s), (1800.0, 300.0))

    def test_each_float_limit_can_be_overridden(self):
        for name, attr, default in self.FLOATS:
            lim = cfg_of({name: "7.5"}).limits
            self.assertEqual(getattr(lim, attr), 7.5, name)
            self.assertIsInstance(getattr(lim, attr), float)
            for other, oattr, odefault in self.FLOATS:
                if other != name:
                    self.assertEqual(getattr(lim, oattr), odefault)

    def test_long_line_bytes_and_max_file_mb(self):
        lim = cfg_of({"TRANSIT_LONG_LINE_BYTES": "4096", "TRANSIT_MAX_FILE_MB": "64"}).limits
        self.assertEqual(lim.long_line_bytes, 4096)
        self.assertEqual(lim.max_file_bytes, 64 * 1024 * 1024)
        self.assertIsInstance(lim.long_line_bytes, int)
        self.assertIsInstance(lim.max_file_bytes, int)
        lim = cfg_of({"TRANSIT_MAX_FILE_MB": "0.5"}).limits
        self.assertEqual(lim.max_file_bytes, 512 * 1024)

    def test_zero_and_garbage_are_ignored_for_every_limit_including_the_per_mb_one(self):
        names = [n for n, _, _ in self.FLOATS] + ["TRANSIT_LONG_LINE_BYTES", "TRANSIT_MAX_FILE_MB"]
        default = cfg_of().limits
        for name in names:
            for bad in ("0", "abc", "", "-1", "-0.5", "nan", "inf", "-inf", "1e999", "0.0", " ", "1,5", "0x10", "None"):
                self.assertEqual(cfg_of({name: bad}).limits, default, (name, bad))

    def test_a_tiny_positive_value_never_becomes_zero(self):
        lim = cfg_of({"TRANSIT_LONG_LINE_BYTES": "0.4", "TRANSIT_MAX_FILE_MB": "0.0000001"}).limits
        self.assertGreaterEqual(lim.long_line_bytes, 1)
        self.assertGreaterEqual(lim.max_file_bytes, 1)

    def test_a_huge_value_does_not_raise(self):
        lim = cfg_of({"TRANSIT_MAX_FILE_MB": "1e308", "TRANSIT_LONG_LINE_BYTES": "1e308"}).limits
        self.assertGreaterEqual(lim.max_file_bytes, 1)
        self.assertGreaterEqual(lim.long_line_bytes, 1)

    def test_limits_do_not_leak_into_other_fields(self):
        base = cfg_of()
        c = cfg_of({"TRANSIT_FILE_BUDGET_S": "5"})
        self.assertEqual(dataclasses.replace(c, limits=base.limits), base)


class EnvNumber(unittest.TestCase):
    def test_the_rule(self):
        e = {"A": "5", "B": "0.5", "C": " 7 ", "D": "1e2", "Z": "0", "N": "-3", "T": "abc", "E": ""}
        self.assertEqual(env_number(e, "A", 9.0), 5.0)
        self.assertEqual(env_number(e, "B", 9.0), 0.5)
        self.assertEqual(env_number(e, "C", 9.0), 7.0)
        self.assertEqual(env_number(e, "D", 9.0), 100.0)
        for name in ("Z", "N", "T", "E", "MISSING"):
            self.assertEqual(env_number(e, name, 9.0), 9.0, name)
        self.assertIsInstance(env_number(e, "A", 9), float)

    def test_nan_and_infinity_are_not_usable_numbers(self):
        for v in ("nan", "NaN", "inf", "Infinity", "-inf", "1e999"):
            self.assertEqual(env_number({"A": v}, "A", 9.0), 9.0, v)

    def test_default_is_returned_as_is(self):
        self.assertEqual(env_number({}, "A", 90), 90)
        self.assertEqual(env_number({}, "A", 0.25), 0.25)

    def test_equals_the_helper_programs_knob_on_every_finite_value(self):
        knob, helper_env = helper_knob()
        values = ["5", "0.5", " 7 ", "1e2", "0", "-3", "abc", "", "1_0", "+4", "007", ".5", "5.", "0.0", "-0", "1e-9", "٣", "5\n",
                  "0x10", "1,5", "True", "None", "1e308"]
        for v in values:
            helper_env.clear()
            helper_env["JAR_X"] = v
            self.assertEqual(env_number({"JAR_X": v}, "JAR_X", 90.0), knob("JAR_X", 90.0), repr(v))
        helper_env.clear()
        self.assertEqual(env_number({}, "JAR_X", 90.0), knob("JAR_X", 90.0))

    def test_reads_only_the_mapping(self):
        with mock.patch.dict(os.environ, {"TRANSIT_X": "5"}):
            self.assertEqual(env_number({}, "TRANSIT_X", 2.0), 2.0)


class Timestamp(unittest.TestCase):
    def test_format_of_a_given_time(self):
        self.assertEqual(load_config({}, now=dt.datetime(2026, 11, 13, 9, 5, 7)).timestamp, "20261113_090507")
        self.assertEqual(load_config({}, now=dt.datetime(2027, 1, 2, 23, 59, 59, 999999)).timestamp, "20270102_235959")
        self.assertEqual(load_config({}, now=dt.datetime(2030, 12, 31, 0, 0, 0)).timestamp, "20301231_000000")

    def test_default_is_the_local_time_now(self):
        before = dt.datetime.now().replace(microsecond=0)
        stamp = load_config({}).timestamp
        after = dt.datetime.now()
        self.assertEqual(len(stamp), 15)
        self.assertEqual(stamp[8], "_")
        self.assertTrue(stamp[:8].isdigit() and stamp[9:].isdigit())
        parsed = dt.datetime.strptime(stamp, "%Y%m%d_%H%M%S")
        self.assertTrue(before <= parsed <= after, (before, parsed, after))


class Frozen(unittest.TestCase):
    def test_config_limits_and_notice_are_frozen(self):
        c = cfg_of()
        for obj, field in ((c, "work_dir"), (c, "limits"), (c.limits, "rule_budget_s"), (Notice("warn", "x"), "text")):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(obj, field, "changed")

    def test_fixes_and_notices_are_immutable_containers(self):
        c = cfg_of({"TRANSIT_FIXES": "D-003"})
        self.assertIsInstance(c.fixes, frozenset)
        self.assertIsInstance(c.notices, tuple)

    def test_two_loads_of_the_same_input_are_equal(self):
        env = {"WORK_DIR": "/w", "MIN_SEVERITY": "low", "TRANSIT_FIXES": "D-009", "OFFLINE": "false"}
        self.assertEqual(cfg_of(env), cfg_of(env))


class Layering(unittest.TestCase):
    def test_a_leaf_with_no_import_time_side_effect(self):
        tree = ast.parse((ROOT / "transit" / "config.py").read_text(encoding="utf-8"), feature_version=(3, 10))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module or "")
        self.assertFalse([n for n in names if n == "transit" or n.startswith("transit.")], names)
        self.assertNotIn("re", names)
        self.assertNotIn("subprocess", names)

    def test_no_forbidden_construct(self):
        tree = ast.parse((ROOT / "transit" / "config.py").read_text(encoding="utf-8"))
        banned_calls = {"print", "eval", "exec", "open", "compile", "__import__", "input"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name):
                    self.assertNotIn(fn.id, banned_calls, fn.id)
                if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                    self.assertNotIn((fn.value.id, fn.attr), {("os", "system"), ("os", "popen"), ("os", "getenv"),
                                                              ("os", "mkdir"), ("os", "makedirs"), ("os", "stat")})
            # load_config reads the mapping it is given, never the process environment
            if isinstance(node, ast.Attribute) and node.attr == "environ" and isinstance(node.value, ast.Name):
                self.assertNotEqual(node.value.id, "os")
            self.assertFalse(isinstance(node, ast.keyword) and node.arg == "shell")

    def test_compiles_with_warnings_as_errors(self):
        import warnings
        src = (ROOT / "transit" / "config.py").read_text(encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(src, "config.py", "exec")


if __name__ == "__main__":
    unittest.main()
