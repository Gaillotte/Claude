"""Tests of transit/cli.py (WP-01): contract 1, the command line. Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_cli.py"

Oracle. The argument section of ``scan_pipeline.sh`` (from ``_POS=()`` to the line that defaults ``SCANNING_NAME``) is cut
out of the script and run by real bash in the C locale, with ``fail`` replaced by a function that prints ``REFUSED``; every
ASCII command line below is run through both engines and the answers must agree. Names with non-ASCII characters are not
compared with bash: the hardened bash counts BYTES under ``LC_ALL=C`` and does not know the C1 controls, while the frozen
docstring of ``scanning_name_error`` counts characters and refuses the C1 controls (reported as an amendment).
"""
from __future__ import annotations

import ast
import dataclasses
import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from transit import cli  # noqa: E402
from transit.cli import Args, UsageError, parse_args, positional_words, scanning_name_error  # noqa: E402

BASH = shutil.which("bash")
SCRIPT = ROOT / "scan_pipeline.sh"

USAGE_WORD = "Usage"
NOT_FOUND = "Directory not found: "
NAME_REFUSED = "scanning_name must not contain"


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def tree(root):
    """Every entry below ``root`` (and ``root`` itself), so that a run that created or removed anything shows."""
    seen = []
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            seen.append(os.path.relpath(os.path.join(dirpath, n), root))
    return sorted(seen)


class Scratch(unittest.TestCase):
    """A private temporary directory that is also the working directory, so that relative arguments mean the same in the
    process and in the bash oracle."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory(prefix="cli_test_")
        self.tmp = os.path.realpath(self._tmp.name)
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def mkdir(self, *parts):
        p = os.path.join(self.tmp, *parts)
        os.makedirs(p, exist_ok=True)
        return p

    def touch(self, *parts):
        p = os.path.join(self.tmp, *parts)
        with open(p, "w"):
            pass
        return p


def bash_arguments_section():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    start = next(i for i, x in enumerate(lines) if x.startswith("_POS=()"))
    end = next(i for i, x in enumerate(lines) if x.startswith('SCANNING_NAME="${SCANNING_NAME:-$TIMESTAMP}"'))
    return "\n".join(lines[start:end + 1])


def bash_parse(argv, cwd):
    """('REFUSED',) or ('OK', scan_dir, report_dir, scanning_name) as the argument section of scan_pipeline.sh computes them."""
    prog = ("set -euo pipefail\nexport LC_ALL=C\nfail() { printf 'REFUSED\\n'; exit 1; }\nTIMESTAMP=TS_DEFAULT\n"
            + bash_arguments_section()
            + "\nprintf 'OK\\0%s\\0%s\\0%s\\0' \"$SCAN_DIR\" \"$REPORT_DIR\" \"$SCANNING_NAME\"\n")
    res = subprocess.run([BASH, "-c", prog, "scan_pipeline.sh"] + [os.fsdecode(a) for a in argv], cwd=cwd,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    if res.stdout.startswith(b"REFUSED"):
        return ("REFUSED",)
    parts = res.stdout.split(b"\0")
    assert parts[0] == b"OK", (res.stdout, res.stderr)
    return ("OK", os.fsdecode(parts[1]), os.fsdecode(parts[2]) or None, os.fsdecode(parts[3]))


def python_parse(argv):
    try:
        a = parse_args(argv)
    except UsageError:
        return ("REFUSED",)
    return ("OK", a.scan_dir, a.report_dir, a.scanning_name if a.scanning_name is not None else "TS_DEFAULT")


def refusal(testcase, argv):
    with testcase.assertRaises(UsageError) as cm:
        parse_args(argv)
    return cm.exception


# ── positional_words (contract 1.1) ──────────────────────────────────────────────────────────────────────────────────
class PositionalWords(unittest.TestCase):
    def test_every_word_beginning_with_two_dashes_is_dropped_wherever_it_is(self):
        self.assertEqual(positional_words(["--quiet", "a", "--x", "b", "--", "c", "--y=1"]), ["a", "b", "c"])
        self.assertEqual(positional_words(["a", "b", "c", "--quiet"]), ["a", "b", "c"])
        self.assertEqual(positional_words(["--quiet", "--verbose", "--min-severity", "a"]), ["a"])

    def test_the_word_after_an_option_is_a_positional_options_take_no_value(self):
        # E18: ``--min-severity medium dir`` makes ``medium`` the first positional.
        self.assertEqual(positional_words(["--min-severity", "medium", "dir"]), ["medium", "dir"])

    def test_all_of_them_dropped_not_only_the_first(self):
        # mutation guard: strip only the first ``--`` word
        self.assertEqual(positional_words(["--a", "--b", "--c", "x"]), ["x"])
        self.assertEqual(positional_words(["--a", "x", "--b", "y", "--c"]), ["x", "y"])
        self.assertEqual(positional_words(["--", "--"]), [])

    def test_a_lone_double_dash_and_longer_runs_of_dashes_are_dropped(self):
        self.assertEqual(positional_words(["--", "a"]), ["a"])
        self.assertEqual(positional_words(["---", "----x", "a"]), ["a"])

    def test_a_single_leading_dash_is_a_positional(self):
        self.assertEqual(positional_words(["-q", "-", "-x", "a"]), ["-q", "-", "-x", "a"])

    def test_a_dash_that_is_not_leading_does_not_count(self):
        self.assertEqual(positional_words(["a--b", "./--odd", "x/--y", " --z"]), ["a--b", "./--odd", "x/--y", " --z"])

    def test_the_order_is_kept_and_positionals_beyond_the_third_are_kept(self):
        self.assertEqual(positional_words(["a", "b", "c", "d", "--e", "f"]), ["a", "b", "c", "d", "f"])

    def test_an_empty_string_is_a_positional(self):
        self.assertEqual(positional_words(["", "a", "", "--q", ""]), ["", "a", "", ""])

    def test_empty_input(self):
        self.assertEqual(positional_words([]), [])
        self.assertEqual(positional_words(["--only"]), [])

    def test_the_result_is_a_new_list_and_the_input_is_not_changed(self):
        src = ["--a", "b"]
        out = positional_words(src)
        self.assertIsInstance(out, list)
        self.assertEqual(src, ["--a", "b"])
        out.append("z")
        self.assertEqual(src, ["--a", "b"])

    def test_any_sequence_is_accepted(self):
        self.assertEqual(positional_words(("--a", "b")), ["b"])

    def test_words_are_not_altered(self):
        odd = ["a\tb", "\x1b]0;x\x07", os.fsdecode(b"\xff\xfe"), "\u00e9", " "]
        self.assertEqual(positional_words(odd), odd)

    @unittest.skipUnless(BASH, "bash is the oracle")
    def test_against_the_loop_of_scan_pipeline_sh(self):
        lines = SCRIPT.read_text(encoding="utf-8").splitlines()
        i = next(k for k, x in enumerate(lines) if x.startswith("_POS=()"))
        loop = "\n".join(lines[i:i + 4])
        self.assertIn("--*", loop)
        prog = "set -euo pipefail\n" + loop + '\nfor w in ${_POS[@]+"${_POS[@]}"}; do printf "%s\\0" "$w"; done\n'
        cases = [[], ["--quiet"], ["a"], ["--q", "a", "--r", "b", "c", "d"], ["-q", "--", "-", "x y", ""], ["---", "a--b", "./--odd"],
                 ["a", "b", "c", "d", "e"], ["", "", ""]]
        for argv in cases:
            res = subprocess.run([BASH, "-c", prog, "x"] + argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, check=True)
            want = [os.fsdecode(x) for x in res.stdout.split(b"\0")[:-1]]
            self.assertEqual(positional_words(argv), want, argv)


# ── scanning_name_error (contract 1.4) ───────────────────────────────────────────────────────────────────────────────
class ScanningName(unittest.TestCase):
    def test_accepted_names(self):
        for name in ("", "report", "a b", "a.b", "a..b", "x.", "-x", "_x", "name with  two  spaces", "a" * 150, "UPPER", "20261113_090507",
                     " ", "  lead", "end ", "\u00e9", "\u65e5\u672c\u8a9e", "a\u00a0b", "\u00a1", "emoji \U0001f600", "back\\slash", "\\033[31m",
                     "a:b", "a*b", "a?b", "~x", "x~", "-", "--", "a" * 149):
            self.assertIsNone(scanning_name_error(name), repr(name))

    def test_slash_is_refused_anywhere(self):
        for name in ("a/b", "/", "/x", "x/", "../x", "a/../b", "x\\/y"):
            self.assertIsNotNone(scanning_name_error(name), repr(name))

    def test_a_leading_dot_is_refused_but_a_later_dot_is_not(self):
        for name in (".", "..", ".hid", "..x", "...", ".x.y"):
            self.assertIsNotNone(scanning_name_error(name), repr(name))
        for name in ("x.", "a.b", "a..b", " .x", "-.x"):
            self.assertIsNone(scanning_name_error(name), repr(name))

    def test_every_control_character_is_refused_and_nothing_else(self):
        # oracle: Unicode category Cc is exactly C0, DEL and C1
        for cp in range(0, 0x400):
            ch = chr(cp)
            if cp == 0x2F:  # "/"
                continue
            want_refused = unicodedata.category(ch) == "Cc"
            for name in ("a" + ch + "b", ch):
                if cp == 0x2E and name == ch:
                    continue  # a lone "." is the leading-dot rule
                self.assertEqual(scanning_name_error(name) is not None, want_refused, (hex(cp), name))

    def test_the_named_control_characters(self):
        for name in ("a\tb", "a\nb", "a\rb", "a\x1bb", "a\x7fb", "a\x1fb", "a\x80b", "a\x85b", "a\x9bb", "a\x9fb", "\x01", "ab\n"):
            self.assertIn(NAME_REFUSED, scanning_name_error(name) or "", repr(name))
        for name in ("a\x20b", "a\xa0b", "a\xa1b"):
            self.assertIsNone(scanning_name_error(name), repr(name))

    def test_150_characters_are_accepted_and_151_are_refused(self):
        # mutation guard: accept 151 characters
        self.assertIsNone(scanning_name_error("a" * 150))
        self.assertIsNotNone(scanning_name_error("a" * 151))
        self.assertIsNotNone(scanning_name_error("a" * 1000))
        self.assertEqual(cli.SCANNING_NAME_MAX_CHARS, 150)

    def test_the_limit_counts_characters_not_bytes(self):
        self.assertIsNone(scanning_name_error("\u00e9" * 150))  # 300 bytes
        self.assertIsNone(scanning_name_error("\u65e5" * 150))  # 450 bytes
        self.assertIsNotNone(scanning_name_error("\u00e9" * 151))
        self.assertIsNotNone(scanning_name_error("\u65e5" * 151))
        # an undecodable byte is one character (surrogate escape)
        self.assertIsNone(scanning_name_error(os.fsdecode(b"\xff" * 150)))
        self.assertIsNotNone(scanning_name_error(os.fsdecode(b"\xff" * 151)))

    def test_the_text_names_the_rule_and_carries_the_value(self):
        for name in ("a/b", ".hid", "a\tb", "x" * 151):
            msg = scanning_name_error(name)
            self.assertIsInstance(msg, str)
            self.assertIn(NAME_REFUSED, msg)
            self.assertIn("150", msg)
            self.assertIn(name, msg)

    def test_return_type_is_none_or_str(self):
        self.assertIsNone(scanning_name_error(""))
        self.assertIsInstance(scanning_name_error("/"), str)

    @unittest.skipUnless(BASH, "bash is the oracle")
    def test_ascii_names_against_the_condition_of_scan_pipeline_sh(self):
        lines = SCRIPT.read_text(encoding="utf-8").splitlines()
        i = next(k for k, x in enumerate(lines) if x.startswith('SCANNING_NAME="${_POS[2]:-}"'))
        j = next(k for k in range(i, len(lines)) if lines[k].strip() == "fi")
        cond = "\n".join(lines[i + 1:j + 1])
        self.assertIn("[[:cntrl:]]", cond)
        names = ["", "a", "a b", "a.b", "a..b", ".hid", "..x", "a/b", "/", "x.", "a" * 150, "a" * 151, "a\tb", "a\x7fb", "a\x1bb", "-x", "\x01",
                 "20261113_090507", " ", "x\ny"]
        prog = "export LC_ALL=C\nfail() { printf 'REFUSED'; }\nSCANNING_NAME=$1\n" + cond + "\n"
        for name in names:
            res = subprocess.run([BASH, "-c", prog, "x", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, check=True)
            self.assertEqual(scanning_name_error(name) is not None, res.stdout == b"REFUSED", repr(name))


# ── parse_args: the checks, in order (contract 1.2) ──────────────────────────────────────────────────────────────────
class Checks(Scratch):
    def test_no_positional_is_a_usage_error(self):
        for argv in ([], ["--quiet"], ["--", "--x", "--y"]):
            exc = refusal(self, argv)
            self.assertIn(USAGE_WORD, exc.message, argv)
            self.assertIn("<directory_to_scan>", exc.message)
            self.assertIn("scan_pipeline.py", exc.message)

    def test_the_program_name_goes_into_the_usage_text(self):
        with self.assertRaises(UsageError) as cm:
            parse_args([], prog="my/prog.py")
        self.assertIn("my/prog.py", cm.exception.message)

    def test_a_missing_directory(self):
        exc = refusal(self, ["no/such/dir"])
        self.assertEqual(exc.message, NOT_FOUND + "no/such/dir")

    def test_the_message_shows_the_value_as_it_was_given_not_with_its_slashes_removed(self):
        self.touch("file.txt")
        self.assertEqual(refusal(self, ["nope/"]).message, NOT_FOUND + "nope/")
        self.assertEqual(refusal(self, ["file.txt//"]).message, NOT_FOUND + "file.txt//")

    def test_the_empty_string_is_not_a_directory(self):
        exc = refusal(self, [""])
        self.assertEqual(exc.message, NOT_FOUND)

    def test_a_regular_file_is_not_a_directory(self):
        f = self.touch("file.txt")
        for value in (f, "file.txt"):
            exc = refusal(self, [value])
            self.assertEqual(exc.message, NOT_FOUND + value)

    def test_a_missing_report_directory(self):
        d = self.mkdir("scan")
        exc = refusal(self, [d, "no/such/reports"])
        self.assertEqual(exc.message, NOT_FOUND + "no/such/reports")

    def test_a_regular_file_as_report_directory(self):
        d = self.mkdir("scan")
        f = self.touch("reports.txt")
        exc = refusal(self, [d, f])
        self.assertEqual(exc.message, NOT_FOUND + f)

    def test_an_empty_report_directory_is_treated_as_absent(self):
        d = self.mkdir("scan")
        a = parse_args([d, ""])
        self.assertEqual(a, Args(d, None, None))

    def test_a_bad_scanning_name_each_way(self):
        d = self.mkdir("scan")
        r = self.mkdir("reports")
        for name in ("a/b", ".hid", "..x", "a\tb", "x" * 151):
            exc = refusal(self, [d, r, name])
            self.assertIn(NAME_REFUSED, exc.message, name)
            self.assertIn(name, exc.message)

    def test_the_checks_run_in_order(self):
        d = self.mkdir("scan")
        r = self.mkdir("reports")
        bad_name = "a/b"
        # (1) usage before anything
        self.assertIn(USAGE_WORD, refusal(self, []).message)
        # (2) the directory before the report directory and the name
        self.assertEqual(refusal(self, ["missing", "also-missing", bad_name]).message, NOT_FOUND + "missing")
        self.assertEqual(refusal(self, ["missing", r, bad_name]).message, NOT_FOUND + "missing")
        # (3) the report directory before the name
        self.assertEqual(refusal(self, [d, "also-missing", bad_name]).message, NOT_FOUND + "also-missing")
        # (4) the name last
        self.assertIn(NAME_REFUSED, refusal(self, [d, r, bad_name]).message)

    def test_the_first_failing_check_wins_even_with_options_in_between(self):
        d = self.mkdir("scan")
        self.assertEqual(refusal(self, ["--quiet", "missing", "--x", d]).message, NOT_FOUND + "missing")
        self.assertEqual(refusal(self, ["--quiet", d, "--x", "missing2", "--y", "a/b"]).message, NOT_FOUND + "missing2")

    def test_usage_error_is_an_exception_with_a_message(self):
        e = UsageError("boom")
        self.assertIsInstance(e, Exception)
        self.assertEqual(e.message, "boom")
        self.assertEqual(str(e), "boom")
        self.assertTrue(issubclass(UsageError, Exception))


# ── parse_args: what is returned ─────────────────────────────────────────────────────────────────────────────────────
class Returned(Scratch):
    def test_one_directory(self):
        d = self.mkdir("scan")
        self.assertEqual(parse_args([d]), Args(d, None, None))

    def test_three_arguments(self):
        d, r = self.mkdir("scan"), self.mkdir("reports")
        self.assertEqual(parse_args([d, r, "nightly"]), Args(d, r, "nightly"))

    def test_an_empty_report_directory_still_honours_the_scanning_name(self):
        d = self.mkdir("scan")
        self.assertEqual(parse_args([d, "", "nightly"]), Args(d, None, "nightly"))

    def test_an_empty_scanning_name_means_none(self):
        d, r = self.mkdir("scan"), self.mkdir("reports")
        self.assertEqual(parse_args([d, r, ""]), Args(d, r, None))
        self.assertEqual(parse_args([d, "", ""]), Args(d, None, None))

    def test_a_fourth_positional_is_ignored_and_not_even_checked(self):
        d, r = self.mkdir("scan"), self.mkdir("reports")
        self.assertEqual(parse_args([d, r, "name", "extra", "more/../.."]), Args(d, r, "name"))
        self.assertEqual(parse_args([d, r, "name", "\tdoes-not-exist"]), Args(d, r, "name"))

    def test_options_anywhere_are_dropped(self):
        d, r = self.mkdir("scan"), self.mkdir("reports")
        self.assertEqual(parse_args(["--quiet", d, "--verbose", r, "--", "nm", "--min-severity"]), Args(d, r, "nm"))
        self.assertEqual(parse_args(["--a", "--b", d, "--c", "--d"]), Args(d, None, None))

    def test_a_directory_whose_name_starts_with_two_dashes_needs_a_prefix(self):
        self.mkdir("--odd")
        self.assertEqual(parse_args(["./--odd"]), Args("./--odd", None, None))
        with self.assertRaises(UsageError) as cm:
            parse_args(["--odd"])
        self.assertIn(USAGE_WORD, cm.exception.message)  # the word was dropped: no positional is left

    def test_a_name_with_a_single_dash_is_a_directory_argument(self):
        self.mkdir("-dash")
        self.assertEqual(parse_args(["-dash"]), Args("-dash", None, None))

    def test_trailing_slashes_are_removed(self):
        d = self.mkdir("scan")
        for suffix in ("/", "//", "///", "////"):
            self.assertEqual(parse_args([d + suffix]).scan_dir, d, suffix)
        self.assertEqual(parse_args(["scan/"]).scan_dir, "scan")
        self.assertEqual(parse_args(["scan//"]).scan_dir, "scan")

    def test_a_lone_root_is_kept(self):
        for value in ("/", "//", "///"):
            self.assertEqual(parse_args([value]).scan_dir, "/", value)

    def test_nothing_else_is_done_to_the_directory(self):
        self.mkdir("a", "b")
        self.assertEqual(parse_args(["a/b"]).scan_dir, "a/b")                # relative stays relative
        self.assertEqual(parse_args(["./a/b"]).scan_dir, "./a/b")            # no normalisation
        self.assertEqual(parse_args(["a/../a/b"]).scan_dir, "a/../a/b")      # ``..`` is not collapsed
        self.assertEqual(parse_args(["a//b"]).scan_dir, "a//b")              # inner doubled slash kept
        self.assertEqual(parse_args([self.tmp + "/a/./b/"]).scan_dir, self.tmp + "/a/./b")
        self.assertEqual(parse_args(["."]).scan_dir, ".")
        self.assertEqual(parse_args(["./"]).scan_dir, ".")
        self.assertEqual(parse_args([".."]).scan_dir, "..")

    def test_the_report_directory_and_the_name_are_kept_as_given(self):
        d, r = self.mkdir("scan"), self.mkdir("reports")
        self.assertEqual(parse_args([d, r + "/", "nm"]).report_dir, r + "/")
        self.assertEqual(parse_args([d, "reports", "a  b"]).scanning_name, "a  b")
        self.assertEqual(parse_args([d, "reports", " lead "]).scanning_name, " lead ")

    def test_a_symlink_to_a_directory_counts_for_both_directories(self):
        real = self.mkdir("real")
        rep = self.mkdir("realrep")
        os.symlink(real, "link")
        os.symlink(rep, "replink")
        self.assertEqual(parse_args(["link", "replink", "n"]), Args("link", "replink", "n"))
        self.assertEqual(parse_args(["link/"]).scan_dir, "link")

    def test_a_dangling_or_looping_symlink_is_not_a_directory(self):
        os.symlink("nowhere", "dangling")
        os.symlink("loop2", "loop1")
        os.symlink("loop1", "loop2")
        for value in ("dangling", "loop1"):
            self.assertEqual(refusal(self, [value]).message, NOT_FOUND + value)

    def test_a_symlink_to_a_file_is_not_a_directory(self):
        self.touch("f")
        os.symlink("f", "flink")
        self.assertEqual(refusal(self, ["flink"]).message, NOT_FOUND + "flink")

    def test_args_is_frozen_and_has_the_three_fields(self):
        a = parse_args(["."])
        self.assertEqual([f.name for f in dataclasses.fields(Args)], ["scan_dir", "report_dir", "scanning_name"])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            a.scan_dir = "x"  # type: ignore[misc]

    def test_parse_args_does_not_change_its_input(self):
        argv = ["--q", ".", "", "n"]
        parse_args(argv)
        self.assertEqual(argv, ["--q", ".", "", "n"])

    def test_a_tuple_of_words_is_accepted(self):
        self.assertEqual(parse_args(("--q", ".")), Args(".", None, None))

    def test_words_that_cannot_be_directories_never_raise_anything_but_usage_error(self):
        for value in ("a\x00b", os.fsdecode(b"\xff\xfe"), "x" * 5000, "a/" * 3000, "\ud800", "\u00e9" * 300, "\t", "\x1b[31m"):
            with self.assertRaises(UsageError, msg=repr(value[:20])):
                parse_args([value])
            with self.assertRaises(UsageError, msg=repr(value[:20])):
                parse_args([".", value])


# ── the message reaches the console as it is, and the console makes it safe ────────────────────────────────────────────
class MessageThroughConsole(Scratch):
    def test_a_hostile_value_in_a_refusal_is_printed_control_free(self):
        import io
        from transit.console import Console
        d = self.mkdir("scan")
        hostile = "a\x1b]0;PWNED\x07\u009b\u202e"
        for argv in ([hostile], [d, hostile], [d, "", hostile.replace("a", "")], [d, "", "x" * 151 + hostile]):
            with self.assertRaises(UsageError) as cm:
                parse_args(argv)
            out, err = io.BytesIO(), io.BytesIO()
            Console("normal", out=out, err=err, err_is_tty=False).error(cm.exception.message)
            data = err.getvalue().decode("utf-8")
            self.assertEqual(out.getvalue(), b"")
            for ch in hostile:
                if ch not in "a]0;PWNED":
                    self.assertNotIn(ch, data.replace("\x1b[31m", "").replace("\x1b[0m", ""), argv)


# ── nothing is created (contract 1.2: every refusal happens before the first write) ─────────────────────────────────
class CreatesNothing(Scratch):
    def snapshot_run(self, argv):
        before = tree(self.tmp)
        with mock.patch("os.mkdir", side_effect=AssertionError("mkdir")), \
             mock.patch("os.makedirs", side_effect=AssertionError("makedirs")), \
             mock.patch("os.rename", side_effect=AssertionError("rename")), \
             mock.patch("os.replace", side_effect=AssertionError("replace")), \
             mock.patch("os.remove", side_effect=AssertionError("remove")), \
             mock.patch("os.unlink", side_effect=AssertionError("unlink")), \
             mock.patch("os.symlink", side_effect=AssertionError("symlink")), \
             mock.patch("builtins.open", side_effect=AssertionError("open")):
            try:
                parse_args(argv)
            except UsageError:
                pass
        self.assertEqual(tree(self.tmp), before)

    def test_success_and_every_refusal_leave_the_tree_untouched_and_open_nothing(self):
        d, r = self.mkdir("scan"), self.mkdir("reports")
        self.touch("file.txt")
        for argv in ([], ["--q"], ["missing"], [""], [d, "missing"], [d, "file.txt"], [d, r, "a/b"], [d, r, ".h"], [d, r, "x" * 151],
                     [d], [d, r], [d, r, "ok"], [d + "/"], ["file.txt"]):
            self.snapshot_run(argv)

    def test_the_work_dir_is_not_created(self):
        d = self.mkdir("scan")
        with tempfile.TemporaryDirectory() as parent:
            work = os.path.join(parent, "work")
            with mock.patch.dict(os.environ, {"WORK_DIR": work}):
                parse_args([d])
                with self.assertRaises(UsageError):
                    parse_args([d, "missing"])
            self.assertEqual(os.listdir(parent), [])

    def test_only_isdir_style_checks_touch_the_file_system(self):
        d = self.mkdir("scan")
        with mock.patch("os.listdir", side_effect=AssertionError("listdir")), \
             mock.patch("os.scandir", side_effect=AssertionError("scandir")), \
             mock.patch("os.walk", side_effect=AssertionError("walk")):
            parse_args([d])


# ── the 19 variants of E4, against bash ──────────────────────────────────────────────────────────────────────────────
class E4Variants(Scratch):
    def setUp(self):
        super().setUp()
        self.mkdir("scan")
        self.mkdir("reports")
        self.mkdir("--odd")
        self.touch("afile")

    def variants(self):
        """(label, argv, reason it is refused or None if it is accepted); the reason is a prefix of the message."""
        d, r = "scan", "reports"
        name = NAME_REFUSED
        return [
            ("no arguments", [], USAGE_WORD),
            ("only -- words", ["--quiet", "--"], USAGE_WORD),
            ("missing directory", ["nope"], NOT_FOUND + "nope"),
            ("empty directory string", [""], NOT_FOUND),
            ("missing report directory", [d, "nope"], NOT_FOUND + "nope"),
            ("empty report directory", [d, "", "nm"], None),
            ("name with a slash", [d, r, "a/b"], name),
            ("leading dot", [d, r, ".hid"], name),
            ("TAB in the name", [d, r, "a\tb"], name),
            ("150 characters", [d, r, "a" * 150], None),
            ("151 characters", [d, r, "a" * 151], name),
            ("a.b", [d, r, "a.b"], None),
            ("..x", [d, r, "..x"], name),
            ("a space in the name", [d, r, "a b"], None),
            ("empty name", [d, r, ""], None),
            ("a fourth argument", [d, r, "nm", "extra"], None),
            ("--quiet between positionals", [d, "--quiet", r, "--quiet", "nm"], None),
            ("./--odd", ["./--odd"], None),
            ("a file as directory", ["afile"], NOT_FOUND + "afile"),
        ]

    def test_there_are_19_and_each_one_is_accepted_or_refused_for_the_reason_of_the_contract(self):
        v = self.variants()
        self.assertEqual(len(v), 19)
        for label, argv, reason in v:
            if reason is None:
                parse_args(argv)
            else:
                with self.assertRaises(UsageError, msg=label) as cm:
                    parse_args(argv)
                self.assertTrue(cm.exception.message.startswith(reason), (label, cm.exception.message))

    @unittest.skipUnless(BASH, "bash is the oracle")
    def test_every_variant_gives_the_answer_of_scan_pipeline_sh(self):
        for label, argv, reason in self.variants():
            self.assertEqual(python_parse(argv), bash_parse(argv, self.tmp), label)
            self.assertEqual(python_parse(argv)[0] == "OK", reason is None, label)

    @unittest.skipUnless(BASH, "bash is the oracle")
    def test_more_command_lines_against_bash(self):
        self.mkdir("a", "b")
        os.symlink("scan", "slink")
        os.symlink("reports", "rlink")
        cases = [
            ["scan/"], ["scan//"], ["/"], ["//"], ["./scan/"], ["a/../scan"], ["slink", "rlink", "n"], ["slink/", "rlink/", "n"],
            ["scan", "reports/", "n"], ["scan", "", ""], ["scan", "", "n"], ["", "scan"], ["scan", "scan", "scan"], ["-q", "--q"],
            ["--odd"], ["./--odd/"], ["--min-severity", "medium", "scan"], ["scan", "--since", "abc"], ["scan", "--since", "abc", "x"],
            ["scan", "reports", "-"], ["scan", "reports", "-x"], ["scan", "reports", "x."], ["scan", "reports", "a..b"],
            ["scan", "reports", "a" * 149], ["scan", "reports", "\x7f"], ["scan", "reports", "a\nb"], ["scan", "reports", "/"],
            ["scan", "reports", "."], ["scan", "reports", ".."], ["scan", "reports", "~"], ["scan", "reports", "*"],
            ["scan", "reports", "n", "m", "o", "p"], ["afile", "reports"], ["scan", "afile"],
        ]
        for argv in cases:
            self.assertEqual(python_parse(argv), bash_parse(argv, self.tmp), argv)

    def test_the_scan_name_is_none_where_bash_uses_the_timestamp(self):
        self.assertIsNone(parse_args(["scan"]).scanning_name)
        self.assertIsNone(parse_args(["scan", "reports", ""]).scanning_name)

    def test_no_stdout_and_no_report_in_any_case(self):
        out = subprocess.run([sys.executable, "-I", "-c",
                              "import sys; sys.path.insert(0, %r); from transit.cli import parse_args, UsageError\n"
                              "for argv in ([], ['nope'], ['scan', 'reports', 'a/b'], ['scan']):\n"
                              "    try:\n        parse_args(argv)\n    except UsageError:\n        pass\n" % str(ROOT)],
                             cwd=self.tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual((out.returncode, out.stdout, out.stderr), (0, b"", b""))
        self.assertEqual(sorted(tree(self.tmp)), sorted(["scan", "reports", "--odd", "afile"]))


# ── layering ─────────────────────────────────────────────────────────────────────────────────────────────────────────
class Layering(unittest.TestCase):
    SRC = (ROOT / "transit" / "cli.py")

    def test_a_leaf_without_regular_expressions_or_processes(self):
        tree_ = ast.parse(self.SRC.read_text(encoding="utf-8"), feature_version=(3, 10))
        names = []
        for node in ast.walk(tree_):
            if isinstance(node, ast.Import):
                names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module or "")
        self.assertFalse([n for n in names if n == "transit" or n.startswith("transit.")], names)
        for banned in ("re", "subprocess", "shutil", "tempfile", "logging"):
            self.assertNotIn(banned, names)

    def test_no_output_no_shell_no_eval(self):
        tree_ = ast.parse(self.SRC.read_text(encoding="utf-8"))
        for node in ast.walk(tree_):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"print", "eval", "exec", "compile", "__import__", "open", "input"})
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "sys":
                self.assertNotIn(node.attr, {"stdout", "stderr", "exit"})
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                self.assertNotIn((node.func.value.id, node.func.attr),
                                 {("os", "system"), ("os", "popen"), ("os", "mkdir"), ("os", "makedirs"), ("os", "getenv")})
            self.assertFalse(isinstance(node, ast.keyword) and node.arg == "shell")
            if isinstance(node, ast.Attribute) and node.attr == "environ" and isinstance(node.value, ast.Name):
                self.assertNotEqual(node.value.id, "os")

    def test_compiles_with_warnings_as_errors(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(self.SRC.read_text(encoding="utf-8"), "cli.py", "exec")

    def test_importing_the_module_writes_nothing(self):
        res = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r); import transit.cli" % str(ROOT)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual((res.returncode, res.stdout, res.stderr), (0, b"", b""))


if __name__ == "__main__":
    unittest.main()
