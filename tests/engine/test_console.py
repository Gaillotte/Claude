"""Tests of transit/console.py (WP-01): channels, quiet, the verdict line, and the sanitiser (S1, S2, D-017, R-10). Plain unittest,
standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_console.py"

The byte-level check does not use the module's own tables: the forbidden characters are listed again here, as ``\\u`` escapes (no
invisible character is ever written literally in this file), so a sanitiser that loses a range cannot make its own test pass. The
C0/C1 behaviour is also compared with the console helpers of ``scan_pipeline.sh`` (``_san``, ``info``, ``warn``, ``ok``,
``fail_f``), cut out of the script and run by real bash in the C locale, and the progress line with the ``printf`` of its Layer 5 loop.
"""
from __future__ import annotations

import ast
import errno
import io
import os
import random
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from transit import console  # noqa: E402
from transit.console import BIDI_CONTROLS, Console, sanitise  # noqa: E402

BASH = shutil.which("bash")
SCRIPT = ROOT / "scan_pipeline.sh"

ESC = "\x1b"
BLUE, YELLOW, GREEN, RED, RESET = ESC + "[34m", ESC + "[33m", ESC + "[32m", ESC + "[31m", ESC + "[0m"
ERASE = ESC + "[K"
CLEAR = "\r" + ERASE  # what bash's _clr and Console.clear_progress write

# The characters that must never reach a terminal, written out again on purpose (see the module docstring).
EXPLICIT_BIDI = ("\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
                 "\u2066", "\u2067", "\u2068", "\u2069")


def forbidden(ch: str) -> bool:
    o = ord(ch)
    return o < 0x20 or 0x7F <= o <= 0x9F or ch in EXPLICIT_BIDI or 0xD800 <= o <= 0xDFFF


# The hostile names of S1 (ESC, CR, TAB, DEL, U+009B, U+202E, a literal \033) and a few more.
HOSTILE = {
    "esc_osc": "x" + ESC + "]0;PWNED\x07.py",
    "cr": "a\rb.txt",
    "tab": "a\tb.txt",
    "del": "a\x7fb.txt",
    "c1_csi": "a\u009b31mb.txt",
    "bidi_override": "a\u202efdp.exe",
    "literal_033": "lit\\033[31mred.txt",
    "lf": "a\nFAKE VERDICT\nPASS",
    "nul": "a\x00b",
    "nel": "a\u0085b",
    "isolates": "a\u2066b\u2069c\u061cd\u200ee\u200f",
    "undecodable": os.fsdecode(b"x\xff\xfe.py"),
    "raw_c1_bytes": os.fsdecode(b"x\xc2\x9b31m.py"),
    "csi_after_esc": ESC + "[2J" + ESC + "[31m",
}


class Rec:
    """A binary stream that records every write and flush into a shared list, so the order across streams can be checked."""

    def __init__(self, events, name, tty=False):
        self.events, self.name, self.tty = events, name, tty
        self.buf = bytearray()

    def write(self, data):
        self.events.append((self.name, "write", bytes(data)))
        self.buf += data
        return len(data)

    def flush(self):
        self.events.append((self.name, "flush", b""))

    def isatty(self):
        return self.tty

    def getvalue(self):
        return bytes(self.buf)


def mk(verbosity="normal", tty=None):
    out, err = io.BytesIO(), io.BytesIO()
    return Console(verbosity, out=out, err=err, err_is_tty=tty), out, err


def strip_engine_sequences(data: bytes) -> bytes:
    for seq in (BLUE, YELLOW, GREEN, RED, RESET, ERASE):
        data = data.replace(seq.encode(), b"")
    return data


def assert_control_free(tc: unittest.TestCase, data: bytes, allow=("\n",), label=""):
    """Every byte left after removing the engine's own colour sequences is printable or one of ``allow``."""
    rest = strip_engine_sequences(data)
    text = rest.decode("utf-8")  # strict: the stream must be valid UTF-8
    for i, ch in enumerate(text):
        if ch in allow:
            continue
        tc.assertFalse(forbidden(ch), "%s: forbidden U+%04X at %d in %r" % (label, ord(ch), i, text[max(0, i - 20):i + 20]))


# ── sanitise ─────────────────────────────────────────────────────────────────────────────────────────────────────────
class Sanitise(unittest.TestCase):
    def test_every_c0_control_and_del_become_a_question_mark(self):
        for o in list(range(0x20)) + [0x7F]:
            self.assertEqual(sanitise("a" + chr(o) + "b"), "a?b", hex(o))

    def test_every_c1_control_becomes_a_question_mark(self):
        # mutation guard: drop the C1 range
        for o in range(0x80, 0xA0):
            self.assertEqual(sanitise("a" + chr(o) + "b"), "a?b", hex(o))
        # the two-byte spelling C2 80 .. C2 9F, as bytes and as a surrogate-escaped name
        for o in range(0x80, 0xA0):
            self.assertEqual(sanitise(b"a\xc2" + bytes([o]) + b"b"), "a?b", hex(o))
            self.assertEqual(sanitise(os.fsdecode(b"a\xc2" + bytes([o]) + b"b")), "a?b", hex(o))

    def test_the_c1_pair_is_one_question_mark_whichever_way_it_was_decoded(self):
        # With a file system encoding that is not UTF-8 the two bytes C2 9B arrive as two lone surrogates; the bash console replaces
        # the pair by ONE question mark, and so do we.
        for o in range(0x80, 0xA0):
            self.assertEqual(sanitise("a\udcc2" + chr(0xDC00 + o) + "b"), "a?b", hex(o))
        self.assertEqual(sanitise("a\udcc2b"), "a?b")           # a lone C2 byte is just an undecodable byte
        self.assertEqual(sanitise("a\udcc2\udcA0b"), "a??b")    # C2 A0 is a valid character in UTF-8, but here both are undecodable
        self.assertEqual(sanitise("\udcc2\udc9b\udcc2\udc9b"), "??")

    def test_the_neighbours_of_the_c1_range_are_kept(self):
        for ch in (" ", "~", "\u00a0", "\u00a1", "\u00ad", "\u00c2", "\u00e9", "\u00ff", "\u0100"):
            self.assertEqual(sanitise("a" + ch + "b"), "a" + ch + "b", hex(ord(ch)))

    def test_every_bidi_control_is_replaced(self):
        # mutation guard: drop the bidi range
        self.assertEqual(len(EXPLICIT_BIDI), 12)
        for ch in EXPLICIT_BIDI:
            self.assertEqual(sanitise("a" + ch + "b"), "a?b", hex(ord(ch)))
        self.assertEqual(sanitise("".join(EXPLICIT_BIDI)), "?" * 12)

    def test_bidi_controls_constant_is_the_list_of_d_017_plus_the_three_marks(self):
        self.assertEqual(set(BIDI_CONTROLS), set(EXPLICIT_BIDI))
        self.assertIsInstance(BIDI_CONTROLS, frozenset)
        for must in ("\u061c", "\u200e", "\u200f", "\u202a", "\u202e", "\u2066", "\u2069"):
            self.assertIn(must, BIDI_CONTROLS)
        for must_not in ("\u202f", "\u2065", "\u206a", "\u200d", "\u200b", "\u2028", "\u2029"):
            self.assertNotIn(must_not, BIDI_CONTROLS)

    def test_lone_surrogates_the_undecodable_bytes_of_a_name_become_question_marks(self):
        self.assertEqual(sanitise(os.fsdecode(b"x\xff\xfey")), "x??y")
        self.assertEqual(sanitise("\ud800"), "?")
        self.assertEqual(sanitise("\udcff\udc80"), "??")

    def test_bytes_are_decoded_as_utf_8_and_each_undecodable_byte_is_a_question_mark(self):
        self.assertEqual(sanitise(b"plain"), "plain")
        self.assertEqual(sanitise("caf\u00e9 \u65e5\u672c".encode()), "caf\u00e9 \u65e5\u672c")
        self.assertEqual(sanitise(b"a\xffb"), "a?b")
        self.assertEqual(sanitise(b"\xc3"), "?")
        self.assertEqual(sanitise(b"\xc0\xaf"), "??")
        self.assertEqual(sanitise(b"\xe3\x81"), "??")  # a truncated three-byte sequence is two undecodable bytes, not one
        self.assertEqual(sanitise(b"a\x1b[31mb"), "a?[31mb")
        self.assertEqual(sanitise(b""), "")
        self.assertEqual(sanitise(bytearray(b"a\xffb")), "a?b")

    def test_a_genuine_replacement_character_is_kept(self):
        self.assertEqual(sanitise("a\ufffdb"), "a\ufffdb")
        self.assertEqual(sanitise("a\ufffdb".encode()), "a\ufffdb")

    def test_printable_text_is_unchanged(self):
        for s in ("", "plain ascii /path/to file.py", "caf\u00e9", "\u65e5\u672c\u8a9e", "emoji \U0001f600", "a b", "~!@#$%^&*()",
                  "\u00a0nbsp", "\u200bzero width", "\ufeffbom", "\\033[31m", "back\\slash"):
            self.assertEqual(sanitise(s), s)

    def test_a_literal_backslash_sequence_is_data_s2(self):
        self.assertEqual(sanitise("lit\\033[31mred.txt"), "lit\\033[31mred.txt")
        self.assertEqual(sanitise("a\\x1b]0;t\\x07"), "a\\x1b]0;t\\x07")
        self.assertEqual(sanitise("\\u202e"), "\\u202e")

    def test_it_is_character_for_character_and_idempotent(self):
        pool = [chr(c) for c in list(range(0, 0xC0)) + [0x61C, 0x200E, 0x202E, 0x2066, 0x2069, 0x3042, 0xFFFD, 0x1F600]] \
            + ["\udc80", "\ud800"] + list("abc /._-")
        rng = random.Random(20261113)
        for _ in range(400):
            s = "".join(rng.choice(pool) for _ in range(rng.randrange(0, 60)))
            got = sanitise(s)
            self.assertEqual(got, "".join("?" if forbidden(c) else c for c in s))
            self.assertEqual(len(got), len(s))
            self.assertEqual(sanitise(got), got)
            self.assertFalse(any(forbidden(c) for c in got))

    def test_never_raises(self):
        class Bad:
            def __str__(self):
                raise RuntimeError("no")

        for value in (None, 123, 1.5, object(), Bad(), memoryview(b"a\x1bb"), ["a"], b"\xff" * 5):
            self.assertIsInstance(sanitise(value), str)  # type: ignore[arg-type]
        self.assertEqual(sanitise(memoryview(b"a\x1bb")), "a?b")
        self.assertEqual(sanitise(123), "123")

    def test_a_str_subclass_with_a_hostile_str_method_cannot_smuggle_text(self):
        class Sneaky(str):
            def __str__(self):
                return "x\x1b]0;PWNED\x07"

        self.assertEqual(sanitise(Sneaky("plain")), "plain")  # the text it holds, not what its __str__ would say
        self.assertEqual(sanitise(Sneaky("a\x1bb")), "a?b")

        class Tampered(str):
            def isascii(self):
                return True

            def isprintable(self):
                return True

            def __radd__(self, other):
                return other + "\x1b]0;PWNED\x07"

        c, out, err = mk()
        c.info(Tampered("a\x1bb"))
        c.info(Tampered("plain"))
        self.assertEqual(out.getvalue().decode(), BLUE + "[INFO]" + RESET + "  a?b\n" + BLUE + "[INFO]" + RESET + "  plain\n")

    def test_the_result_can_always_be_encoded(self):
        for name, text in HOSTILE.items():
            sanitise(text).encode("utf-8")

    def test_large_input_is_fast(self):
        big = ("a" * 79 + ESC) * 50000  # 4 MB, one control per 80 characters
        t0 = time.monotonic()
        got = sanitise(big)
        self.assertLess(time.monotonic() - t0, 5.0)
        self.assertEqual(len(got), len(big))
        self.assertNotIn(ESC, got)
        t0 = time.monotonic()
        sanitise("\u00e9" * 4_000_000)
        self.assertLess(time.monotonic() - t0, 5.0)

    @unittest.skipUnless(BASH, "bash is the oracle")
    def test_c0_del_and_c1_agree_with_the_bash_console(self):
        lines = SCRIPT.read_text(encoding="utf-8").splitlines()
        defs = [next(x for x in lines if x.startswith(k)) for k in ("_clr()", "_san()", "info()", "warn()", "ok()", "fail_f()")]
        prog = "VERBOSITY=normal\n" + "\n".join(defs) + '\n"$1" "$2"\n'
        cases = [chr(o) for o in list(range(1, 0x20)) + [0x7F] + list(range(0x80, 0xA0))]
        cases += ["\u00a0", "\u00c2", "\u00e9", "\u65e5", "plain", "lit\\033[31m", "z"]
        for fn, py in (("info", "info"), ("ok", "ok"), ("warn", "warn"), ("fail_f", "fail_line")):
            for ch in cases:
                text = "a" + ch + "b"
                res = subprocess.run([BASH, "-c", prog, "bash", fn, text],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                c, out, err = mk()
                getattr(c, py)(text)
                self.assertEqual(out.getvalue(), res.stdout, (fn, repr(ch)))
                self.assertEqual(err.getvalue(), res.stderr, (fn, repr(ch)))


# ── channels and quiet ───────────────────────────────────────────────────────────────────────────────────────────────
class Channels(unittest.TestCase):
    def test_info_and_ok_go_to_stdout_with_the_bash_prefixes(self):
        c, out, err = mk()
        c.info("hello")
        c.ok("done")
        self.assertEqual(out.getvalue().decode(), BLUE + "[INFO]" + RESET + "  hello\n" + GREEN + "[OK]" + RESET + "    done\n")
        self.assertEqual(err.getvalue(), b"")

    def test_warn_fail_line_and_error_go_to_stderr(self):
        c, out, err = mk()
        c.warn("careful")
        c.fail_line("[a.py] bad")
        c.error("cannot go on")
        self.assertEqual(err.getvalue().decode(),
                         YELLOW + "[WARN]" + RESET + "  careful\n" + RED + "[FAIL]" + RESET + "  [a.py] bad\n"
                         + RED + "[FAIL]" + RESET + "  cannot go on\n")
        self.assertEqual(out.getvalue(), b"")

    def test_each_call_is_exactly_one_line(self):
        c, out, err = mk()
        for name, text in HOSTILE.items():
            before_o, before_e = out.getvalue().count(b"\n"), err.getvalue().count(b"\n")
            c.info(text)
            c.warn(text)
            self.assertEqual(out.getvalue().count(b"\n"), before_o + 1, name)
            self.assertEqual(err.getvalue().count(b"\n"), before_e + 1, name)

    def test_text_is_written_as_utf_8_whatever_the_locale(self):
        c, out, err = mk()
        c.info("caf\u00e9 \u65e5\u672c \U0001f600")
        self.assertIn("caf\u00e9 \u65e5\u672c \U0001f600".encode("utf-8"), out.getvalue())

    def test_quiet_silences_info_and_ok_only(self):
        c, out, err = mk("quiet")
        c.info("i")
        c.ok("o")
        self.assertEqual((out.getvalue(), err.getvalue()), (b"", b""))
        c.warn("w")
        c.fail_line("f")
        c.error("e")
        self.assertEqual(out.getvalue(), b"")
        self.assertEqual(err.getvalue().decode().count("\n"), 3)
        c.verdict("PASS")
        self.assertEqual(out.getvalue(), b"PASS\n")

    def test_with_quiet_stdout_is_exactly_the_verdict_line(self):
        c, out, err = mk("quiet")
        c.info("a")
        c.ok("b")
        c.warn("c")
        c.verdict("FAIL")
        self.assertEqual(out.getvalue(), b"FAIL\n")

    def test_verbose_and_unknown_words_behave_as_normal(self):
        for v in ("verbose", "normal", "bogus", "QUIET", ""):
            c, out, err = mk(v)
            c.info("x")
            self.assertIn(b"[INFO]", out.getvalue(), v)

    def test_default_verbosity_is_normal(self):
        out = io.BytesIO()
        Console(out=out, err=io.BytesIO(), err_is_tty=False).info("x")
        self.assertIn(b"[INFO]", out.getvalue())

    def test_text_waiting_in_the_text_layer_of_a_default_stream_is_written_first(self):
        raw = io.BytesIO()
        front = io.TextIOWrapper(raw, encoding="utf-8")  # buffered: nothing reaches ``raw`` until a flush
        front.write("earlier, from someone else\n")
        self.assertEqual(raw.getvalue(), b"")
        with mock.patch.object(sys, "stdout", front), mock.patch.object(sys, "stderr", io.StringIO()):
            c = Console("normal", err_is_tty=False)
            c.info("after")
        lines = raw.getvalue().decode().split("\n")
        self.assertEqual(lines[0], "earlier, from someone else")
        self.assertIn("[INFO]", lines[1])

    def test_nothing_is_written_at_construction(self):
        out, err = io.BytesIO(), io.BytesIO()
        Console("normal", out=out, err=err, err_is_tty=True)
        self.assertEqual((out.getvalue(), err.getvalue()), (b"", b""))

    def test_every_write_is_flushed(self):
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err"), err_is_tty=False)
        c.info("a")
        c.warn("b")
        c.verdict("PASS")
        kinds = [(n, k) for n, k, _ in ev]
        self.assertEqual(kinds, [("out", "write"), ("out", "flush"), ("err", "write"), ("err", "flush"),
                                 ("out", "write"), ("out", "flush")])

    def test_each_message_is_one_write_call(self):
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err"), err_is_tty=False)
        c.info("a")
        c.ok("b")
        c.warn("c")
        c.fail_line("d")
        c.error("e")
        self.assertEqual([k for _, k, _ in ev].count("write"), 5)

    def test_non_text_arguments_do_not_raise(self):
        c, out, err = mk()
        c.info(123)  # type: ignore[arg-type]
        c.warn(None)  # type: ignore[arg-type]
        c.info(b"bytes \xff")  # type: ignore[arg-type]
        self.assertIn(b"123", out.getvalue())
        self.assertIn(b"bytes ?", out.getvalue())

    def test_the_text_argument_is_sanitised_by_every_method(self):
        # mutation guard: a method that forgets to sanitise
        for method in ("info", "ok", "warn", "fail_line", "error"):
            c, out, err = mk()
            getattr(c, method)("a" + ESC + "]0;x\x07\u202e\u009b")
            data = out.getvalue() + err.getvalue()
            self.assertTrue(data.endswith(b"a?]0;x???\n"), (method, data))


class Verdict(unittest.TestCase):
    def test_pass_and_fail_are_written_exactly(self):
        for v in ("PASS", "FAIL"):
            c, out, err = mk()
            c.verdict(v)
            self.assertEqual(out.getvalue(), (v + "\n").encode())
            self.assertEqual(err.getvalue(), b"")

    def test_any_other_value_raises_value_error_and_writes_nothing(self):
        for bad in ("pass", "Pass", "WARN", "PASSED", "", "PASS\n", " PASS", "FAIL ", None, 1, b"PASS"):
            c, out, err = mk()
            with self.assertRaises(ValueError, msg=repr(bad)):
                c.verdict(bad)  # type: ignore[arg-type]
            self.assertEqual((out.getvalue(), err.getvalue()), (b"", b""), repr(bad))

    def test_a_refused_value_does_not_even_clear_the_progress_line(self):
        c, out, err = mk("normal", tty=True)
        c.progress(1, 2, "a.py")
        before = err.getvalue()
        with self.assertRaises(ValueError):
            c.verdict("MAYBE")
        self.assertEqual(err.getvalue(), before)

    def test_the_verdict_is_the_last_stdout_write_of_a_run(self):
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err"), err_is_tty=False)
        c.info("a")
        c.warn("b")
        c.ok("c")
        c.fail_line("d")
        c.verdict("FAIL")
        writes = [(n, d) for n, k, d in ev if k == "write" and n == "out"]
        self.assertEqual(writes[-1], ("out", b"FAIL\n"))
        self.assertEqual(ev[-1][:2], ("out", "flush"))

    def test_what_is_written_is_the_engines_own_constant_not_the_argument(self):
        class Evil(str):
            def __add__(self, other):
                return "PASS\x1b]0;PWNED\x07" + other

        for word in ("PASS", "FAIL"):
            c, out, err = mk()
            c.verdict(Evil(word))
            self.assertEqual(out.getvalue(), (word + "\n").encode())

    def test_the_verdict_is_never_coloured_or_prefixed(self):
        c, out, _ = mk()
        c.verdict("PASS")
        self.assertEqual(out.getvalue().split(b"\n")[0], b"PASS")


# ── S1 / S2 / D-017 at the byte level ────────────────────────────────────────────────────────────────────────────────
class ByteLevel(unittest.TestCase):
    def test_every_method_with_every_hostile_name_writes_only_printable_bytes(self):
        for name, text in HOSTILE.items():
            for wrap in ("%s", "[%s] FAIL", "dir/%s/x.py", "archive entry %s: bad"):
                msg = wrap % text
                c, out, err = mk()
                c.info(msg)
                c.ok(msg)
                c.warn(msg)
                c.fail_line(msg)
                c.error(msg)
                assert_control_free(self, out.getvalue(), label="%s stdout" % name)
                assert_control_free(self, err.getvalue(), label="%s stderr" % name)

    def test_the_exact_replacement_for_the_six_names_of_s1(self):
        want = {
            "esc_osc": "x?]0;PWNED?.py", "cr": "a?b.txt", "tab": "a?b.txt", "del": "a?b.txt", "c1_csi": "a?31mb.txt",
            "bidi_override": "a?fdp.exe",
        }
        for name, expected in want.items():
            c, out, err = mk()
            c.info(HOSTILE[name])
            self.assertEqual(out.getvalue().decode(), BLUE + "[INFO]" + RESET + "  " + expected + "\n", name)

    def test_the_literal_backslash_name_is_printed_with_its_four_characters_s2(self):
        c, out, err = mk()
        c.info(HOSTILE["literal_033"])
        c.warn(HOSTILE["literal_033"])
        self.assertIn(b"lit\\033[31mred.txt", out.getvalue())
        self.assertIn(b"lit\\033[31mred.txt", err.getvalue())
        self.assertNotIn(b"lit\x1b", out.getvalue())

    def test_a_name_cannot_forge_a_second_line(self):
        c, out, err = mk()
        c.info(HOSTILE["lf"])
        self.assertEqual(out.getvalue().count(b"\n"), 1)
        c.verdict("FAIL")
        self.assertEqual(out.getvalue().split(b"\n")[-2], b"FAIL")

    def test_a_name_cannot_reach_the_stream_as_a_second_escape_after_the_engines_own(self):
        c, out, err = mk()
        c.warn(ESC + "[31mfake colour")
        self.assertEqual(err.getvalue().count(ESC.encode()), 2)  # the engine's own: colour start and reset

    def test_the_bidi_override_cannot_make_a_path_read_differently(self):
        c, out, err = mk()
        c.warn("[evil\u202etxt.exe] gpj.")
        self.assertNotIn("\u202e".encode(), err.getvalue())


# ── the progress line (R-10) ─────────────────────────────────────────────────────────────────────────────────────────
class Progress(unittest.TestCase):
    PREFIX = CLEAR + BLUE + "[L5]" + RESET + "  "

    def test_drawn_only_on_a_terminal(self):
        c, out, err = mk("normal", tty=False)
        c.progress(1, 3, "a.py")
        c.clear_progress()
        self.assertEqual((out.getvalue(), err.getvalue()), (b"", b""))
        c, out, err = mk("normal", tty=True)
        c.progress(1, 3, "a.py")
        self.assertEqual(out.getvalue(), b"")
        self.assertEqual(err.getvalue().decode(), self.PREFIX + "[1/3] a.py")

    def test_the_default_asks_the_stream(self):
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err", tty=True))
        c.progress(2, 5, "p.py")
        self.assertIn(b"[2/5] p.py", b"".join(d for n, k, d in ev if n == "err"))
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err", tty=False))
        c.progress(2, 5, "p.py")
        self.assertEqual(ev, [])

    def test_an_explicit_value_beats_the_stream(self):
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err", tty=True), err_is_tty=False)
        c.progress(1, 1, "p.py")
        self.assertEqual(ev, [])
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err", tty=False), err_is_tty=True)
        c.progress(1, 1, "p.py")
        self.assertIn(b"[1/1] p.py", b"".join(d for n, k, d in ev if n == "err"))

    def test_a_stream_that_cannot_answer_isatty_means_no_progress(self):
        class NoTty:
            def __init__(self):
                self.data = b""

            def write(self, d):
                self.data += d
                return len(d)

            def flush(self):
                pass

        err = NoTty()
        c = Console("normal", out=io.BytesIO(), err=err)
        c.progress(1, 1, "x")  # must not raise
        self.assertEqual(err.data, b"")

    def test_quiet_draws_nothing_even_on_a_terminal(self):
        c, out, err = mk("quiet", tty=True)
        c.progress(1, 3, "a.py")
        c.clear_progress()
        self.assertEqual((out.getvalue(), err.getvalue()), (b"", b""))

    def test_the_counter_is_right_aligned_to_the_width_of_the_total(self):
        c, out, err = mk("normal", tty=True)
        c.progress(3, 120, "a.py")
        c.progress(120, 120, "b.py")
        c.progress(1, 9, "c.py")
        text = err.getvalue().decode()
        self.assertIn("[  3/120] a.py", text)
        self.assertIn("[120/120] b.py", text)
        self.assertIn("[1/9] c.py", text)

    @unittest.skipUnless(BASH, "bash is the oracle")
    def test_the_line_equals_the_printf_of_the_layer_5_loop(self):
        lines = SCRIPT.read_text(encoding="utf-8").splitlines()
        i = next(k for k, x in enumerate(lines) if x.strip().startswith('printf "\\r\\033[K\\033[34m[L5]'))
        fmt_line = lines[i].strip()
        self.assertTrue(fmt_line.endswith("\\"), fmt_line)
        self.assertIn('"$current" "$total_files" "${short_f:0:80}"', lines[i + 1])
        prog = "total_files=$1; current=$2; short_f=$3\n" + fmt_line[:-1] + ' "$current" "$total_files" "${short_f:0:80}"\n'
        for current, total, name in ((1, 3, "a.py"), (3, 120, "dir/b.py"), (120, 120, "c.py"), (7, 9, "n" * 200), (1, 1, "x y.txt")):
            res = subprocess.run([BASH, "-c", prog, "x", str(total), str(current), name], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, check=True)
            c, out, err = mk("normal", tty=True)
            c.progress(current, total, name)
            self.assertEqual(err.getvalue(), res.stdout, (current, total, name))

    def test_the_name_is_cut_to_80_characters(self):
        c, out, err = mk("normal", tty=True)
        c.progress(1, 1, "n" * 200)
        self.assertEqual(err.getvalue().decode(), self.PREFIX + "[1/1] " + "n" * 80)
        c, out, err = mk("normal", tty=True)
        c.progress(1, 1, "n" * 80)
        self.assertTrue(err.getvalue().decode().endswith("n" * 80))
        c, out, err = mk("normal", tty=True)
        c.progress(1, 1, "\u00e9" * 100)
        self.assertTrue(err.getvalue().decode().endswith("\u00e9" * 80))
        self.assertFalse(err.getvalue().decode().endswith("\u00e9" * 81))

    def test_every_hostile_name_draws_only_printable_bytes_cr_and_the_engines_sequences(self):
        for name, text in HOSTILE.items():
            for wrapped in (text, "d/" + text + "/x.py", "n" * 70 + text, text * 30):
                c, out, err = mk("normal", tty=True)
                c.progress(7, 9, wrapped)
                data = err.getvalue()
                assert_control_free(self, data, allow=("\r",), label=name)
                self.assertEqual(data.count(b"\r"), 1, "only the engine's own return, %s" % name)
                self.assertEqual(out.getvalue(), b"")

    def test_a_long_hostile_name_cut_in_the_middle_of_an_escape_stays_clean(self):
        for k in range(70, 90):
            text = "a" * k + ESC + "]0;PWNED\x07" + "b" * 20
            c, out, err = mk("normal", tty=True)
            c.progress(1, 1, text)
            assert_control_free(self, err.getvalue(), allow=("\r",), label=str(k))

    def test_the_name_is_sanitised_before_it_is_cut(self):
        # mutation guard: cut the progress line before sanitising it.  ``sanitise`` is character for character, so the output
        # cannot tell the two orders apart; the call can.
        seen = []
        real = console.sanitise

        def spy(value):
            seen.append(value)
            return real(value)

        c, out, err = mk("normal", tty=True)
        name = "a" * 150 + ESC + "]0;PWNED\x07" + "b" * 100
        with mock.patch.object(console, "sanitise", spy):
            c.progress(1, 1, name)
        self.assertIn(name, seen, "sanitise must see the whole name, not the first 80 characters")
        self.assertNotIn(ESC, err.getvalue().decode()[len(self.PREFIX) - 0:])

    def test_the_name_is_sanitised_when_the_replacement_would_land_inside_the_cut(self):
        c, out, err = mk("normal", tty=True)
        c.progress(1, 1, "a" * 78 + ESC + ESC + "zz")
        self.assertTrue(err.getvalue().decode().endswith("a" * 78 + "??"))

    def test_clear_progress_erases_a_drawn_line_once(self):
        c, out, err = mk("normal", tty=True)
        c.progress(1, 2, "a.py")
        before = err.getvalue()
        c.clear_progress()
        self.assertEqual(err.getvalue(), before + CLEAR.encode())
        c.clear_progress()
        self.assertEqual(err.getvalue(), before + CLEAR.encode())

    def test_clear_progress_without_a_drawn_line_writes_nothing(self):
        c, out, err = mk("normal", tty=True)
        c.clear_progress()
        self.assertEqual(err.getvalue(), b"")

    def test_every_other_method_clears_the_line_first(self):
        calls = (("info", ("x",)), ("ok", ("x",)), ("warn", ("x",)), ("fail_line", ("x",)), ("error", ("x",)),
                 ("verdict", ("PASS",)), ("exception", ("where", RuntimeError("boom"))))
        for method, args in calls:
            ev = []
            c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err", tty=True))
            c.progress(1, 2, "a.py")
            ev.clear()
            getattr(c, method)(*args)
            writes = [(n, d) for n, k, d in ev if k == "write"]
            self.assertEqual(writes[0], ("err", CLEAR.encode()), method)
            self.assertGreaterEqual(len(writes), 2, method)
            # and a second call does not clear again
            ev.clear()
            getattr(c, method)(*args)
            self.assertNotIn(("err", CLEAR.encode()), [(n, d) for n, k, d in ev if k == "write"], method)

    def test_the_clear_comes_before_the_message_across_streams(self):
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err", tty=True))
        c.progress(1, 2, "a.py")
        c.info("after")
        order = [(n, d) for n, k, d in ev if k == "write"]
        self.assertEqual([n for n, _ in order], ["err", "err", "out"])
        self.assertEqual(order[1][1], CLEAR.encode())

    def test_progress_after_a_redraw_replaces_the_line(self):
        c, out, err = mk("normal", tty=True)
        c.progress(1, 2, "a.py")
        c.progress(2, 2, "b.py")
        self.assertEqual(err.getvalue().decode().count(CLEAR), 2)

    def test_no_clear_sequence_is_written_when_stderr_is_not_a_terminal(self):
        c, out, err = mk("normal", tty=False)
        c.info("x")
        c.warn("y")
        c.verdict("PASS")
        self.assertNotIn(b"\r", err.getvalue())
        self.assertNotIn(ERASE.encode(), err.getvalue())

    def test_a_quiet_suppressed_message_leaves_a_drawn_line_alone(self):
        # a line can only be drawn when not quiet, so this is the normal-mode view of the same rule: nothing is written for a
        # message that is not printed
        c, out, err = mk("quiet", tty=True)
        c.info("x")
        c.ok("y")
        self.assertEqual((out.getvalue(), err.getvalue()), (b"", b""))


# ── exception ────────────────────────────────────────────────────────────────────────────────────────────────────────
class ExceptionBlock(unittest.TestCase):
    def raised(self, exc):
        try:
            raise exc
        except BaseException as e:  # noqa: BLE001
            return e

    def test_goes_to_stderr_with_the_label_the_class_and_the_message(self):
        c, out, err = mk()
        c.exception("internal error", self.raised(ValueError("boom")))
        text = err.getvalue().decode()
        self.assertEqual(out.getvalue(), b"")
        self.assertIn("internal error", text)
        self.assertIn("ValueError", text)
        self.assertIn("boom", text)
        self.assertIn("Traceback", text)
        self.assertTrue(text.startswith(RED + "[FAIL]" + RESET + "  "))

    def test_hostile_text_in_the_message_the_label_and_the_traceback_is_sanitised(self):
        for name, text in HOSTILE.items():
            c, out, err = mk()
            exc = self.raised(RuntimeError("can't read " + text))
            c.exception("scanning " + text, exc)
            data = err.getvalue()
            assert_control_free(self, data, label=name)
            self.assertEqual(out.getvalue(), b"")

    def test_a_file_name_in_the_source_line_of_the_traceback_is_sanitised_too(self):
        evil = "x" + ESC + "]0;PWNED\x07"
        try:
            exec(compile("def f():\n    raise OSError(%r)\nf()\n" % evil, "<" + evil + ">", "exec"), {})  # noqa: S102
        except OSError as e:
            exc = e
        c, out, err = mk()
        c.exception("run", exc)
        assert_control_free(self, err.getvalue())

    def test_a_message_with_line_breaks_cannot_start_a_line_of_its_own_at_column_zero(self):
        c, out, err = mk()
        c.exception("run", self.raised(RuntimeError("one\n[FAIL]  forged\nPASS")))
        lines = err.getvalue().decode().split("\n")[:-1]
        self.assertTrue(lines[0].startswith(RED + "[FAIL]" + RESET), lines[0])
        for line in lines[1:]:
            self.assertTrue(line.startswith("    "), repr(line))

    def test_the_block_has_several_lines_and_is_one_write(self):
        ev = []
        c = Console("normal", out=Rec(ev, "out"), err=Rec(ev, "err"), err_is_tty=False)
        c.exception("internal error", self.raised(KeyError("k")))
        writes = [d for n, k, d in ev if k == "write"]
        self.assertEqual(len(writes), 1)
        self.assertGreaterEqual(writes[0].count(b"\n"), 3)
        self.assertTrue(writes[0].endswith(b"\n"))
        self.assertFalse(writes[0].endswith(b"\n\n"))

    def test_a_chained_exception_is_included(self):
        try:
            try:
                raise KeyError("inner-cause")
            except KeyError as inner:
                raise RuntimeError("outer") from inner
        except RuntimeError as e:
            exc = e
        c, out, err = mk()
        c.exception("x", exc)
        text = err.getvalue().decode()
        self.assertIn("inner-cause", text)
        self.assertIn("outer", text)

    def test_base_exceptions_and_an_exception_that_cannot_be_printed(self):
        class Unprintable(Exception):
            def __str__(self):
                raise RuntimeError("no str")

        for exc in (self.raised(KeyboardInterrupt()), self.raised(SystemExit(0)), self.raised(Unprintable()), RuntimeError("never raised")):
            c, out, err = mk()
            c.exception("where", exc)  # must not raise
            self.assertIn(b"where", err.getvalue())
            self.assertIn(type(exc).__name__.encode(), err.getvalue())

    def test_quiet_does_not_silence_it(self):
        c, out, err = mk("quiet")
        c.exception("internal error", self.raised(ValueError("boom")))
        self.assertIn(b"boom", err.getvalue())

    def test_a_label_that_is_not_text_does_not_raise(self):
        c, out, err = mk()
        c.exception(None, ValueError("v"))  # type: ignore[arg-type]
        self.assertIn(b"ValueError", err.getvalue())


# ── a closed pipe ────────────────────────────────────────────────────────────────────────────────────────────────────
class Broken:
    def __init__(self, exc):
        self.exc, self.calls = exc, 0

    def write(self, d):
        self.calls += 1
        raise self.exc

    def flush(self):
        raise self.exc

    def isatty(self):
        return False


class ClosedPipe(unittest.TestCase):
    def every_method(self, c):
        c.info("i")
        c.ok("o")
        c.warn("w")
        c.fail_line("f")
        c.error("e")
        c.progress(1, 2, "p")
        c.clear_progress()
        c.exception("x", ValueError("v"))
        c.verdict("PASS")

    def test_a_broken_pipe_on_stdout_is_swallowed_and_stderr_still_works(self):
        for exc in (BrokenPipeError(errno.EPIPE, "pipe"), OSError(errno.EIO, "io"), ValueError("I/O operation on closed file")):
            err = io.BytesIO()
            c = Console("normal", out=Broken(exc), err=err, err_is_tty=True)
            self.every_method(c)
            self.assertIn(b"[WARN]", err.getvalue())
            self.assertIn(b"[FAIL]", err.getvalue())

    def test_a_broken_pipe_on_stderr_is_swallowed_and_stdout_still_works(self):
        for exc in (BrokenPipeError(errno.EPIPE, "pipe"), OSError(errno.ENOSPC, "full")):
            out = io.BytesIO()
            c = Console("normal", out=out, err=Broken(exc), err_is_tty=False)
            self.every_method(c)
            self.assertIn(b"[INFO]", out.getvalue())
            self.assertTrue(out.getvalue().endswith(b"PASS\n"))

    def test_both_broken_never_raises(self):
        c = Console("normal", out=Broken(BrokenPipeError()), err=Broken(BrokenPipeError()), err_is_tty=True)
        self.every_method(c)

    def test_a_closed_stream_object_is_swallowed(self):
        out, err = io.BytesIO(), io.BytesIO()
        c = Console("normal", out=out, err=err, err_is_tty=False)
        out.close()
        err.close()
        self.every_method(c)

    def test_a_broken_stream_is_not_hammered(self):
        out = Broken(BrokenPipeError(errno.EPIPE, "pipe"))
        c = Console("normal", out=out, err=io.BytesIO(), err_is_tty=False)
        for _ in range(5):
            c.info("x")
        self.assertLessEqual(out.calls, 1)

    def test_a_write_error_that_is_not_a_closed_pipe_does_not_stop_later_output(self):
        class Flaky:
            def __init__(self):
                self.data, self.n = b"", 0

            def write(self, d):
                self.n += 1
                if self.n == 1:
                    raise OSError(errno.EAGAIN, "try again")
                self.data += d
                return len(d)

            def flush(self):
                pass

            def isatty(self):
                return False

        out = Flaky()
        c = Console("normal", out=out, err=io.BytesIO(), err_is_tty=False)
        c.info("lost")
        c.info("kept")
        c.verdict("PASS")
        self.assertIn(b"kept", out.data)
        self.assertTrue(out.data.endswith(b"PASS\n"))

    def test_a_real_pipe_closed_by_the_reader_ends_with_status_0_and_no_noise(self):
        code = ("import sys, time\nsys.path.insert(0, %r)\nfrom transit.console import Console\n"
                "c = Console('normal')\ntime.sleep(0.5)\n"
                "for i in range(2000):\n    c.info('line %%d' %% i)\nc.warn('still here')\nc.verdict('PASS')\n" % str(ROOT))
        p = subprocess.Popen([sys.executable, "-I", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdout.close()
        _, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 0, err)
        self.assertIn(b"still here", err)
        self.assertNotIn(b"Exception ignored", err)
        self.assertNotIn(b"Traceback", err)

    def test_a_real_pipe_closed_on_stderr_ends_with_status_0_and_the_verdict_on_stdout(self):
        code = ("import sys, time\nsys.path.insert(0, %r)\nfrom transit.console import Console\n"
                "c = Console('normal')\ntime.sleep(0.5)\n"
                "for i in range(2000):\n    c.warn('warning %%d' %% i)\nc.verdict('FAIL')\n" % str(ROOT))
        p = subprocess.Popen([sys.executable, "-I", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stderr.close()
        out, _ = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertTrue(out.endswith(b"FAIL\n"), out[-50:])


# ── the default streams ──────────────────────────────────────────────────────────────────────────────────────────────
class DefaultStreams(unittest.TestCase):
    def test_defaults_are_the_binary_buffers_of_sys_stdout_and_sys_stderr(self):
        ob, eb = io.BytesIO(), io.BytesIO()
        so, se = io.TextIOWrapper(ob, encoding="latin-1", write_through=True), io.TextIOWrapper(eb, encoding="latin-1", write_through=True)
        with mock.patch.object(sys, "stdout", so), mock.patch.object(sys, "stderr", se):
            c = Console("normal", err_is_tty=False)
            c.info("caf\u00e9 \u65e5")
            c.warn("w")
            c.verdict("PASS")
        self.assertIn("caf\u00e9 \u65e5".encode("utf-8"), ob.getvalue())  # UTF-8 whatever the text layer's encoding
        self.assertTrue(ob.getvalue().endswith(b"PASS\n"))
        self.assertIn(b"[WARN]", eb.getvalue())

    def test_a_text_only_stream_is_written_through_as_text(self):
        so, se = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", so), mock.patch.object(sys, "stderr", se):
            c = Console("normal", err_is_tty=False)
            c.info("caf\u00e9")
            c.warn("w\x1b")
            c.verdict("FAIL")
        self.assertEqual(so.getvalue(), BLUE + "[INFO]" + RESET + "  caf\u00e9\nFAIL\n")
        self.assertEqual(se.getvalue(), YELLOW + "[WARN]" + RESET + "  w?\n")

    def test_a_text_only_stream_that_cannot_encode_loses_the_characters_not_the_stream(self):
        class AsciiOnly:
            def __init__(self):
                self.data = ""

            def write(self, text):
                text.encode("ascii")
                self.data += text
                return len(text)

            def flush(self):
                pass

        so = AsciiOnly()
        with mock.patch.object(sys, "stdout", so), mock.patch.object(sys, "stderr", io.StringIO()):
            c = Console("normal", err_is_tty=False)
            c.info("caf" + chr(0xE9))
            c.info("next")
            c.verdict("PASS")
        self.assertIn("caf?", so.data)
        self.assertIn("next", so.data)
        self.assertTrue(so.data.endswith("PASS\n"))

    def test_no_stream_at_all_does_not_raise(self):
        with mock.patch.object(sys, "stdout", None), mock.patch.object(sys, "stderr", None):
            c = Console("normal")
            c.info("x")
            c.warn("y")
            c.progress(1, 1, "z")
            c.verdict("PASS")

    def test_the_streams_are_looked_up_when_the_console_is_made(self):
        first, second = io.BytesIO(), io.BytesIO()
        s1 = io.TextIOWrapper(first, encoding="utf-8", write_through=True)
        s2 = io.TextIOWrapper(second, encoding="utf-8", write_through=True)
        with mock.patch.object(sys, "stdout", s1), mock.patch.object(sys, "stderr", io.StringIO()):
            c = Console("normal", err_is_tty=False)
        with mock.patch.object(sys, "stdout", s2):
            c.info("x")
        self.assertIn(b"[INFO]", first.getvalue())
        self.assertEqual(second.getvalue(), b"")

    def test_importing_the_module_writes_nothing(self):
        res = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r); import transit.console" % str(ROOT)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual((res.returncode, res.stdout, res.stderr), (0, b"", b""))

    def test_the_real_process_streams_carry_the_bytes(self):
        code = ("import sys\nsys.path.insert(0, %r)\nfrom transit.console import Console\n"
                "c = Console('normal')\nc.info('caf\\u00e9')\nc.warn('w\\x1b[2J')\nc.verdict('PASS')\n" % str(ROOT))
        res = subprocess.run([sys.executable, "-I", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.decode("utf-8"), BLUE + "[INFO]" + RESET + "  caf\u00e9\nPASS\n")
        self.assertEqual(res.stderr.decode("utf-8"), YELLOW + "[WARN]" + RESET + "  w?[2J\n")


# ── layering ─────────────────────────────────────────────────────────────────────────────────────────────────────────
class Layering(unittest.TestCase):
    def test_a_leaf_without_regular_expressions(self):
        tree = ast.parse((ROOT / "transit" / "console.py").read_text(encoding="utf-8"), feature_version=(3, 10))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module or "")
        self.assertFalse([n for n in names if n == "transit" or n.startswith("transit.")], names)
        for banned in ("re", "subprocess", "logging"):
            self.assertNotIn(banned, names)

    def test_compiles_with_warnings_as_errors(self):
        import warnings
        src = (ROOT / "transit" / "console.py").read_text(encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(src, "console.py", "exec")

    def test_no_eval_exec_or_shell(self):
        tree = ast.parse((ROOT / "transit" / "console.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"eval", "exec", "compile", "__import__"})
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                self.assertNotIn((node.func.value.id, node.func.attr), {("os", "system"), ("os", "popen")})
            self.assertFalse(isinstance(node, ast.keyword) and node.arg == "shell")

    def test_no_invisible_or_bidi_character_is_written_literally_in_the_module(self):
        for path in (ROOT / "transit" / "console.py", Path(__file__)):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for ch in line:
                    self.assertFalse(forbidden(ch) or ch in "\u00a0\u00ad\u200b\u200c\u200d\u2028\u2029\ufeff",
                                     "%s:%d has U+%04X" % (path.name, n, ord(ch)))


if __name__ == "__main__":
    unittest.main()
