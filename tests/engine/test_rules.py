"""Tests of ``transit/rules`` (WP-04; docs/python_engine_design.md sections 9.1, 9.2, 9.3 and 11).

    python3 -I -m unittest discover -s tests/engine -p "test_rules.py"

Oracles: real ``grep`` (and ``tr`` for the folded view of ``grep_flat``) for every mode, ``rx`` itself for the routing of long
lines (the whole-buffer linear matcher and the plain ``re`` answer), a ``bytes.split`` model for the long-line finder. A
timing or memory claim is measured, not assumed (the 600 KB hostile line, the 90 MB of two-byte lines in a child process).
No token-shaped credential appears here. Rule ids used by the tests are unique per call (``rid``): every test module of the
suite runs in one process and the engine-wide registry is shared.
"""
import contextlib
import dataclasses
import itertools
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from transit import findings, rules, rx  # noqa: E402
from transit.rules import (  # noqa: E402
    AllOf, AnyOf, AppliesTo, Match, Matcher, Not, RuleRun, RuleSet, RuleSpec, ScanBudgetExceeded, SearchPolicy, Target,
    evaluate, run_ruleset,
)

GREP = shutil.which("grep")
TR = shutil.which("tr")
ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
FOLD = bytes(32 if b in (9, 10, 13) else b for b in range(256))
_COUNTER = itertools.count(1)


# ------------------------------------------------------------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------------------------------------------------------------
def rid(slug: str = "x") -> str:
    """A rule id nobody else uses (the registry is process-wide)."""
    return "wp04t/%04d-%s" % (next(_COUNTER), slug)


def spec(cond, outcome="fail", message="CWE-0:wp04_test", **kw) -> RuleSpec:
    return RuleSpec(id=kw.pop("id", None) or rid(), outcome=outcome, message=message, cond=cond, **kw)


def reg(cond):
    """Register ``cond`` (a Match or a composite) through a one-row RuleSet and return it, now evaluable."""
    RuleSet("wp04t-reg-%d" % next(_COUNTER), [spec(cond)])
    return cond


def tgt(data: bytes, limit: int = 8192, basename: str = "f.txt", ext: str = "txt", long_line=None) -> Target:
    if long_line is None:
        long_line = any(len(x) > limit for x in data.split(b"\n"))
    return Target(data=data, basename=basename, ext=ext, has_long_line=long_line, flat=lambda: data.translate(FOLD))


def pol(limit: int = 8192, budget: float = 0.25, blind: bool = False) -> SearchPolicy:
    return SearchPolicy(rule_budget_s=budget, long_line_bytes=limit, excl_nul_blind=blind)


def grep_hit(args, data: bytes) -> bool:
    r = subprocess.run([GREP, *args], input=data, capture_output=True, env=ENV)
    if r.returncode > 1:
        raise AssertionError("grep failed: %r %r" % (args, r.stderr))
    return r.returncode == 0


def grep_excl_hit(pat: str, excl: str, data: bytes, text: bool = True) -> bool:
    """Bash ``grep_check_excl`` after the hardening (-a on both) or, with ``text=False``, before it."""
    first = [GREP, "-ahiE" if text else "-hiE", "-e", pat]
    out = subprocess.run(first, input=data, capture_output=True, env=ENV)
    if out.returncode > 1:
        raise AssertionError("grep failed: %r" % (first,))
    second = [GREP, "-aviE" if text else "-viE", "-e", excl]
    return subprocess.run(second, input=out.stdout, capture_output=True, env=ENV).returncode == 0


def grep_flat_hit(pat: str, data: bytes) -> bool:
    folded = subprocess.run([TR, "\r\n\t", "   "], input=data, capture_output=True, env=ENV).stdout
    return grep_hit(["-qiE", "-e", pat], folded)


def model_long_lines(data: bytes, limit: int):
    """The oracle of the long-line finder: (start, end) of every line longer than ``limit``, one trailing LF not a line start."""
    end = len(data) - 1 if data.endswith(b"\n") else len(data)
    out, pos = [], 0
    for part in data[:end].split(b"\n"):
        if len(part) > limit:
            out.append((pos, pos + len(part)))
        pos += len(part) + 1
    return out


def random_buffer(rnd: random.Random, pieces, max_len: int) -> bytes:
    return b"".join(rnd.choice(pieces) for _ in range(rnd.randint(0, max_len)))


PIECES = [b"a", b"b", b"c", b"ab", b"abc", b"\n", b"\n", b" ", b"x", b"curl ", b"http://", b"ABC", b"\t", b"=", b"-"]


# ------------------------------------------------------------------------------------------------------------------------
class TestMatchValidation(unittest.TestCase):
    def test_defaults_and_value_semantics(self):
        m = Match("abc")
        self.assertEqual((m.mode, m.ci, m.excl, m.binary), ("line", False, None, "text"))
        self.assertEqual(m, Match("abc"))
        self.assertEqual(hash(m), hash(Match("abc")))
        self.assertNotEqual(m, Match("abc", ci=True))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            m.pattern = "x"  # type: ignore[misc]

    def test_constants(self):
        self.assertEqual(rules.MODES, ("line", "flat"))
        self.assertEqual(rules.BINARY_MODES, ("text", "skip"))

    def test_invalid_combinations_raise_at_construction(self):
        bad = [
            dict(mode="bogus"), dict(mode=""), dict(binary="grep"), dict(binary="binary"),
            dict(mode="flat", excl="x"),            # flat with excl
            dict(excl="x", binary="skip"),          # excl with skip
            dict(mode="flat", excl="x", binary="skip"),
        ]
        for kw in bad:
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                Match("abc", **kw)

    def test_wrong_types_raise(self):
        for kw in (dict(pattern=5), dict(pattern=b"abc"), dict(pattern="a", excl=5), dict(pattern="a", ci="yes"),
                   dict(pattern="a", excl=b"x")):
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                Match(**kw)

    def test_valid_combinations(self):
        Match("a", ci=True)
        Match("a", mode="flat")
        Match("a", mode="flat", ci=True)
        Match("a", excl="b")
        Match("a", excl="b", ci=True)
        Match("a", binary="skip")
        Match("a", mode="flat", binary="skip")


class TestConditionValidation(unittest.TestCase):
    def test_members_are_checked(self):
        a, b = Match("a"), Match("b")
        for cls in (AllOf, AnyOf):
            with self.subTest(cls=cls.__name__):
                cls((a, b))
                cls((a,))
                cls((a, cls((b, a))))
                with self.assertRaises(ValueError):
                    cls(())
                with self.assertRaises(ValueError):
                    cls([a, b])              # a list is unhashable and so cannot be a registered condition
                with self.assertRaises(ValueError):
                    cls((a, "b"))
                with self.assertRaises(ValueError):
                    cls("ab")

    def test_not_member(self):
        Not(Match("a"))
        Not(AllOf((Match("a"), Match("b"))))
        for bad in ("a", None, 5, [Match("a")]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Not(bad)  # type: ignore[arg-type]

    def test_conditions_are_hashable_values(self):
        c1 = AllOf((Match("a"), Not(Match("b"))))
        c2 = AllOf((Match("a"), Not(Match("b"))))
        self.assertEqual(c1, c2)
        self.assertEqual(len({c1, c2}), 1)


# ------------------------------------------------------------------------------------------------------------------------
class TestRuleSetConstruction(unittest.TestCase):
    def test_name_rules_and_order(self):
        s1, s2, s3 = spec(Match("aaa")), spec(Match("bbb"), outcome="warn"), spec(Match("ccc"))
        rs = RuleSet("wp04t-order", [s1, s2, s3])
        self.assertEqual(rs.name, "wp04t-order")
        self.assertEqual(rs.rules, (s1, s2, s3))
        self.assertIsInstance(rs.rules, tuple)

    def test_registers_every_leaf_with_rx(self):
        a, b, c, d = Match("la1"), Match("lb2", ci=True), Match("lc3", excl="lx"), Match("ld4", mode="flat")
        single = spec(a)
        comp = spec(AllOf((b, Not(c), AnyOf((d, Match("le5"))))))
        RuleSet("wp04t-reg", [single, comp])
        by_id = {r.id: r for r in rx.registered()}
        self.assertEqual((by_id[single.id].mode, by_id[single.id].pattern), ("line", "la1"))
        base = comp.id
        self.assertEqual((by_id[base + "#1"].mode, by_id[base + "#1"].pattern), ("line_i", "lb2"))
        self.assertEqual((by_id[base + "#2"].mode, by_id[base + "#2"].pattern, by_id[base + "#2"].excl), ("excl", "lc3", "lx"))
        self.assertEqual((by_id[base + "#3"].mode, by_id[base + "#3"].pattern), ("flat", "ld4"))
        self.assertEqual((by_id[base + "#4"].mode, by_id[base + "#4"].pattern), ("line", "le5"))
        self.assertNotIn(base, by_id)            # a composite has no plain id of its own
        self.assertNotIn(base + "#5", by_id)

    def test_registered_rules_use_the_translator_compile(self):
        s = spec(Match("lcompile[0-9]+", ci=True))
        RuleSet("wp04t-compile", [s])
        rule = [r for r in rx.registered() if r.id == s.id][0]
        self.assertIs(rule.compiled, rx.ere_to_py("lcompile[0-9]+", True))

    def test_every_leaf_is_evaluable_after_construction(self):
        cond = AnyOf((Match("ev1"), AllOf((Match("ev2"), Not(Match("ev3"))))))
        RuleSet("wp04t-eval", [spec(cond)])
        self.assertTrue(evaluate(cond, tgt(b"ev2\n"), pol()))
        self.assertFalse(evaluate(cond, tgt(b"ev2 ev3\n"), pol()))

    def test_duplicate_id_in_one_table(self):
        s = spec(Match("dupa"))
        with self.assertRaises(ValueError):
            RuleSet("wp04t-dup", [s, dataclasses.replace(s, cond=Match("dupb"))])
        with self.assertRaises(ValueError):
            RuleSet("wp04t-dup2", [s, s])

    def test_duplicate_id_across_tables(self):
        s = spec(Match("xdupa"))
        RuleSet("wp04t-first", [s])
        with self.assertRaises(ValueError):
            RuleSet("wp04t-second", [dataclasses.replace(s, cond=Match("xdupb"))])
        with self.assertRaises(ValueError):
            RuleSet("wp04t-third", [s])          # same row, other table: still the same id twice

    def test_same_table_built_again_is_idempotent(self):
        s = spec(Match("idem1"))
        RuleSet("wp04t-idem", [s])
        RuleSet("wp04t-idem", [s])               # a reloaded module builds its table again

    def test_invalid_fields(self):
        ok = Match("fld")
        base = dict(id=rid(), outcome="fail", message="CWE-0:x", cond=ok)
        bad = [
            dict(outcome="FAIL"), dict(outcome="pass"), dict(outcome=""), dict(id=""), dict(id="a#1"), dict(id=5),
            dict(message=""), dict(message=5), dict(cond="abc"), dict(cond=None), dict(severity="high"),
            dict(severity="BLOCKER"), dict(severity=3), dict(applies_to="pom.xml"), dict(source=5),
            dict(applies_to=AppliesTo(basenames=())), dict(applies_to=AppliesTo(exts=())),
            dict(applies_to=AppliesTo(exts=("PY",))), dict(applies_to=AppliesTo(exts=(".py",))),
            dict(applies_to=AppliesTo(exts=("",))), dict(applies_to=AppliesTo(basenames=("",))),
            dict(applies_to=AppliesTo(basenames="pom.xml")),
        ]
        for kw in bad:
            with self.subTest(kw=kw):
                row = dict(base)
                row.update(kw)
                if "id" not in kw:
                    row["id"] = rid()
                with self.assertRaises(ValueError):
                    RuleSet("wp04t-bad", [RuleSpec(**row)])

    def test_rows_must_be_rule_specs(self):
        for rows in (["abc"], [None], [Match("a")]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                RuleSet("wp04t-rows", rows)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            RuleSet("", [])
        RuleSet("wp04t-empty-%d" % next(_COUNTER), [])

    def test_valid_severities_follow_findings(self):
        self.assertEqual(set(rules._SEVERITIES), set(findings.SEVERITY_NUMBER))
        for sev in findings.SEVERITY_NUMBER:
            with self.subTest(sev=sev):
                RuleSet("wp04t-sev-%s" % sev, [spec(Match("sev"), severity=sev)])
        RuleSet("wp04t-sev-none", [spec(Match("sev"), severity=None)])

    def test_applies_to_forms_accepted(self):
        RuleSet("wp04t-applies", [
            spec(Match("ap1"), applies_to=AppliesTo(basenames=("pom.xml", "*.pom"))),
            spec(Match("ap2"), applies_to=AppliesTo(exts=("xml", "pom"))),
            spec(Match("ap3"), applies_to=AppliesTo(basenames=("Makefile*",), exts=("mk",))),
            spec(Match("ap4"), applies_to=AppliesTo()),
        ])

    def test_invalid_pattern_is_an_exception_at_construction(self):
        for pat in ("(", "a{2,1}", "[a", "a{65536}"):
            with self.subTest(pat=pat), self.assertRaises(rx.EREError):
                RuleSet("wp04t-ere", [spec(Match(pat))])
        with self.assertRaises(rx.EREError):
            RuleSet("wp04t-ere2", [spec(Match("fine", excl="("))])
        with self.assertRaises(rx.EREError):
            RuleSet("wp04t-ere3", [spec(AllOf((Match("fine"), Not(Match("("))))) ])

    def test_failed_construction_registers_nothing(self):
        good, bad = spec(Match("atom_good")), spec(AllOf((Match("atom_ok"), Match("("))))
        with self.assertRaises(rx.EREError):
            RuleSet("wp04t-atomic", [good, bad])
        known = {r.id for r in rx.registered()}
        self.assertNotIn(good.id, known)
        self.assertNotIn(bad.id + "#1", known)
        with self.assertRaises(ValueError):
            evaluate(good.cond, tgt(b"atom_good\n"), pol())     # not evaluable, nothing leaked
        RuleSet("wp04t-atomic-again", [good])                    # and its id is still free
        self.assertTrue(evaluate(good.cond, tgt(b"atom_good\n"), pol()))

    def test_id_clash_with_rx_registry_content(self):
        s = spec(Match("clash_a"))
        rx.rule(s.id, "something else", mode="line")
        with self.assertRaises(ValueError):
            RuleSet("wp04t-clash", [s])
        self.assertNotIn(s.id, [r.id for r in rx.registered() if r.pattern == "clash_a"])


class TestMatcherConstruction(unittest.TestCase):
    def test_registers_and_exposes(self):
        mid = rid("matcher")
        m = Match("mc_one", ci=True)
        mt = Matcher(mid, m)
        self.assertEqual((mt.id, mt.match), (mid, m))
        rule = {r.id: r for r in rx.registered()}[mid]
        self.assertEqual((rule.mode, rule.pattern), ("line_i", "mc_one"))
        self.assertTrue(mt.search(tgt(b"xx MC_ONE\n"), pol()))
        self.assertFalse(mt.search(tgt(b"xx\n"), pol()))

    def test_excl_and_flat_labels(self):
        a, b = Matcher(rid("m"), Match("mc_two", excl="mc_x")), Matcher(rid("m"), Match("mc_three", mode="flat"))
        by_id = {r.id: r for r in rx.registered()}
        self.assertEqual((by_id[a.id].mode, by_id[a.id].excl), ("excl", "mc_x"))
        self.assertEqual(by_id[b.id].mode, "flat")

    def test_duplicate_id_same_content_is_idempotent_other_content_raises(self):
        mid = rid("m")
        Matcher(mid, Match("mc_dup"))
        Matcher(mid, Match("mc_dup"))
        with self.assertRaises(ValueError):
            Matcher(mid, Match("mc_dup2"))
        with self.assertRaises(ValueError):
            Matcher(mid, Match("mc_dup", ci=True))

    def test_id_shared_with_a_rule_row_raises(self):
        s = spec(Match("mc_row"))
        RuleSet("wp04t-mrow", [s])
        with self.assertRaises(ValueError):
            Matcher(s.id, Match("mc_row"))
        mid = rid("m")
        Matcher(mid, Match("mc_row2"))
        with self.assertRaises(ValueError):
            RuleSet("wp04t-mrow2", [dataclasses.replace(spec(Match("mc_row2")), id=mid)])

    def test_bad_arguments(self):
        for args in (("", Match("a")), ("a#1", Match("a")), (5, Match("a")), (rid(), "a"), (rid(), None)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                Matcher(*args)  # type: ignore[arg-type]
        with self.assertRaises(rx.EREError):
            Matcher(rid(), Match("("))

    def test_matcher_leaves_a_failed_construction_unregistered(self):
        mid = rid("m")
        with self.assertRaises(rx.EREError):
            Matcher(mid, Match("[a"))
        self.assertNotIn(mid, [r.id for r in rx.registered()])
        Matcher(mid, Match("fine"))


# ------------------------------------------------------------------------------------------------------------------------
@unittest.skipUnless(GREP and TR, "needs grep and tr")
class TestModesAgainstGrep(unittest.TestCase):
    """Each mode against the real grep on curated and random buffers."""

    PATTERNS = [
        r"curl[^|]*http://", "abc", "^abc", "abc$", "a.c", r"\bhttp", r"pass(word)?[[:space:]]*=", "x+", "^$", "[[:space:]]$",
        "(abc|xyz)[0-9]", r"\<key\>", "foo|bar", "a{2,3}b", "[^a-z]ABC", r"c\w*p", "", "=$", "^[[:space:]]*-",
    ]
    EXCLS = ["http://", "ABC", "^[[:space:]]*-", "x", "[0-9]"]
    PIECES = PIECES + [b"password", b" = ", b"key", b"foo", b"bar", b"aab", b"1", b"|", b"xyz", b"ABCd"]

    @classmethod
    def setUpClass(cls):
        cls.line = {p: reg(Match(p)) for p in cls.PATTERNS}
        cls.line_i = {p: reg(Match(p, ci=True)) for p in cls.PATTERNS}
        cls.flat = {p: reg(Match(p, mode="flat")) for p in cls.PATTERNS}
        cls.excl = {(p, x): reg(Match(p, excl=x)) for p in cls.PATTERNS[:8] for x in cls.EXCLS}
        rnd = random.Random(20261113)
        cls.buffers = [b"", b"\n", b"abc", b"abc\n", b"\n\n", b"ABC", b"curl x | http://y\n", b"password = 1\n", b"key\n",
                       b"  - item\n", b"line\r\n", b"a\tb\n"]
        cls.buffers += [random_buffer(rnd, cls.PIECES, 40) for _ in range(60)]

    def test_line(self):
        for p, m in self.line.items():
            for data in self.buffers:
                with self.subTest(pattern=p, data=data):
                    self.assertEqual(evaluate(m, tgt(data), pol()), grep_hit(["-qE", "-e", p], data))

    def test_line_ci(self):
        for p, m in self.line_i.items():
            for data in self.buffers:
                with self.subTest(pattern=p, data=data):
                    self.assertEqual(evaluate(m, tgt(data), pol()), grep_hit(["-qiE", "-e", p], data))

    def test_flat(self):
        for p, m in self.flat.items():
            for data in self.buffers:
                with self.subTest(pattern=p, data=data):
                    self.assertEqual(evaluate(m, tgt(data), pol()), grep_flat_hit(p, data))

    def test_flat_sees_across_a_line_break_and_ignores_case(self):
        m = reg(Match(r"<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+[\"']file:", mode="flat"))
        payload = b'<!ENTITY\n  xxe\tSYSTEM\r\n  "file:///etc/passwd">'
        self.assertTrue(evaluate(m, tgt(payload), pol()))
        self.assertTrue(evaluate(m, tgt(payload.lower()), pol()))
        self.assertFalse(evaluate(m, tgt(b"<!ENTITY x SYSTEM 'http://x'>"), pol()))
        # the same pattern as a line rule cannot see across the break
        line = reg(Match(r"<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+[\"']file:"))
        self.assertFalse(evaluate(line, tgt(payload), pol()))

    def test_excl(self):
        for (p, x), m in self.excl.items():
            for data in self.buffers:
                with self.subTest(pattern=p, excl=x, data=data):
                    self.assertEqual(evaluate(m, tgt(data), pol()), grep_excl_hit(p, x, data))

    def test_ci_is_forced_for_excl_and_flat(self):
        self.assertTrue(evaluate(reg(Match("secret", excl="zzz")), tgt(b"SECRET\n"), pol()))
        self.assertTrue(evaluate(reg(Match("secret", mode="flat")), tgt(b"SECRET\n"), pol()))
        self.assertFalse(evaluate(reg(Match("secret")), tgt(b"SECRET\n"), pol()))
        self.assertFalse(evaluate(reg(Match("secret", excl="zzz")), tgt(b"SECRET zzz\n"), pol()))
        self.assertFalse(evaluate(reg(Match("secret", excl="ZZZ")), tgt(b"SECRET zzz\n"), pol()))


@unittest.skipUnless(GREP and TR, "needs grep and tr")
class TestBinaryModes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = reg(Match("needle", binary="text"))
        cls.skip = reg(Match("needle", binary="skip"))
        cls.excl = reg(Match("needle", excl="zzz"))
        cls.flat = reg(Match("needle", mode="flat"))
        cls.flat_skip = reg(Match("needle", mode="flat", binary="skip"))

    def test_text_is_grep_a(self):
        for data in (b"needle\0x\n", b"\0needle\n", b"a\0b\nneedle\n", b"nee\0dle\n", b"needle\n\0", b"\0\0\0\n"):
            with self.subTest(data=data):
                self.assertEqual(evaluate(self.text, tgt(data), pol()), grep_hit(["-qaE", "-e", "needle"], data))

    def test_skip_is_grep_capital_i(self):
        for data in (b"needle\0x\n", b"\0needle\n", b"a\0b\nneedle\n", b"needle\n", b"needle\n\0", b"x\0"):
            with self.subTest(data=data):
                self.assertEqual(evaluate(self.skip, tgt(data), pol()), grep_hit(["-qIE", "-e", "needle"], data))

    def test_skip_looks_only_at_the_first_32_kib(self):
        for pos in (100, 32767, 32768, 40000):
            data = b"needle\n" + b"a" * pos + b"\0\n"
            with self.subTest(pos=pos):
                self.assertEqual(evaluate(self.skip, tgt(data), pol()), rx.search_lines(rx.ere_to_py("needle"), data, binary="skip"))
        near = b"needle\n" + b"a" * 100 + b"\0\n"
        far = b"needle\n" + b"a" * 500_000 + b"\0\n"
        self.assertFalse(evaluate(self.skip, tgt(near), pol()))
        self.assertTrue(evaluate(self.skip, tgt(far), pol()))
        self.assertTrue(evaluate(self.text, tgt(near), pol()))
        with tempfile.TemporaryDirectory() as d:        # the real grep reads a file the same way, far from the boundary
            for name, data in (("near", near), ("far", far)):
                p = Path(d, name)
                p.write_bytes(data)
                rc = subprocess.run([GREP, "-qIE", "-e", "needle", str(p)], env=ENV).returncode
                self.assertEqual(evaluate(self.skip, tgt(data), pol()), rc == 0, name)
        # NOTE: the boundary itself is rx's (32 KiB, design section 9.2); GNU grep 3.11 decides from its first 96 KiB buffer.

    def test_skip_with_the_long_line_routes(self):
        for limit in (8, 8192):
            near = b"needle\n" + b"a" * 100 + b"\0" + b"b" * 300 + b"\n"
            far = b"needle\n" + b"a" * 40000 + b"\0" + b"b" * 300 + b"\n"
            with self.subTest(limit=limit):
                self.assertFalse(evaluate(self.skip, tgt(near, limit, long_line=True), pol(limit)))
                self.assertTrue(evaluate(self.skip, tgt(far, limit, long_line=True), pol(limit)))
                self.assertTrue(evaluate(self.text, tgt(near, limit, long_line=True), pol(limit)))

    def test_flat_honours_skip_and_text(self):
        data = b"xx\0 needle\n"
        self.assertTrue(evaluate(self.flat, tgt(data), pol()))
        self.assertFalse(evaluate(self.flat_skip, tgt(data), pol()))
        self.assertTrue(evaluate(self.flat_skip, tgt(b"xx needle\n"), pol()))

    def test_excl_blind_follows_the_policy(self):
        data = b"needle\0\nneedle yyy\n"
        self.assertFalse(evaluate(self.excl, tgt(data), pol(blind=True)))
        self.assertTrue(evaluate(self.excl, tgt(data), pol(blind=False)))
        self.assertEqual(evaluate(self.excl, tgt(data), pol(blind=False)), grep_excl_hit("needle", "zzz", data, text=True))
        self.assertEqual(evaluate(self.excl, tgt(data), pol(blind=True)), grep_excl_hit("needle", "zzz", data, text=False))
        # a file without a NUL byte is the same under both settings
        clean = b"needle\n"
        self.assertTrue(evaluate(self.excl, tgt(clean), pol(blind=True)))
        self.assertTrue(evaluate(self.excl, tgt(clean), pol(blind=False)))

    def test_excl_blind_with_the_long_line_routes(self):
        data = b"needle\n" + b"a" * 300 + b"\0" + b"needle zzz\n" + b"b" * 300 + b"\n"
        self.assertFalse(evaluate(self.excl, tgt(data, 16, long_line=True), pol(16, blind=True)))
        self.assertTrue(evaluate(self.excl, tgt(data, 16, long_line=True), pol(16, blind=False)))


# ------------------------------------------------------------------------------------------------------------------------
class TestComposites(unittest.TestCase):
    TLS = AllOf((Match(r"tls\.Config\s*\{"), Not(Match("MinVersion"))))

    @classmethod
    def setUpClass(cls):
        reg(cls.TLS)

    def test_scan_go_tls_case(self):
        t = lambda d: evaluate(self.TLS, tgt(d), pol())  # noqa: E731
        self.assertTrue(t(b"cfg := &tls.Config{\n\tInsecureSkipVerify: false,\n}\n"))
        self.assertTrue(t(b"x := tls.Config {}\n"))
        self.assertFalse(t(b"cfg := &tls.Config{\n\tMinVersion: tls.VersionTLS12,\n}\n"))
        self.assertFalse(t(b"cfg := &tls.Config{}\n// MinVersion somewhere else in the file\n"))   # a whole-file negation
        self.assertFalse(t(b"nothing to see\n"))
        self.assertFalse(t(b""))

    def test_not_is_evaluated_over_the_whole_file(self):
        n = reg(Not(Match("alpha")))
        self.assertTrue(evaluate(n, tgt(b"beta\ngamma\n"), pol()))
        self.assertFalse(evaluate(n, tgt(b"beta\nalpha\n"), pol()))
        self.assertTrue(evaluate(n, tgt(b""), pol()))
        self.assertFalse(evaluate(reg(Not(Not(Match("alpha")))), tgt(b"beta\n"), pol()))

    def test_all_of_is_a_whole_file_conjunction(self):
        c = reg(AllOf((Match("fetch", ci=True), Match("execute", ci=True))))
        self.assertTrue(evaluate(c, tgt(b"FETCH the thing\n\n\nthen Execute it\n"), pol()))
        self.assertFalse(evaluate(c, tgt(b"fetch only\n"), pol()))
        self.assertFalse(evaluate(c, tgt(b"execute only\n"), pol()))

    def test_any_of(self):
        c = reg(AnyOf((Match("one"), Match("two"), Match("three"))))
        for data, want in ((b"xx one\n", True), (b"two\n", True), (b"three", True), (b"four\n", False), (b"", False)):
            with self.subTest(data=data):
                self.assertEqual(evaluate(c, tgt(data), pol()), want)

    def test_nested(self):
        c = reg(AnyOf((AllOf((Match("p1"), Not(Match("p2")))), AllOf((Match("q1"), Match("q2"))))))
        for data, want in ((b"p1\n", True), (b"p1 p2\n", False), (b"q1\nq2\n", True), (b"q1\n", False), (b"p1 p2\nq1 q2\n", True)):
            with self.subTest(data=data):
                self.assertEqual(evaluate(c, tgt(data), pol()), want)

    def test_short_circuit(self):
        a, b = reg(Match("sc_a")), reg(Match("sc_b"))
        with mock.patch.object(rx, "search_lines", wraps=rx.search_lines) as spy:
            self.assertFalse(evaluate(AllOf((a, b)), tgt(b"zzz\n"), pol()))
            self.assertEqual(spy.call_count, 1)
            spy.reset_mock()
            self.assertTrue(evaluate(AnyOf((a, b)), tgt(b"sc_a\n"), pol()))
            self.assertEqual(spy.call_count, 1)
            spy.reset_mock()
            self.assertTrue(evaluate(AllOf((a, b)), tgt(b"sc_a sc_b\n"), pol()))
            self.assertEqual(spy.call_count, 2)

    def test_unregistered_match_raises(self):
        loose = Match("never_registered_anywhere_xyz")
        with self.assertRaises(ValueError):
            evaluate(loose, tgt(b"never_registered_anywhere_xyz\n"), pol())
        with self.assertRaises(ValueError):
            evaluate(Match("never_registered_anywhere_xyz", ci=True), tgt(b"x\n"), pol())
        with self.assertRaises(ValueError):
            evaluate(Match("never_registered_anywhere_xyz", mode="flat"), tgt(b"x\n"), pol())

    def test_unregistered_match_raises_inside_a_composite_even_when_short_circuited(self):
        known = reg(Match("known_one"))
        loose = Match("never_registered_either_xyz")
        for cond in (AllOf((known, loose)), AllOf((loose, known)), AnyOf((known, loose)), Not(loose), AnyOf((known, Not(loose)))):
            with self.subTest(cond=cond), self.assertRaises(ValueError):
                evaluate(cond, tgt(b"known_one\n"), pol())
        with self.assertRaises(ValueError):
            evaluate("not a condition", tgt(b"x\n"), pol())  # type: ignore[arg-type]

    def test_registration_is_by_value(self):
        reg(Match("by_value_pat"))
        self.assertTrue(evaluate(Match("by_value_pat"), tgt(b"by_value_pat\n"), pol()))     # an equal Match is the same rule
        with self.assertRaises(ValueError):
            evaluate(Match("by_value_pat", ci=True), tgt(b"by_value_pat\n"), pol())         # a different one is not

    def test_unregistered_matcher_pattern_registered_via_matcher_is_evaluable(self):
        m = Match("via_matcher_only")
        Matcher(rid("m"), m)
        self.assertTrue(evaluate(m, tgt(b"via_matcher_only\n"), pol()))


# ------------------------------------------------------------------------------------------------------------------------
class TestRunRuleset(unittest.TestCase):
    def test_hits_in_table_order_and_outcome_does_not_matter(self):
        rows = [spec(Match("rr_a")), spec(Match("rr_b"), outcome="warn"), spec(Match("rr_c")), spec(Match("rr_d"), outcome="warn")]
        rs = RuleSet("wp04t-run", rows)
        run = run_ruleset(rs, tgt(b"rr_d rr_a rr_b\n"), pol())
        self.assertIsInstance(run, RuleRun)
        self.assertEqual(run.hits, (rows[0], rows[1], rows[3]))
        self.assertEqual((run.skipped, run.timed_out), ((), ()))
        self.assertEqual(run_ruleset(rs, tgt(b"nothing\n"), pol()), RuleRun(hits=(), skipped=(), timed_out=()))
        self.assertEqual(run_ruleset(rs, tgt(b""), pol()).hits, ())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            run.hits = ()  # type: ignore[misc]

    def test_composite_rows(self):
        both = spec(AllOf((Match("rc_a"), Match("rc_b"))))
        neg = spec(AllOf((Match("rc_a"), Not(Match("rc_b")))))
        rs = RuleSet("wp04t-runc", [both, neg])
        self.assertEqual(run_ruleset(rs, tgt(b"rc_a\n"), pol()).hits, (neg,))
        self.assertEqual(run_ruleset(rs, tgt(b"rc_a rc_b\n"), pol()).hits, (both,))

    def test_applies_to(self):
        pom = spec(Match("ap_x"), applies_to=AppliesTo(basenames=("pom.xml", "*.pom")))
        xml = spec(Match("ap_x"), applies_to=AppliesTo(exts=("xml",)))
        both = spec(Match("ap_x"), applies_to=AppliesTo(basenames=("pom*.xml",), exts=("xml",)))
        mk = spec(Match("ap_x"), applies_to=AppliesTo(basenames=("Makefile*", "GNUmakefile*")))
        anyfile = spec(Match("ap_x"))
        rs = RuleSet("wp04t-applies-run", [pom, xml, both, mk, anyfile])
        data = b"ap_x\n"
        cases = [
            (("pom.xml", "xml"), [pom, xml, both, anyfile]),
            (("lib.pom", "pom"), [pom, anyfile]),
            (("other.xml", "xml"), [xml, anyfile]),
            (("pom-parent.xml", "xml"), [xml, both, anyfile]),
            (("Makefile.am", "am"), [mk, anyfile]),
            (("makefile", "makefile"), [anyfile]),          # glob matching is case sensitive
            (("POM.XML", "xml"), [xml, anyfile]),
            (("a.txt", "txt"), [anyfile]),
        ]
        for (base, ext), want in cases:
            with self.subTest(basename=base, ext=ext):
                self.assertEqual(run_ruleset(rs, tgt(data, basename=base, ext=ext), pol()).hits, tuple(want))

    def test_a_rule_that_does_not_apply_is_not_evaluated(self):
        only_pom = spec(Match("na_x"), applies_to=AppliesTo(basenames=("pom.xml",)))
        rs = RuleSet("wp04t-na", [only_pom])
        with mock.patch.object(rx, "search_lines", wraps=rx.search_lines) as spy:
            self.assertEqual(run_ruleset(rs, tgt(b"na_x\n", basename="a.txt"), pol()).hits, ())
            self.assertEqual(spy.call_count, 0)

    # -- the deadline (9.3) --------------------------------------------------------------------------------------------
    def test_deadline_in_the_past_skips_everything_that_applies(self):
        rows = [spec(Match("dl_a")), spec(Match("dl_b")), spec(Match("dl_c"), applies_to=AppliesTo(exts=("zzz",))), spec(Match("dl_d"))]
        rs = RuleSet("wp04t-deadline", rows)
        run = run_ruleset(rs, tgt(b"dl_a dl_b dl_d\n"), pol(), deadline=time.monotonic() - 1.0)
        self.assertEqual(run.hits, ())
        self.assertEqual(run.skipped, (rows[0].id, rows[1].id, rows[3].id))      # the one that never applied is not "skipped"
        self.assertEqual(run.timed_out, ())

    def test_no_deadline_and_a_far_deadline_skip_nothing(self):
        rows = [spec(Match("fd_a")), spec(Match("fd_b"))]
        rs = RuleSet("wp04t-fardeadline", rows)
        for deadline in (None, time.monotonic() + 3600):
            run = run_ruleset(rs, tgt(b"fd_a fd_b\n"), pol(), deadline=deadline)
            self.assertEqual((run.hits, run.skipped), (tuple(rows), ()))

    def test_deadline_is_checked_between_rules_and_never_inside_one(self):
        slow_pat = r"curl[^|]*http://"
        first = spec(Match(slow_pat))
        rest = [spec(Match("bd_a")), spec(Match("bd_b"))]
        rs = RuleSet("wp04t-between", [first] + rest)
        data = (b"curl x " * 450000)[:3_000_000]            # one 3 MB line: the linear matcher needs ~0.1 s for the first rule
        deadline = time.monotonic() + 0.02
        t0 = time.monotonic()
        run = run_ruleset(rs, tgt(data), pol(), deadline=deadline)
        self.assertGreater(time.monotonic() - t0, 0.02, "the first rule must have outlasted the deadline for this test to mean anything")
        self.assertEqual(run.hits, ())                       # the first rule ran to the end (no match), it was not cut
        self.assertEqual(run.skipped, (rest[0].id, rest[1].id))

    def test_skipped_ids_are_a_suffix_of_the_applicable_rules(self):
        rows = [spec(Match("sf_%d" % i)) for i in range(6)]
        rs = RuleSet("wp04t-suffix", rows)
        ticks = itertools.count()
        # a clock that advances once per call: the deadline passes after the third rule starts
        with mock.patch.object(rules.time, "monotonic", side_effect=lambda: float(next(ticks))):
            run = run_ruleset(rs, tgt(b"sf_0 sf_1 sf_2 sf_3 sf_4 sf_5\n"), pol(), deadline=2.5)
        ran = [r.id for r in run.hits]
        self.assertEqual(ran + list(run.skipped), [r.id for r in rows])
        self.assertTrue(0 < len(ran) < 6)

    # -- a pattern with no linear matcher ------------------------------------------------------------------------------
    BACKREF = r"(a+)(a+)(a+)\3\2\1x"

    def test_timed_out_for_a_pattern_without_a_linear_matcher(self):
        self.assertFalse(rx.dfa_available(rx.ere_to_py(self.BACKREF)))
        slow, after = spec(Match(self.BACKREF)), spec(Match("to_after"))
        rs = RuleSet("wp04t-timeout", [slow, after])
        data = b"a" * 3000 + b"\nto_after\n"
        t0 = time.monotonic()
        run = run_ruleset(rs, tgt(data), pol(budget=0.05), deadline=None)
        self.assertLess(time.monotonic() - t0, 3.0)
        self.assertEqual(run.timed_out, (slow.id,))
        self.assertEqual(run.hits, (after,))               # the next rule still ran
        self.assertEqual(run.skipped, ())
        with self.assertRaises(rx.RegexTimeout):
            evaluate(slow.cond, tgt(data), pol(budget=0.05))
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0.0)

    def test_a_timeout_inside_a_composite_times_the_row_out(self):
        row = spec(AnyOf((Match(self.BACKREF), Match("to_never"))))
        rs = RuleSet("wp04t-timeout2", [row])
        self.assertEqual(run_ruleset(rs, tgt(b"a" * 3000 + b"\n"), pol(budget=0.05)).timed_out, (row.id,))

    # -- threads ---------------------------------------------------------------------------------------------------------
    def test_off_the_main_thread_raises_runtime_error(self):
        m = Match("th_x")
        rs = RuleSet("wp04t-thread", [spec(m)])
        mt = Matcher(rid("m"), m)
        t = tgt(b"th_x\n")
        calls = {
            "evaluate": lambda: evaluate(m, t, pol()),
            "run_ruleset": lambda: run_ruleset(rs, t, pol()),
            "search": lambda: mt.search(t, pol()),
            "spans": lambda: list(mt.spans(t, pol())),
        }
        for name, fn in calls.items():
            box = []

            def work(fn=fn, box=box):
                try:
                    fn()
                except BaseException as exc:  # noqa: BLE001
                    box.append(exc)

            th = threading.Thread(target=work)
            th.start()
            th.join(10)
            with self.subTest(call=name):
                self.assertEqual(len(box), 1)
                self.assertIsInstance(box[0], RuntimeError)
        calls["evaluate"]()            # and the main thread is fine


# ------------------------------------------------------------------------------------------------------------------------
class TestSearchPolicy(unittest.TestCase):
    """Design 9.2: the matcher is chosen per buffer; the answer never depends on the choice."""

    def test_short_lines_use_re_with_the_rule_budget(self):
        m = reg(Match("sp_x"))
        with mock.patch.object(rx, "search_lines", wraps=rx.search_lines) as sl, mock.patch.object(rx, "dfa_search", wraps=rx.dfa_search) as ds:
            self.assertTrue(evaluate(m, tgt(b"ok\nsp_x\n"), pol(budget=0.125)))
        self.assertEqual(ds.call_count, 0)
        self.assertEqual(sl.call_count, 1)
        self.assertEqual(sl.call_args.kwargs["budget"], 0.125)

    def test_a_long_line_never_meets_re(self):
        m = reg(Match(r"curl[^|]*http://"))
        data = b"short\n" + b"curl x " * 3000 + b"\n"
        with mock.patch.object(rx, "search_lines", wraps=rx.search_lines) as sl, mock.patch.object(rx, "dfa_search", wraps=rx.dfa_search) as ds:
            self.assertFalse(evaluate(m, tgt(data), pol()))
        self.assertEqual(sl.call_count, 0)
        self.assertGreaterEqual(ds.call_count, 1)

    def test_the_flag_on_the_target_decides_not_a_recount(self):
        m = reg(Match("flag_x"))
        data = b"flag_x\n"
        with mock.patch.object(rx, "dfa_search", wraps=rx.dfa_search) as ds:
            evaluate(m, tgt(data, long_line=True), pol())
            self.assertEqual(ds.call_count, 1)
            ds.reset_mock()
            evaluate(m, tgt(data, long_line=False), pol())
            self.assertEqual(ds.call_count, 0)

    def test_long_line_without_a_linear_matcher_falls_back_to_re_with_budget(self):
        bm = reg(Match(TestRunRuleset.BACKREF))
        data = b"a" * 5000 + b"\n"
        with mock.patch.object(rx, "search_lines", wraps=rx.search_lines) as sl:
            with self.assertRaises(rx.RegexTimeout):
                evaluate(bm, tgt(data, long_line=True), pol(budget=0.05))
        self.assertEqual(sl.call_args.kwargs["budget"], 0.05)

    def test_flat_uses_the_linear_matcher_above_the_line_limit_and_re_below(self):
        m = reg(Match("ft_x", mode="flat"))
        small, big = b"ft_x\n", b"a\n" * 6000 + b"ft_x\n"
        with mock.patch.object(rx, "search_lines", wraps=rx.search_lines) as sl, mock.patch.object(rx, "dfa_search", wraps=rx.dfa_search) as ds:
            self.assertTrue(evaluate(m, tgt(small), pol()))
            self.assertEqual((sl.call_count, ds.call_count), (1, 0))
            sl.reset_mock()
            self.assertTrue(evaluate(m, tgt(big), pol()))
            self.assertEqual((sl.call_count, ds.call_count), (0, 1))

    def test_flat_has_no_size_cap(self):
        m = reg(Match(r"<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+[\"'](file:|/)", mode="flat"))
        pad = b"<!-- padding -->\n" * 350_000                   # ~6 MB, past the 5 MiB cap of the old helper
        hostile = b'<!ENTITY\n xxe SYSTEM "file:///etc/passwd">\n'
        self.assertGreater(len(pad), 5_242_880)
        t0 = time.monotonic()
        self.assertTrue(evaluate(m, tgt(pad + hostile), pol()))
        self.assertFalse(evaluate(m, tgt(pad + b"<root/>\n"), pol()))
        self.assertTrue(evaluate(m, tgt(hostile + pad), pol()))
        self.assertLess(time.monotonic() - t0, 30)

    def test_excl_routing(self):
        m = reg(Match("ex_a", excl="ex_b"))
        with mock.patch.object(rx, "search_excl", wraps=rx.search_excl) as se:
            self.assertTrue(evaluate(m, tgt(b"ex_a\n"), pol(blind=True)))
            self.assertEqual(se.call_args.kwargs["binary"], "grep")
            self.assertEqual(se.call_args.kwargs["budget"], 0.25)
            self.assertTrue(evaluate(m, tgt(b"ex_a\n"), pol(blind=False)))
            self.assertEqual(se.call_args.kwargs["binary"], "text")
        big = b"ok\n" * 300 + b"y" * 500 + b"\n" + b"ok\n" * 300 + b"ex_a\n"        # a long line among short ones: routed
        with mock.patch.object(rx, "search_excl", wraps=rx.search_excl) as se, \
                mock.patch.object(rx, "dfa_matching_lines", wraps=rx.dfa_matching_lines) as dl:
            self.assertTrue(evaluate(m, tgt(big, 100, long_line=True), pol(100)))
            self.assertTrue(all(c.kwargs["binary"] == "text" for c in se.call_args_list))   # blind = False here
            self.assertGreaterEqual(dl.call_count, 1)                                   # the long line was not left to re
            self.assertGreaterEqual(se.call_count, 1)                                   # the short runs went to re

    # -- the routed answer equals the whole-buffer linear answer ------------------------------------------------------------
    LINE_PATTERNS = ["a+b", "^ab", "ba$", "a.c", r"\bab\b", "x*", "^$", "b[^a]*c", "(ab|ba)c", "^$|zz", "abc.*abc", r"curl[^|]*http://", "[[:space:]]$"]
    EXCL_PAIRS = [("a+", "ab"), ("^b", "c"), ("x*", "a"), ("^$", "z"), ("c", "^c"), ("abc", "ABC"), ("[ab]+$", "ba"), ("b", ""),
                  ("^$", "^$"), ("x*", "y*"), ("a*", "^$"), ("^$", "c")]      # the last four: an exclusion that matches an empty line

    def test_routing_equals_the_whole_buffer_linear_answer_for_line_rules(self):
        rnd = random.Random(7)
        matches = {p: reg(Match(p)) for p in self.LINE_PATTERNS}
        matches_i = {p: reg(Match(p, ci=True)) for p in self.LINE_PATTERNS}
        n = 0
        for _ in range(500):
            limit = rnd.choice((1, 2, 3, 5, 8, 13))
            data = random_buffer(rnd, PIECES, 300)
            for p in rnd.sample(self.LINE_PATTERNS, 4):
                for m, ci in ((matches[p], False), (matches_i[p], True)):
                    c = rx.ere_to_py(p, ci)
                    want = rx.dfa_search(c, data) if data else False
                    self.assertEqual(want, rx.search_lines(c, data), (p, data))     # the two oracles agree with each other
                    got = evaluate(m, tgt(data, limit, long_line=True), pol(limit))
                    self.assertEqual(got, want, (p, ci, limit, data))
                    n += 1
        self.assertGreater(n, 3000)

    def test_routing_equals_the_whole_buffer_answer_for_excl_rules(self):
        rnd = random.Random(8)
        matches = {pair: reg(Match(pair[0], excl=pair[1])) for pair in self.EXCL_PAIRS}
        for _ in range(400):
            limit = rnd.choice((1, 2, 3, 5, 8, 13))
            data = random_buffer(rnd, PIECES, 300)
            for pair in rnd.sample(self.EXCL_PAIRS, 3):
                want = rx.search_excl(pair[0], pair[1], data, binary="text")
                got = evaluate(matches[pair], tgt(data, limit, long_line=True), pol(limit))
                self.assertEqual(got, want, (pair, limit, data))

    def test_an_exclusion_that_matches_an_empty_line(self):
        """An empty line is a line: the pattern `^$` finds it and the exclusion `^$` excludes it (a slice of b"" has no lines)."""
        both = reg(Match("^$", excl="^$"))
        only = reg(Match("^$", excl="zzz"))
        for data in (b"a\n\nb\n", b"\n", b"a\n\n", b"\n\n", b"a" * 50 + b"\n\n" + b"b" * 50):
            for limit, flag in ((100, True), (3, True), (8192, False)):
                with self.subTest(data=data, limit=limit):
                    self.assertFalse(evaluate(both, tgt(data, limit, long_line=flag), pol(limit)))
                    self.assertTrue(evaluate(only, tgt(data, limit, long_line=flag), pol(limit)))

    def test_routing_when_the_flag_is_false_or_the_buffer_is_small(self):
        m = reg(Match("a+b"))
        rnd = random.Random(9)
        for _ in range(200):
            data = random_buffer(rnd, PIECES, 120)
            want = rx.search_lines(rx.ere_to_py("a+b"), data)
            for flag in (False, True):
                self.assertEqual(evaluate(m, tgt(data, 8192, long_line=flag), pol()), want)

    def test_segments_around_long_lines(self):
        """Hand-built buffers where only one part decides: before, between, after, inside a long line, an empty line."""
        L = 4
        long1, long2 = b"z" * 10, b"y" * 10
        m_has = lambda pat: reg(Match(pat))  # noqa: E731
        cases = [
            (b"hit\n" + long1 + b"\nrest\n", "hit", True),
            (b"hit\n" + long1 + b"\nrest\n", "rest", True),
            (b"\n" + long1 + b"\n", "^$", True),                       # the empty line before the long line
            (long1 + b"\n\n" + long2 + b"\n", "^$", True),             # one empty line between two long lines
            (long1 + b"\n" + long2 + b"\n", "^$", False),              # none
            (long1 + b"\n" + long2, "^$", False),
            (long1 + b"\n\n", "^$", True),                             # the empty line after the last long line
            (long1 + b"\n", "^$", False),                              # a trailing LF is not another line
            (b"ab\n" + long1 + b"\ncd", "cd$", True),
            (b"ab\n" + long1 + b"\ncd", "^zzz", True),
            (b"ab\n" + long1 + b"\ncd", "^zzz$", False),
            (b"ab\n" + long1 + b"\ncd", "^z{10}$", True),
            (b"ab\n" + long1 + b"\ncd", "z{11}", False),
            (b"ab\n" + long1 + b"\ncd", "b.z", False),                 # nothing crosses a line break
            (b"ab" + long1 + b"\n", r"\bz", False),
            (long1, "^z", True),
            (long1, "z$", True),
            (b"x" + long1 + b"\n" + b"x" * 4 + b"\nq", "^x{4}$", True),   # a line of exactly L is short, L + 1 is long
            (b"x" * 5 + b"\n" + b"x" * 4, "^x{5}$", True),
            (b"a\n" * 50 + long1 + b"\n" + b"b\n" * 50, "^b$", True),
            (b"a\n" * 50 + long1 + b"\n" + b"b\n" * 50, "^c$", False),
        ]
        for data, pat, want in cases:
            with self.subTest(data=data, pattern=pat):
                self.assertEqual(evaluate(m_has(pat), tgt(data, L, long_line=True), pol(L)), want)
                self.assertEqual(want, rx.search_lines(rx.ere_to_py(pat), data))     # the expectation is grep's

    def test_long_line_finder_against_a_split_model(self):
        rnd = random.Random(11)
        for _ in range(1500):
            limit = rnd.choice((1, 2, 3, 4, 5, 7, 8, 16))
            data = random_buffer(rnd, PIECES + [b"q" * rnd.randint(1, 40)], 90)
            end = len(data) - 1 if data.endswith(b"\n") else len(data)
            self.assertEqual(list(rules._long_lines(data, end, limit)), model_long_lines(data, limit), (limit, data))

    def test_long_line_finder_on_big_inputs(self):
        limit = 8192
        data = b"ab\n" * 100_000 + b"x" * 30_000 + b"\n" + b"cd\n" * 100_000 + b"y" * 8192 + b"\n" + b"z" * 8193 + b"\n" + b"w" * 9000
        end = len(data)
        self.assertEqual(list(rules._long_lines(data, end, limit)), model_long_lines(data, limit))
        self.assertEqual(len(model_long_lines(data, limit)), 3)

    def test_budget_fallback_still_answers(self):
        """A search that outlasts the budget is finished by the linear matcher (rx does it for whole buffers, the router for segments)."""
        m = reg(Match(r"(a|b)*c[^|]*curl[^|]*http://"))
        data = b"curl x " * 1100 + b"\n"                   # 7.7 KB, short enough for the re path
        want = rx.dfa_search(rx.ere_to_py(r"(a|b)*c[^|]*curl[^|]*http://"), data)
        self.assertEqual(evaluate(m, tgt(data), pol(budget=0.0005)), want)
        big = b"ok\n" * 20000 + b"curl x " * 12000 + b"\n" + b"ok\n" * 20000
        m2 = reg(Match(r"curl[^|]*http://"))
        self.assertFalse(evaluate(m2, tgt(big, 8192), pol(8192, budget=0.0005)))
        self.assertTrue(evaluate(m2, tgt(big + b"curl http://x\n", 8192), pol(8192, budget=0.0005)))

    SHORT = (b"curl x " * 1170)[:8190] + b"\n"            # a line under the 8 KiB limit that is quadratic for `curl[^|]*http://`

    def test_a_timeout_inside_a_routed_run_is_finished_by_the_linear_matcher(self):
        """The runs between the long lines are searched by re; when re runs out of its budget the run is finished linearly, and the
        answer is still found (here at the very end of a run that re cannot get through in time)."""
        run = self.SHORT * 30 + b"curl http://x\n"
        data = run + b"z" * 20000 + b"\n" + self.SHORT * 3
        m = reg(Match(r"curl[^|]*http://"))
        e = reg(Match(r"curl[^|]*http://", excl="zzz"))
        for cond in (m, e):
            with self.subTest(cond=cond):
                t0 = time.perf_counter()
                self.assertTrue(evaluate(cond, tgt(data), pol(budget=0.02)))
                self.assertLess(time.perf_counter() - t0, 2.0)
                self.assertFalse(evaluate(cond, tgt(self.SHORT * 30 + b"z" * 20000 + b"\n" + self.SHORT * 3), pol(budget=0.02)))

    def test_a_spent_budget_still_finds_a_match_in_a_later_run(self):
        """The first run costs more than the whole budget; the runs after the long line are then searched linearly, not skipped."""
        data = self.SHORT * 30 + b"z" * 20000 + b"\n" + self.SHORT * 2 + b"curl http://x\n" + b"z" * 20000 + b"\n" + b"curl http://y\n"
        clean = self.SHORT * 30 + b"z" * 20000 + b"\n" + self.SHORT * 2 + b"z" * 20000 + b"\n" + b"ok\n"
        for cond in (reg(Match(r"curl[^|]*http://")), reg(Match(r"curl[^|]*http://", excl="zzz"))):
            with self.subTest(cond=cond):
                self.assertTrue(evaluate(cond, tgt(data), pol(budget=0.02)))
                self.assertFalse(evaluate(cond, tgt(clean), pol(budget=0.02)))
        # the exclusion still applies in the linear run
        both = reg(Match(r"curl[^|]*http://", excl="http://y"))
        self.assertTrue(evaluate(both, tgt(data), pol(budget=0.02)))
        only_y = self.SHORT * 30 + b"z" * 20000 + b"\n" + self.SHORT * 2 + b"curl http://y\n" + b"z" * 20000 + b"\n"
        self.assertFalse(evaluate(both, tgt(only_y), pol(budget=0.02)))

    def test_one_budget_for_all_the_runs_of_a_buffer(self):
        """300 long lines with a run of one 8 KiB line between each pair: re may spend ONE budget on the whole buffer, not one per run
        (a fresh budget per run measured 6.2 s here; the linear matcher needs 0.4 s)."""
        data = ((b"curl x " * 1300)[:9000] + b"\n" + (b"curl x " * 1200)[:8000] + b"\n") * 300
        for cond in (reg(Match(r"curl[^|]*http://")), reg(Match(r"curl[^|]*http://", excl="zzz"))):
            with self.subTest(cond=cond):
                t0 = time.perf_counter()
                self.assertFalse(evaluate(cond, tgt(data), pol(budget=0.25)))
                self.assertLess(time.perf_counter() - t0, 2.5)

    def test_nonpositive_budget_does_not_disable_the_limit(self):
        """setitimer(0) would DISARM the alarm: a budget of 0 must reach rx as a small positive number, never as 0 or None."""
        m = reg(Match(r"curl[^|]*http://"))
        e = reg(Match(r"curl[^|]*http://", excl="zzz"))
        data = b"curl x " * 1100 + b"\n"
        for budget in (0.0, -1.0):
            with self.subTest(budget=budget):
                with mock.patch.object(rx, "search_lines", wraps=rx.search_lines) as sl, mock.patch.object(rx, "search_excl", wraps=rx.search_excl) as se:
                    self.assertFalse(evaluate(m, tgt(data), pol(budget=budget)))
                    self.assertFalse(evaluate(e, tgt(data), pol(budget=budget)))
                    self.assertFalse(evaluate(reg(Match(r"curl[^|]*http://", mode="flat")), tgt(data), pol(budget=budget)))
                self.assertGreater(sl.call_args.kwargs["budget"], 0)
                self.assertGreater(se.call_args.kwargs["budget"], 0)

    def test_only_a_flat_rule_asks_for_the_folded_copy(self):
        def boom():
            raise AssertionError("the folded copy was built for a rule that does not need it")

        t = Target(data=b"abc\nxyz\n", basename="f", ext="txt", has_long_line=False, flat=boom)
        for cond in (reg(Match("abc")), reg(Match("abc", ci=True)), reg(Match("abc", excl="q")), reg(Not(Match("zzz"))),
                     reg(AllOf((Match("abc"), Match("xyz"))))):
            with self.subTest(cond=cond):
                evaluate(cond, t, pol())
        evaluate(reg(Match("abc", binary="skip")), t, pol())
        with self.assertRaises(AssertionError):
            evaluate(reg(Match("abc", mode="flat")), t, pol())
        # a flat rule that will answer "no" from the first 32 KiB (grep -I and a NUL byte) builds no copy at all
        self.assertFalse(evaluate(reg(Match("abc", mode="flat", binary="skip")), Target(b"abc\0", "f", "txt", False, boom), pol()))

    def test_no_nested_time_limit(self):
        """rx.time_limit cannot be nested (leaving the inner block cancels the outer timer): at most one is ever open."""
        depth = {"cur": 0, "max": 0, "calls": 0}
        real = rx.time_limit

        @contextlib.contextmanager
        def spy(seconds):
            depth["cur"] += 1
            depth["calls"] += 1
            depth["max"] = max(depth["max"], depth["cur"])
            try:
                with real(seconds):
                    yield
            finally:
                depth["cur"] -= 1

        rows = [spec(Match("nt_%d" % i)) for i in range(4)] + [spec(Match("nt_x", excl="nt_y")), spec(Match("nt_f", mode="flat")),
                                                               spec(AllOf((Match("nt_a"), Not(Match("nt_b")))))]
        rs = RuleSet("wp04t-nest", rows)
        big = b"ok\n" * 20000 + b"curl x " * 12000 + b"\n" + b"ok\n" * 20000
        with mock.patch.object(rx, "time_limit", spy):
            run_ruleset(rs, tgt(b"nt_0 nt_x nt_f nt_a\n"), pol(), deadline=time.monotonic() + 60)
            run_ruleset(rs, tgt(big, 8192), pol(8192, budget=0.0005), deadline=time.monotonic() + 60)
            run_ruleset(rs, tgt(big, 100, long_line=True), pol(100, budget=0.0005), deadline=time.monotonic() + 60)
            evaluate(rows[0].cond, tgt(b"x\n"), pol())
        self.assertGreater(depth["calls"], 0)
        self.assertEqual(depth["max"], 1)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0.0)

    def test_no_timer_left_armed(self):
        m = reg(Match("la_x"))
        evaluate(m, tgt(b"la_x\n"), pol())
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0.0)


# ------------------------------------------------------------------------------------------------------------------------
class TestMatcherSpans(unittest.TestCase):
    def test_spans_equal_rx_matching_lines(self):
        rnd = random.Random(13)
        for pattern in ("a+b", "^ab", "ba$", "x*", "^$", r"\bab\b", "c"):
            mt = Matcher(rid("sp"), Match(pattern))
            c = rx.ere_to_py(pattern)
            for _ in range(150):
                data = random_buffer(rnd, PIECES, 80)
                for flag in (False, True):
                    t = tgt(data, 3, long_line=flag)
                    got = list(mt.spans(t, pol(3)))
                    self.assertEqual(got, list(rx.matching_lines(c, data)), (pattern, flag, data))

    def test_spans_ci_and_skip(self):
        mt = Matcher(rid("sp"), Match("abc", ci=True))
        self.assertEqual(list(mt.spans(tgt(b"x\nABC\nabc d\n"), pol())), [(2, 5), (6, 11)])
        sk = Matcher(rid("sp"), Match("abc", binary="skip"))
        self.assertEqual(list(sk.spans(tgt(b"abc\nx\n"), pol())), [(0, 3)])
        self.assertEqual(list(sk.spans(tgt(b"abc\0\nx\n"), pol())), [])
        tx = Matcher(rid("sp"), Match("abc"))
        self.assertEqual(list(tx.spans(tgt(b"abc\0\nx\n"), pol())), [(0, 4)])

    def test_offsets_index_the_original_buffer(self):
        data = b"zero\nfirst needle here\n\nsecond needle\nlast"
        mt = Matcher(rid("sp"), Match("needle"))
        got = list(mt.spans(tgt(data), pol()))
        self.assertEqual([data[a:b] for a, b in got], [b"first needle here", b"second needle"])
        self.assertEqual([data[a:b] for a, b in mt.spans(tgt(data, 4, long_line=True), pol(4))], [b"first needle here", b"second needle"])

    def test_spans_excl(self):
        mt = Matcher(rid("sp"), Match("key", excl="skip"))
        data = b"key one\nkey skip\nKEY two\nnone\n"
        self.assertEqual([data[a:b] for a, b in mt.spans(tgt(data), pol())], [b"key one", b"KEY two"])
        self.assertEqual([data[a:b] for a, b in mt.spans(tgt(data, 3, long_line=True), pol(3))], [b"key one", b"KEY two"])
        nul = b"key one\0\n"
        self.assertEqual(list(mt.spans(tgt(nul), pol(blind=True))), [])
        self.assertEqual(list(mt.spans(tgt(nul), pol(blind=False))), [(0, 8)])

    def test_flat_matcher_has_no_spans(self):
        mt = Matcher(rid("sp"), Match("abc", mode="flat"))
        with self.assertRaises(ValueError):
            mt.spans(tgt(b"abc\n"), pol())            # at the call, not at the first next()
        with self.assertRaises(ValueError):
            list(mt.spans(tgt(b"abc\n"), pol()))

    def test_spans_is_lazy(self):
        mt = Matcher(rid("sp"), Match("a"))
        data = b"a\n" * 200_000
        it = iter(mt.spans(tgt(data), pol()))
        self.assertEqual(next(it), (0, 1))
        self.assertEqual(next(it), (2, 3))
        # the generator pulls from rx one item at a time (a mutant that builds a list first pulls the whole stream)
        for flag, name in ((False, "matching_lines"), (True, "dfa_matching_lines")):
            pulled = [0]

            def fake(*args, **kwargs):
                for i in range(200_000):
                    pulled[0] += 1
                    yield (i, i + 1)

            with mock.patch.object(rx, name, fake):
                gen = iter(mt.spans(tgt(data, long_line=flag), pol()))
                self.assertEqual(next(gen), (0, 1))
            with self.subTest(route=name):
                self.assertLessEqual(pulled[0], 2)

    def test_search_is_evaluate(self):
        m = Match("se_x", excl="se_y")
        mt = Matcher(rid("sp"), m)
        for data in (b"se_x\n", b"se_x se_y\n", b"", b"se_x\0\n"):
            for blind in (False, True):
                self.assertEqual(mt.search(tgt(data), pol(blind=blind)), evaluate(m, tgt(data), pol(blind=blind)))

    def test_spans_use_the_linear_matcher_for_a_long_line(self):
        mt = Matcher(rid("sp"), Match(r"curl[^|]*http://"))
        data = b"curl x " * 100_000 + b"\ncurl http://x\n"
        t0 = time.monotonic()
        got = list(mt.spans(tgt(data), pol()))
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(len(got), 1)
        self.assertEqual(data[got[0][0]:got[0][1]], b"curl http://x")


# ------------------------------------------------------------------------------------------------------------------------
class TestHostileLine(unittest.TestCase):
    """S12: every pattern the engine can run finishes on a 600 KB line in under a second."""

    LIMIT_S = 1.0
    LINES = {
        "curl": (b"curl x " * 100000)[:600_000],
        "a": b"a" * 600_000,
    }

    @staticmethod
    def inventory_matches():
        """Every ERE the bash scanner hands to grep_check, grep_check_i, grep_flat, grep_check_excl and _pdf_has (the 243 of the
        inventory that are static), as the Match a table row would be."""
        rows = json.loads((ROOT / "tests" / "conformance" / "patterns.json").read_text())
        out = {}
        for x in rows:
            if x.get("dialect") != "ere" or x.get("dynamic"):
                continue
            h, pat = x["helper"], x["pattern"]
            if h == "grep_check" or h == "_pdf_has":
                m = Match(pat)
            elif h == "grep_check_i":
                m = Match(pat, ci=True)
            elif h == "grep_flat":
                m = Match(pat, mode="flat")
            elif h == "grep_check_excl":
                m = Match(pat, excl=x["excl"])
            else:
                continue
            out[m] = x["enclosing_function"]
        return out

    def check(self, matches):
        worst = (0.0, None)
        for m in matches:
            ci = m.ci or m.mode == "flat" or m.excl is not None
            if not rx.dfa_available(rx.ere_to_py(m.pattern, ci)):
                continue          # a back-reference: no linear matcher, it can only time out (see TestRunRuleset.test_timed_out...)
            for name, line in self.LINES.items():
                t = tgt(line)
                self.assertTrue(t.has_long_line)
                t0 = time.perf_counter()
                evaluate(m, t, pol())
                dt = time.perf_counter() - t0
                if dt > worst[0]:
                    worst = (dt, (m.pattern[:70], name))
                self.assertLess(dt, self.LIMIT_S, "%r on the %s line took %.2f s" % (m, name, dt))
        return worst

    def test_every_inventory_pattern(self):
        matches = list(self.inventory_matches())
        self.assertGreater(len(matches), 200)
        for m in matches:       # F4: every pattern of the inventory has a linear matcher, so the check below skips none of them
            self.assertTrue(rx.dfa_available(rx.ere_to_py(m.pattern, m.ci or m.mode == "flat" or m.excl is not None)), m)
        RuleSet("wp04t-inventory", [RuleSpec(id="wp04t-inventory/%03d-p" % i, outcome="warn", message="CWE-0:inv", cond=m)
                                    for i, m in enumerate(matches)])
        self.check(matches)

    def test_every_registered_rule_of_the_process(self):
        """Whatever other modules registered through RuleSet or Matcher (the universal rows, the key header and body, the credential
        alternation and each provider): rebuild its Match from the registry and run it."""
        seen, matches = set(), []
        for r in rx.registered():
            if r.id.startswith("wp04t"):
                continue
            if r.mode == "excl":
                m = Match(r.pattern, excl=r.excl)
            elif r.mode == "flat":
                m = Match(r.pattern, mode="flat")
            elif r.mode == "line_i":
                m = Match(r.pattern, ci=True)
            else:
                m = Match(r.pattern)
            if m in seen:
                continue
            seen.add(m)
            try:
                evaluate(m, tgt(b"x\n"), pol())
            except ValueError:
                continue                   # registered straight with rx.rule, not through RuleSet or Matcher
            matches.append(m)
        self.check(matches)

    def test_one_line_of_each_size_with_a_quadratic_pattern(self):
        m = reg(Match(r"curl[^|]*http://"))
        for size in (10_000, 70_000, 600_000, 3_000_000):
            data = (b"curl x " * (size // 7 + 1))[:size]
            t0 = time.perf_counter()
            self.assertFalse(evaluate(m, tgt(data), pol()))
            self.assertLess(time.perf_counter() - t0, 0.1 + size * 6e-7, size)

    def test_hostile_flat_and_excl_lines(self):
        flat = reg(Match(r"curl[^|]*http://", mode="flat"))
        excl = reg(Match(r"curl[^|]*http://", excl="zzz"))
        data = (b"curl x \n" * 80_000)[:600_000]       # the folded view is one 600 KB line
        for m in (flat, excl):
            t0 = time.perf_counter()
            self.assertFalse(evaluate(m, tgt(data), pol(blind=False)))
            self.assertLess(time.perf_counter() - t0, self.LIMIT_S)
        data2 = b"curl x " * 60_000 + b"\n" + b"y" * 700_000
        t0 = time.perf_counter()
        self.assertFalse(evaluate(excl, tgt(data2), pol()))
        self.assertLess(time.perf_counter() - t0, self.LIMIT_S)


# ------------------------------------------------------------------------------------------------------------------------
_RSS_CHILD = r"""
import resource, sys
sys.path.insert(0, sys.argv[1])
from transit import rules, rx
from transit.rules import Match, Matcher, RuleSet, RuleSpec, SearchPolicy, Target
phase, size = sys.argv[2], int(sys.argv[3])
policy = SearchPolicy(rule_budget_s=0.25, long_line_bytes=8192, excl_nul_blind=False)
ms = {"line": Match("zzzz"), "excl": Match("zzzz", excl="q")}
RuleSet("rss", [RuleSpec(id="rss/%02d-%s" % (i, k), outcome="warn", message="CWE-0:x", cond=m) for i, (k, m) in enumerate(ms.items())])
every = Matcher("rss/every", Match("a"))
never = Matcher("rss/never", Match("zzzz"))
unit = b"ab\n"
def no_flat():
    raise AssertionError("only a flat rule may ask for the folded copy")
if phase == "short":
    # the whole file is two-byte lines: 30 million of them, and `every` matches each one
    data = unit * (size // 3)
    t = Target(data=data, basename="f", ext="txt", has_long_line=False, flat=no_flat)
    assert rules.evaluate(ms["line"], t, policy) is False
    assert next(iter(every.spans(t, policy))) == (0, 2)      # only the first of the 30 million spans is asked for
    assert list(never.spans(t, policy)) == []
else:
    # the same kind of file with one over-long line in the middle: the router splits around it (excl copies each run)
    half = unit * (size // 6)
    data = b"".join([half, b"x" * 9000, b"\n", half])
    del half
    t = Target(data=data, basename="f", ext="txt", has_long_line=True, flat=no_flat)
    assert rules.evaluate(ms["line"], t, policy) is False
    assert rules.evaluate(ms["excl"], t, policy) is False
    assert next(iter(every.spans(t, policy))) == (0, 2)
print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)
"""


class TestMemory(unittest.TestCase):
    """No buffer is split into a list of lines and no more than one derived copy lives at a time (design 9.4, R-04, F12): the peak
    resident size of a child process stays under three times the file. A list of the lines of 90 MB of two-byte lines needs about 19 times."""

    def peak(self, phase: str, size: int) -> int:
        r = subprocess.run([sys.executable, "-I", "-c", _RSS_CHILD, str(ROOT), phase, str(size)], capture_output=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        return int(r.stdout.split()[-1])

    def test_90_mb_of_two_byte_lines_peaks_under_three_times_the_file(self):
        size = 90_000_000
        peak = self.peak("short", size)
        self.assertLess(peak, 3 * size, "peak resident size %d MB for a %d MB file" % (peak >> 20, size >> 20))

    def test_a_file_with_one_long_line_in_the_middle(self):
        size = 60_000_000
        peak = self.peak("long", size)
        self.assertLess(peak, 3 * size, "peak resident size %d MB for a %d MB file" % (peak >> 20, size >> 20))


class TestRuleSpecAndPolicyTypes(unittest.TestCase):
    def test_search_policy_defaults_and_frozen(self):
        p = SearchPolicy()
        self.assertEqual((p.rule_budget_s, p.long_line_bytes, p.excl_nul_blind), (0.25, 8192, True))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            p.rule_budget_s = 1.0  # type: ignore[misc]

    def test_target_fields(self):
        t = Target(b"x", "b", "e", True, lambda: b"y")
        self.assertEqual((t.data, t.basename, t.ext, t.has_long_line, t.flat()), (b"x", "b", "e", True, b"y"))

    def test_scan_budget_exceeded_is_an_exception(self):
        self.assertTrue(issubclass(ScanBudgetExceeded, Exception))

    def test_module_has_no_re_import_and_no_line_materialisation(self):
        src = (ROOT / "transit" / "rules" / "__init__.py").read_text()
        code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        # strip the module docstring, which names the forbidden calls in order to forbid them
        body = code.split('"""', 2)[2] if code.lstrip().startswith('"""') else code
        for needle in ("import re\n", "from re ", ".after_context(", ".lines_over(", ".splitlines(", '.split(b"\\n")', ".split(b'\\n')"):
            self.assertNotIn(needle, body, needle)


if __name__ == "__main__":
    unittest.main()
