"""Tests of transit/files.py (WP-03): the file system side of a run. Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_files.py"

Oracles (docs/python_engine_design.md section 11): the real ``find`` driven with the exact prune expression that scan_pipeline.sh
builds (the block of the script is cut out and run by real bash, so the 30 pattern sets below also test the ``.transitignore``
reader), the real ``sha256sum`` recipe of contract 4, glibc's ``fnmatch`` (called through ctypes in a child process with
``LC_ALL=C``, which is what ``find -path`` calls), the symlink test and the ``.diff_files`` reader of the script. A token-shaped
credential is never written contiguously in this file. Everything below goes through the public names of the module (``files.X``),
so a missing name is one red test and not an import error.
"""
from __future__ import annotations

import ast
import dataclasses
import errno
import hashlib
import itertools
import json
import os
import random
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from transit import files, rx  # noqa: E402
from transit.config import DEFAULT_EXCLUDE_DIRS, Config, Limits, load_config  # noqa: E402
from transit.rules import Target  # noqa: E402

BASH = shutil.which("bash")
FIND = shutil.which("find")
SCRIPT = ROOT / "scan_pipeline.sh"
GOLDEN = ROOT / "tests" / "conformance" / "golden"
FIXTURES = ROOT / "tests" / "fixtures"
ENV_C = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
HAVE_ORACLE = bool(BASH) and bool(FIND) and SCRIPT.exists()


# ── helpers ────────────────────────────────────────────────────────────────────────────────────────────────────────
def fsb(name) -> bytes:
    return name if isinstance(name, bytes) else os.fsencode(name)


def write_file(base, rel, data=b"x\n") -> None:
    full = os.path.join(fsb(str(base)) if not isinstance(base, bytes) else base, fsb(rel))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode())


def make_tree(base, spec) -> None:
    for rel, data in spec.items():
        write_file(base, rel, data)


def config(**limits) -> Config:
    """The real ``config.load_config`` of an empty environment (``load_exclusions`` never reads it: D-003 is closed in bash)."""
    cfg = load_config({"WORK_DIR": "/nonexistent", "TMPDIR": "/tmp"})
    return dataclasses.replace(cfg, limits=Limits(**limits)) if limits else cfg


NO_DIFF = files.DiffSelection(active=False, keys=frozenset(), stale_ignored=False)


def scan(scan_dir, patterns=(), dirs=DEFAULT_EXCLUDE_DIRS, diff=None):
    ex = files.Exclusions(dir_names=tuple(dirs), patterns=tuple(patterns))
    return files.files_for_scan(scan_dir, ex, diff or NO_DIFF)


def rels(scan_list) -> list:
    return [e.rel for e in scan_list.entries]


def sorted_bytes(names) -> list:
    return sorted(names, key=fsb)


def fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="wp03_")
        self.addCleanup(self._td.cleanup)
        self.tmp = os.path.realpath(self._td.name)

    def mk(self, name="repo") -> str:
        path = os.path.join(self.tmp, name)
        os.makedirs(path)
        return path


# ── the bash oracles ───────────────────────────────────────────────────────────────────────────────────────────────
def _script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _between(text: str, start: str, end: str) -> str:
    i = text.index(start)
    j = text.index(end, i) + len(end)
    return text[i:j]


def _bash(script: str, *args, timeout=120) -> bytes:
    out = subprocess.run([BASH, "-c", script, "oracle", *args], capture_output=True, env=ENV_C, timeout=timeout)
    if out.returncode != 0:
        raise AssertionError("oracle failed: %r" % out.stderr[-500:])
    return out.stdout


def bash_prune(scan_dir: str):
    """(FIND_PRUNE_ARGS, EXTRA_EXCLUDE_DIRS) exactly as scan_pipeline.sh builds them for ``scan_dir`` (as bytes)."""
    block = _between(_script_text(), "\nDEFAULT_EXCLUDE_DIRS=(", "unset _prune_root\n")
    script = ("set -u\ninfo() { :; }\nSCAN_DIR=\"$1\"\n" + block +
              "\nprintf '%s\\0' \"${FIND_PRUNE_ARGS[@]}\"\nprintf '\\001SENTINEL\\0'\n"
              "if (( ${#EXTRA_EXCLUDE_DIRS[@]} )); then printf '%s\\0' \"${EXTRA_EXCLUDE_DIRS[@]}\"; fi\n")
    parts = _bash(script, scan_dir).split(b"\0")[:-1]
    k = parts.index(b"\x01SENTINEL")
    return parts[:k], parts[k + 1:]


def find_files(scan_dir: str) -> list:
    """The files ``find`` lists under the prune expression of the script, as rel strings sorted by bytes."""
    prune, _extra = bash_prune(scan_dir)
    out = subprocess.run([FIND, fsb(scan_dir), *prune, b"-type", b"f", b"-print0"], capture_output=True, env=ENV_C)
    root = fsb(scan_dir)
    names = [p[len(root) + 1:] for p in out.stdout.split(b"\0")[:-1]]
    return [n.decode("utf-8", "surrogateescape") for n in sorted(names)]


def find_symlinks(scan_dir: str) -> list:
    prune, _extra = bash_prune(scan_dir)
    out = subprocess.run([FIND, fsb(scan_dir), *prune, b"-type", b"l", b"-printf", b"%p\\0%l\\0"], capture_output=True, env=ENV_C)
    parts = out.stdout.split(b"\0")[:-1]
    root = fsb(scan_dir)
    return sorted((parts[i][len(root) + 1:].decode("utf-8", "surrogateescape"), parts[i + 1].decode("utf-8", "surrogateescape"))
                  for i in range(0, len(parts), 2))


def bash_symlink_escapes(pairs, scan_dir="/scan/root") -> list:
    text = _script_text()
    start = text.index("_symlink_escapes() {")
    end = text.index("\n}\n", start) + 3
    script = ("set -u\nSCAN_DIR=\"$1\"; shift\n" + text[start:end] +
              "\nwhile [ $# -gt 1 ]; do if _symlink_escapes \"$SCAN_DIR/$1\" \"$2\"; then printf '1'; else printf '0'; fi; shift 2; done\n")
    args = [x for pair in pairs for x in pair]
    out = _bash(script, scan_dir, *args)
    return [c == b"1"[0] for c in out]


def bash_diff(scan_dir: str, work_dir: str, since: str):
    """(DIFF_FILES_ONLY, set of keys) as the script's diff block computes them."""
    block = _between(_script_text(), "\nDIFF_FILES_ONLY=false", "file(s) will be scanned\"\nfi\n")
    script = ("set -u\ninfo() { :; }\nwarn() { :; }\nSCAN_DIR=\"$1\"; WORK_DIR=\"$2\"; SINCE_COMMIT=\"$3\"\n" + block +
              "\nprintf '%s\\n' \"$DIFF_FILES_ONLY\"\n"
              "if (( ${#DIFF_FILES_SET[@]} )); then printf '%s\\0' \"${!DIFF_FILES_SET[@]}\"; fi\n")
    out = _bash(script, scan_dir, work_dir, since)
    head, _, rest = out.partition(b"\n")
    keys = {k.decode("utf-8", "surrogateescape") for k in rest.split(b"\0")[:-1]} if rest else set()
    return head == b"true", keys


FNMATCH_CHILD = textwrap.dedent('''
    import ctypes, json, locale, sys
    locale.setlocale(locale.LC_ALL, "C")
    libc = ctypes.CDLL(None)
    libc.fnmatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    libc.fnmatch.restype = ctypes.c_int
    pairs = json.load(sys.stdin)
    print(json.dumps([libc.fnmatch(bytes.fromhex(p), bytes.fromhex(t), 0) == 0 for p, t in pairs]))
''')


def fnmatch_oracle(pairs) -> list:
    payload = json.dumps([[p.hex(), t.hex()] for p, t in pairs]).encode()
    out = subprocess.run([sys.executable, "-I", "-c", FNMATCH_CHILD], input=payload, capture_output=True, env=ENV_C, timeout=600)
    if out.returncode != 0:
        raise AssertionError("fnmatch oracle failed: %r" % out.stderr[-500:])
    return json.loads(out.stdout)


def s(b_: bytes) -> str:
    return b_.decode("utf-8", "surrogateescape")


# ── glob_match ─────────────────────────────────────────────────────────────────────────────────────────────────────
class GlobMatchTests(unittest.TestCase):
    TABLE = [
        # (pattern, text, expected) -- fnmatch(3) without FNM_PATHNAME: * matches / and a leading dot
        ("*.log", "x.log", True), ("*.log", "sub/x.log", True), ("*.log", "x.logs", False), ("*", "a/b/c", True), ("*", "", True),
        ("", "", True), ("", "a", False), ("a", "", False), ("?", "a", True), ("?", "/", True), ("?", "", False), ("?.py", "a.py", True),
        ("?.py", "ab.py", False), ("a*b", "a/b", True), ("a*b", "ab", True), ("a*b", "acb", True), ("a*b", "ac", False),
        ("*a*a*a*b", "aaab", True), ("*a*a*a*b", "aab", False), ("[ab].py", "a.py", True), ("[ab].py", "c.py", False),
        ("[!ab].py", "c.py", True), ("[!ab].py", "a.py", False), ("[^ab].py", "c.py", True), ("[^ab].py", "b.py", False),
        ("[a-c]x", "bx", True), ("[a-c]x", "dx", False), ("[c-a]x", "bx", False), ("[]a]x", "]x", True), ("[]a]x", "ax", True),
        ("[!]a]x", "bx", True), ("[!]a]x", "]x", False), ("[a-]x", "-x", True), ("[a-]x", "ax", True), ("[a-]x", "bx", False),
        ("\\*", "*", True), ("\\*", "a", False), ("\\?x", "?x", True), ("\\?x", "ax", False), ("a\\", "a", False), ("a\\", "a\\", False),
        ("\\[a]", "[a]", True), ("[\\]]", "]", True), ("[a\\-c]", "-", True), ("[a\\-c]", "b", False),
        ("[", "[", True), ("[", "a", False), ("[a", "[a", True), ("[a", "a", False), ("a[", "a[", True), ("[!", "[!", True),
        ("[[:alpha:]]", "q", True), ("[[:alpha:]]", "7", False), ("[[:digit:]a]", "a", True), ("[[:digit:]a]", "5", True),
        ("[![:upper:]]", "a", True), ("[![:upper:]]", "A", False), ("[[:foo:]]", "a", False), ("[[:alpha:]", "a", False),
        ("[[:z:]]", ":]", True), ("[[:z:]]", "z", False), ("[[:alphz:]]", "[", False), ("[[:alpha:]]x", "ax", True), ("[a[:digit:]]", "5", True),
        ("[[.a.]-c]", "b", True), ("[[=a=]]", "a", True), ("[[=ab=]]", "a", False), ("[[", "[[", True), ("[[", "[", False), ("[ab", "[ab", True),
        ("[a-[:alpha:]]", "q", False),
        ("docs", "docs", True), ("docs", "docs/", False), ("docs/", "docs/", True), ("/h.py", "h.py", False), ("!keep", "keep", False),
        ("sub/*", "sub/a/b", True), ("sub/*", "sub", False), ("*/docs", "sub/docs", True), ("*/docs", "docs", False),
        ("weird dir", "weird dir", True), ("[[:space:]]", " ", True), ("[[:punct:]]", ".", True), ("[[:punct:]]", "a", False),
        # the C locale: one character is one BYTE (what LC_ALL=C find -path does), and bytes above 127 are in no class
        ("?", "\u00e9", False), ("??", "\u00e9", True), ("*", "\u00e9", True), ("[[:alpha:]]", "\u00e9", False), ("\u00e9", "\u00e9", True),
        ("x?y", "x\u00e9y", False), ("a?", "a\udce9", True),
    ]

    def test_table(self):
        for pattern, text, expected in self.TABLE:
            with self.subTest(pattern=pattern, text=text):
                self.assertIs(files.glob_match(pattern, text), expected)

    def test_table_against_glibc(self):
        pairs = [(p.encode("utf-8", "surrogateescape"), t.encode("utf-8", "surrogateescape")) for p, t, _ in self.TABLE]
        oracle = fnmatch_oracle(pairs)
        for (p, t, expected), want in zip(self.TABLE, oracle):
            with self.subTest(pattern=p, text=t):
                self.assertIs(want, expected, "the table itself disagrees with glibc")

    def test_small_exhaustive_against_glibc(self):
        psym = [b"a", b"b", b"[", b"]", b"!", b"^", b"-", b"\\", b":", b"*", b"?", b"z", b"=", b".", b"\xc3"]
        tsym = [b"a", b"b", b"[", b"]", b"-", b"!", b"/", b":", b"\xc3"]
        pats = [b"".join(c) for n in range(0, 4) for c in itertools.product(psym, repeat=n)]
        texts = [b"".join(c) for n in range(0, 3) for c in itertools.product(tsym, repeat=n)]
        pairs = [(p, t) for p in pats for t in texts]
        want = fnmatch_oracle(pairs)
        bad = [(p, t, w) for (p, t), w in zip(pairs, want) if files.glob_match(s(p), s(t)) is not w]
        self.assertEqual([], bad[:10], "%d of %d pairs differ from glibc fnmatch" % (len(bad), len(pairs)))

    def test_random_longer_against_glibc(self):
        rnd = random.Random(20261113)
        psym = [b"a", b"b", b"c", b"/", b".", b"*", b"*", b"?", b"[", b"]", b"!", b"^", b"-", b"\\", b":", b"z", b"A", b"1"]
        tsym = [b"a", b"b", b"c", b"/", b".", b"-", b"[", b"]", b"A", b"1", b"\\"]
        classes = [b"[[:alpha:]]", b"[[:digit:]]", b"[![:upper:]]", b"[[:foo:]]", b"[[:alpha:]-z]", b"[a-[:alpha:]]", b"[[:space:]a]", b"[[=a=]]",
                   b"[[.a.]]", b"[[.a.]-c]", b"[[=ab=]]", b"[[:alpha:]a-c]"]
        pairs = []
        for _ in range(30000):
            p = b"".join(rnd.choice(psym) for _ in range(rnd.randint(0, 9)))
            if rnd.random() < 0.15:
                p += rnd.choice(classes) + b"".join(rnd.choice(psym) for _ in range(rnd.randint(0, 2)))
            t = b"".join(rnd.choice(tsym) for _ in range(rnd.randint(0, 8)))
            pairs.append((p, t))
        want = fnmatch_oracle(pairs)
        bad = [(p, t, w) for (p, t), w in zip(pairs, want) if files.glob_match(s(p), s(t)) is not w]
        self.assertEqual([], bad[:10], "%d of %d pairs differ from glibc fnmatch" % (len(bad), len(pairs)))

    def test_cost_is_polynomial_not_exponential(self):
        started = time.monotonic()
        self.assertFalse(files.glob_match("*a" * 40 + "b", "a" * 3000))
        self.assertFalse(files.glob_match("[a-z]*" * 30 + "1", "abc" * 1000))
        self.assertTrue(files.glob_match("*" * 200 + "a", "b" * 2000 + "a"))
        self.assertLess(time.monotonic() - started, 5.0)


# ── Exclusions ─────────────────────────────────────────────────────────────────────────────────────────────────────
def naive_excluded(patterns, rel: str) -> bool:
    suffixes = [rel] + [rel[i + 1:] for i, ch in enumerate(rel) if ch == "/"]
    return any(files.glob_match(p, x) for p in patterns for x in suffixes)


class ExclusionsTests(unittest.TestCase):
    def test_built_in_names_prune_directories_at_any_depth(self):
        ex = files.Exclusions(dir_names=("build", "vendor", ".git"), patterns=())
        for rel in ("build", "a/build", "a/b/vendor", ".git", "x/.git"):
            self.assertTrue(ex.excludes(rel, is_dir=True), rel)
        for rel in ("builder", "a/builds", "a/xbuild", "build.py", "a/b/vendor2", "git"):
            self.assertFalse(ex.excludes(rel, is_dir=True), rel)

    def test_built_in_names_never_match_a_file(self):
        """D-002: a regular file called build or vendor is scanned."""
        ex = files.Exclusions(dir_names=tuple(DEFAULT_EXCLUDE_DIRS), patterns=())
        for name in DEFAULT_EXCLUDE_DIRS:
            self.assertFalse(ex.excludes(name, is_dir=False), name)
            self.assertFalse(ex.excludes("sub/" + name, is_dir=False), name)
            self.assertTrue(ex.excludes("sub/" + name, is_dir=True), name)

    def test_patterns_match_files_and_directories_on_the_path_or_a_suffix(self):
        ex = files.Exclusions(dir_names=(), patterns=("docs", "a/b", "*.log", "sub/*", "?.py"))
        for rel, is_dir in (("docs", True), ("docs", False), ("x/docs", True), ("a/b", False), ("z/a/b", True), ("x.log", False),
                            ("deep/er/x.log", False), ("sub/anything", False), ("sub/a/b", True), ("q.py", False), ("d/q.py", False)):
            self.assertTrue(ex.excludes(rel, is_dir=is_dir), rel)
        for rel in ("sub", "docs2", "xdocs", "a/bc", "b", "a", "x.logs", "ab.py", "docs.d"):
            self.assertFalse(ex.excludes(rel, is_dir=False), rel)

    def test_a_trailing_backslash_excludes_the_children_of_the_directory(self):
        ex = files.Exclusions(dir_names=(), patterns=("a\\", "sub/b\\"))
        for rel in ("a/x", "z/a/x", "a/x.py", "sub/b/c", "q/sub/b/c", "a/x/y"):
            self.assertTrue(ex.excludes(rel, is_dir=False), rel)
            self.assertTrue(ex.excludes(rel, is_dir=True), rel)
        for rel in ("a", "z/a", "sub/b", "ab/x", "sub", "b/c"):
            self.assertFalse(ex.excludes(rel, is_dir=False), rel)
        even = files.Exclusions(dir_names=(), patterns=("a\\\\",))
        self.assertTrue(even.excludes("a\\", is_dir=False), "an escaped backslash is a literal one")
        self.assertFalse(even.excludes("a/x", is_dir=False))

    def test_forms_that_do_nothing_in_find(self):
        ex = files.Exclusions(dir_names=(), patterns=("docs/", "/h.py", "!keep", "docs//x"))
        for rel in ("docs", "h.py", "keep", "docs/x", "sub/docs", "sub/h.py"):
            self.assertFalse(ex.excludes(rel, is_dir=True), rel)
            self.assertFalse(ex.excludes(rel, is_dir=False), rel)

    def test_star_matches_every_entry(self):
        ex = files.Exclusions(dir_names=(), patterns=("*",))
        for rel in ("a", "a/b", ".hidden", "x y/z"):
            self.assertTrue(ex.excludes(rel, is_dir=False), rel)

    def test_equivalent_to_testing_every_pattern_on_every_suffix(self):
        """The literal index and the first-character filter give exactly the result of the naive loop (R-15)."""
        rnd = random.Random(7)
        names = ["a", "b", "ab", "a.py", "b.log", "docs", "x y", ".h", "[a]", "a*b", "q"]
        pattern_pool = ["a", "b", "ab", "docs", "a/b", "*.log", "*b", "a*", "?", "?.py", "[ab]", "[ab].py", "*/docs", "docs/*", "x y",
                        ".h", "[[]a]", "\\*", "a\\*b", "sub/a", "q/", "/q", "!a", "*", "a?", "[!a]*", "d*s", "*.py", "\\q", "[", "ab*b*"]
        for _ in range(400):
            patterns = tuple(rnd.sample(pattern_pool, rnd.randint(1, 8)))
            ex = files.Exclusions(dir_names=(), patterns=patterns)
            for _ in range(25):
                rel = "/".join(rnd.choice(names) for _ in range(rnd.randint(1, 4)))
                self.assertEqual(naive_excluded(patterns, rel), ex.excludes(rel, is_dir=False), (patterns, rel))

    def test_100000_literals_are_a_lookup_not_a_loop(self):
        literals = tuple("name%06d" % i for i in range(100000))
        ex = files.Exclusions(dir_names=(), patterns=literals)
        started = time.monotonic()
        for i in range(3000):
            self.assertFalse(ex.excludes("src/pkg%d/file%d.py" % (i, i), is_dir=False))
        self.assertTrue(ex.excludes("src/deep/name099999", is_dir=False))
        self.assertTrue(ex.excludes("name000000", is_dir=True))
        self.assertLess(time.monotonic() - started, 5.0)

    def test_semgrep_dirs_are_the_names_then_the_patterns(self):
        ex = files.Exclusions(dir_names=("node_modules", "build"), patterns=("docs", "*.log"))
        self.assertEqual(("node_modules", "build", "docs", "*.log"), tuple(ex.semgrep_dirs()))

    def test_exclusions_is_frozen_with_two_fields(self):
        self.assertEqual(["dir_names", "patterns"], [f.name for f in dataclasses.fields(files.Exclusions)])
        ex = files.Exclusions(dir_names=("a",), patterns=("b",))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ex.patterns = ()  # type: ignore[misc]


# ── .transitignore ─────────────────────────────────────────────────────────────────────────────────────────────────
TI_CASES = [
    b"docs\n", b"docs", b"docs\r\nsub\r\n", b"docs\r\nsub", b"# c\n\n  \n*.log\n", b"\r\n\r\n", b"a\\\nb\n", b"x\0y\nz\0\n\0\nw", b"\xff\xfe\n",
    b" lead\ntrail \n", b"#\n#x\n \n", b"a\r\r\n", b"a\r", b"\n\n\n", b"", b"docs\n\nsub\nsub\n", b"\tt\n", b"*\n", b"/h.py\n!keep\ndocs/\n",
    b"line one\nline two", b"\xc3\xa9.py\n", b"a#b\n#a\n", b"# only a comment", b"x\r", b"\r",
]


@unittest.skipUnless(HAVE_ORACLE, "bash, find or scan_pipeline.sh not available")
class LoadExclusionsTests(TmpCase):
    def test_patterns_equal_those_of_the_bash_reader(self):
        """The reader of the hardened script (last line without a newline, one CR removed, NUL bytes dropped) is the oracle."""
        for content in TI_CASES:
            with self.subTest(content=content):
                d = self.mk("r%d" % abs(hash(content)))
                with open(os.path.join(d, ".transitignore"), "wb") as fh:
                    fh.write(content)
                _prune, extra = bash_prune(d)
                ex, notes = files.load_exclusions(d, cfg=config())
                self.assertEqual([x.decode("utf-8", "surrogateescape") for x in extra], list(ex.patterns))
                self.assertEqual(tuple(DEFAULT_EXCLUDE_DIRS), tuple(ex.dir_names))
                self.assertEqual((), tuple(notes))

    def test_d003_last_line_and_crlf(self):
        d = self.mk()
        write_file(d, ".transitignore", b"src/db.py\r\nREADME.md")
        ex, _ = files.load_exclusions(d, cfg=config())
        self.assertEqual(("src/db.py", "README.md"), tuple(ex.patterns))

    def test_no_file_no_patterns_no_note(self):
        d = self.mk()
        ex, notes = files.load_exclusions(d, cfg=config())
        self.assertEqual(((), ()), (tuple(ex.patterns), tuple(notes)))
        self.assertEqual(tuple(DEFAULT_EXCLUDE_DIRS), tuple(ex.dir_names))

    def test_a_symlinked_transitignore_is_not_read(self):
        d = self.mk()
        write_file(self.tmp, "outside.txt", b"docs\n*\n")
        os.symlink(os.path.join(self.tmp, "outside.txt"), os.path.join(d, ".transitignore"))
        ex, notes = files.load_exclusions(d, cfg=config())
        self.assertEqual((), tuple(ex.patterns))
        self.assertEqual(1, len(notes))
        self.assertIn(".transitignore", notes[0])

    def test_a_fifo_and_a_directory_are_refused_without_blocking(self):
        for kind in ("fifo", "dir"):
            d = self.mk(kind)
            path = os.path.join(d, ".transitignore")
            os.mkfifo(path) if kind == "fifo" else os.mkdir(path)
            signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError("blocked on a FIFO")))
            signal.alarm(10)
            try:
                ex, notes = files.load_exclusions(d, cfg=config())
            finally:
                signal.alarm(0)
            self.assertEqual((), tuple(ex.patterns))
            self.assertEqual(1, len(notes), kind)

    def test_over_the_size_limit_is_refused(self):
        d = self.mk()
        write_file(d, ".transitignore", b"a\n" * (600 * 1024))
        ex, notes = files.load_exclusions(d, cfg=config())
        self.assertEqual((), tuple(ex.patterns))
        self.assertEqual(1, len(notes))

    def test_64_globs_are_accepted_and_65_refuse_the_whole_file(self):
        d = self.mk("ok")
        write_file(d, ".transitignore", "".join("g%d*\n" % i for i in range(files.MAX_GLOB_PATTERNS)))
        ex, notes = files.load_exclusions(d, cfg=config())
        self.assertEqual(files.MAX_GLOB_PATTERNS, len(ex.patterns))
        self.assertEqual((), tuple(notes))
        d = self.mk("over")
        write_file(d, ".transitignore", "docs\n" + "".join("g%d*\n" % i for i in range(files.MAX_GLOB_PATTERNS + 1)))
        ex, notes = files.load_exclusions(d, cfg=config())
        self.assertEqual((), tuple(ex.patterns), "a refused file applies no exclusion at all, literals included")
        self.assertEqual(1, len(notes))
        self.assertIn("64", notes[0])

    def test_pattern_length_limit(self):
        d = self.mk("ok")
        write_file(d, ".transitignore", "a" * files.MAX_PATTERN_CHARS + "\n")
        ex, notes = files.load_exclusions(d, cfg=config())
        self.assertEqual(1, len(ex.patterns))
        self.assertEqual((), tuple(notes))
        for body in ("a" * (files.MAX_PATTERN_CHARS + 1), "x*" + "a" * files.MAX_PATTERN_CHARS):
            d = self.mk("over%d" % len(body))
            write_file(d, ".transitignore", "keep\n" + body + "\n")
            ex, notes = files.load_exclusions(d, cfg=config())
            self.assertEqual((), tuple(ex.patterns))
            self.assertEqual(1, len(notes))

    def test_a_hundred_thousand_literals_are_accepted(self):
        d = self.mk()
        write_file(d, ".transitignore", "".join("lit%06d\n" % i for i in range(100000)))
        started = time.monotonic()
        ex, notes = files.load_exclusions(d, cfg=config())
        self.assertEqual(100000, len(ex.patterns))
        self.assertEqual((), tuple(notes))
        self.assertTrue(ex.excludes("x/lit099999", is_dir=False))
        self.assertLess(time.monotonic() - started, 5.0)

    def test_the_characters_that_make_a_glob(self):
        self.assertEqual("*?[\\", files.GLOB_METACHARS)
        self.assertEqual((512, 64, 256), (files.MAX_WALK_DEPTH, files.MAX_GLOB_PATTERNS, files.MAX_PATTERN_CHARS))


# ── files_for_scan ─────────────────────────────────────────────────────────────────────────────────────────────────
F5_TREE = {
    "README.md": b"r\n", ".hidden": b"h\n", "a.py": b"a\n", "b.py": b"b\n", "h.py": b"h\n", "keep": b"k\n", "x.log": b"l\n",
    "docs/d.py": b"d\n", "docs/guide.md": b"g\n", "sub/docs/d.py": b"d\n", "sub/x.log": b"l\n", "sub/a/b/deep.py": b"d\n",
    "sub/a/b.py": b"b\n", "weird dir/w.py": b"w\n", "weird dir/.dot": b"d\n", "dir.with.dots/f": b"f\n", "?.py": b"q\n", "[ab].py": b"q\n",
    "build/out.txt": b"o\n", "node_modules/m/i.js": b"i\n", "src/build": b"a file called build\n", "vendor": b"a file called vendor\n",
    "tests/target/t.txt": b"t\n", ".git/config": b"c\n", "src/main.py": b"m\n", "sub/.manifest_sha256.txt": b"n\n",
}
F5_SETS = [
    ["docs"], ["a/b"], ["*.log"], ["docs/"], ["/h.py"], ["!keep"], ["*"], ["sub/*"], ["?.py"], ["[ab].py"], ["*/docs"], ["weird dir"],
    ["x.log", "docs"], ["# comment", "sub"], ["a*"], ["*.py"], ["sub/a"], ["[!a]*.py"], ["\\?.py"], ["d?cs"], ["*dot*"], ["keep", ""],
    ["["], ["sub/docs/d.py"], ["*/*/b.py"], [".hidden"], ["build"], ["weird*"], ["[[:alpha:]].py"], ["w[a-z]ird dir/*"], ["src/build"],
    ["vendor"], [".manifest_sha256.txt"], ["[a-c]*"], ["*/"], ["sub/a/b/*"], ["target"], ["README.md", "docs", "?.py"], ["docs", "docs", "docs"],
    ["*.py", "!a.py"], ["dir.with.dots"], ["dir.*"], ["*?"], ["\\*"], [".*"], ["[.]git"], ["sub/*/*"], ["*/*/*/*"],
    # a trailing backslash: the script's `D/*` forms make it an escaped slash, so the children of D are excluded (found by the fuzz in the notes)
    ["docs\\"], ["?\\"], ["sub\\", "x.log"], ["\\\\"], ["*\\"], ["sub/a\\"], ["a\\\\"], ["[ab]\\"],
]


@unittest.skipUnless(HAVE_ORACLE, "bash, find or scan_pipeline.sh not available")
class FilesForScanAgainstFindTests(TmpCase):
    def check(self, d):
        ex, _ = files.load_exclusions(d, cfg=config())
        got = files.files_for_scan(d, ex, NO_DIFF)
        self.assertEqual((), got.errors)
        self.assertEqual(find_files(d), rels(got))

    def test_the_f5_pattern_sets_give_exactly_the_files_find_lists(self):
        for index, patterns in enumerate(F5_SETS):
            with self.subTest(patterns=patterns):
                d = self.mk("t%d" % index)
                make_tree(d, F5_TREE)
                write_file(d, ".transitignore", "".join(p + "\n" for p in patterns))
                self.check(d)

    def test_crlf_and_unterminated_last_line_sets_give_the_files_find_lists(self):
        for index, content in enumerate((b"docs\r\nsub\r\n", b"docs\r\n*.log", b"x.log\r", b"# c\r\ndocs", b"weird dir\r\n\r\nsub/docs")):
            with self.subTest(content=content):
                d = self.mk("c%d" % index)
                make_tree(d, F5_TREE)
                write_file(d, ".transitignore", content)
                self.check(d)

    def test_random_trees_and_pattern_sets_against_find(self):
        """The fuzz that found the trailing-backslash form (the script's ``D/*`` prune forms are not always redundant)."""
        rnd = random.Random(20261113)
        names = ["a", "b", "ab", "a.py", "b.log", "docs", "x y", ".h", "[a]", "a*b", "q", "build", "vendor", "node_modules", "\u00e9", "-x", "t.t", "ZZ", "a-b"]
        symbols = ["a", "b", "*", "?", "[", "]", "!", "^", "-", "\\", ".", "/", "x", "q", "d", "o", "c", "s", "y", " ", "p", "\u00e9"]
        for case in range(70):
            d = self.mk("r%d" % case)
            for _ in range(rnd.randint(3, 25)):
                rel = "/".join(rnd.choice(names) for _ in range(rnd.randint(1, 4)))
                try:
                    write_file(d, rel, b"x")
                except OSError:
                    pass
            patterns = []
            for _ in range(rnd.randint(1, 5)):
                if rnd.random() < 0.4:
                    patterns.append(rnd.choice(names) + (rnd.choice(["", "/*", "/", "*", "\\"]) if rnd.random() < 0.5 else ""))
                else:
                    patterns.append("".join(rnd.choice(symbols) for _ in range(rnd.randint(1, 6))))
            write_file(d, ".transitignore", "".join(p + "\n" for p in patterns))
            with self.subTest(case=case, patterns=patterns):
                self.check(d)

    def test_no_transitignore_at_all(self):
        d = self.mk()
        make_tree(d, F5_TREE)
        self.check(d)

    def test_a_root_whose_name_is_a_glob(self):
        d = os.path.join(self.tmp, "we[ir]d*dir?\\x")
        os.makedirs(d)
        make_tree(d, F5_TREE)
        write_file(d, ".transitignore", "docs\n*.log\n")
        self.check(d)

    def test_names_that_are_hostile(self):
        d = self.mk()
        names = [b"new\nline.py", b"esc\x1b[0m.py", b"bad\xff\xfe.py", b"sp ace.py", b"$(touch X).py", b"a'b.py", b"-rf.py", b"t\tab", b"\xc3\xa9.py"]
        for n in names:
            write_file(d, n)
        write_file(d, b"sub/" + names[0])
        self.check(d)

    def test_ancestors_of_the_scan_root_are_not_tested_d001(self):
        """Scanning /x/build/repo used to prune everything; neither the built-in names nor a pattern is ever tested against the root."""
        for ancestor in ("build", "node_modules", ".git", "vendor"):
            d = os.path.join(self.tmp, ancestor, "repo")
            os.makedirs(d)
            make_tree(d, {"a.py": b"a\n", "src/b.py": b"b\n"})
            self.assertEqual(["a.py", "src/b.py"], rels(scan(d)), ancestor)
            self.assertEqual(["a.py", "src/b.py"], rels(scan(d, patterns=("repo", ancestor, "*/repo"))), "the root itself is never tested")
            self.assertEqual([], rels(scan(d, patterns=("*",))), "'*' excludes the entries, not the root")

    def test_a_file_named_like_a_built_in_directory_is_scanned_d002(self):
        d = self.mk()
        make_tree(d, {name: b"x\n" for name in DEFAULT_EXCLUDE_DIRS})
        make_tree(d, {"sub/" + name: b"x\n" for name in DEFAULT_EXCLUDE_DIRS})
        self.assertEqual(sorted_bytes(list(DEFAULT_EXCLUDE_DIRS) + ["sub/" + n for n in DEFAULT_EXCLUDE_DIRS]), rels(scan(d)))
        d2 = self.mk("dirs")
        make_tree(d2, {name + "/inner.py": b"x\n" for name in DEFAULT_EXCLUDE_DIRS})
        make_tree(d2, {"keep.py": b"x\n", "deep/a/node_modules/x.js": b"x\n"})
        self.assertEqual(["keep.py"], rels(scan(d2)))

    def test_a_file_called_manifest_sha256_is_listed_at_the_root_and_nested_r01(self):
        d = self.mk()
        make_tree(d, {".manifest_sha256.txt": b"root\n", "sub/.manifest_sha256.txt": b"nested\n", "sub/deeper/.manifest_sha256.txt": b"n\n", "ok.py": b"1\n"})
        self.assertEqual([".manifest_sha256.txt", "ok.py", "sub/.manifest_sha256.txt", "sub/deeper/.manifest_sha256.txt"], rels(scan(d)))
        self.check(d)

    def test_hidden_files_and_the_transitignore_itself_are_listed(self):
        d = self.mk()
        make_tree(d, {".hidden": b"1\n", ".transitignore": b"nothing-here\n", ".transit-allow.json": b"[]\n", "ok.py": b"1\n"})
        self.assertEqual([".hidden", ".transit-allow.json", ".transitignore", "ok.py"], rels(scan(d, patterns=("nothing-here",))))

    def test_order_is_the_bytes_of_rel_and_sizes_are_lstat_sizes(self):
        d = self.mk()
        spec = {"a.b": b"1", "a/b": b"22", "a-b": b"333", "a0": b"4444", "B": b"5", "\u00e9.py": b"66", "z": b"", "a/a": b"7"}
        make_tree(d, spec)
        got = scan(d)
        self.assertEqual(sorted_bytes(spec), rels(got))
        self.assertEqual(["B", "a-b", "a.b", "a/a", "a/b", "a0", "z", "\u00e9.py"], rels(got))
        for entry in got.entries:
            self.assertEqual(len(spec[entry.rel]), entry.size)
            self.assertEqual(d + "/" + entry.rel, entry.path)

    def test_only_regular_files_are_listed_and_symlinks_are_neither_listed_nor_followed(self):
        d = self.mk()
        outside = self.mk("outside")
        write_file(outside, "secret.py", b"s\n")
        make_tree(d, {"real.py": b"1\n", "dir/inner.py": b"2\n"})
        os.symlink("real.py", os.path.join(d, "link_to_file.py"))
        os.symlink("dir", os.path.join(d, "link_to_dir"))
        os.symlink(outside, os.path.join(d, "link_out"))
        os.symlink("nowhere", os.path.join(d, "dangling"))
        os.symlink(".", os.path.join(d, "loop"))
        os.mkfifo(os.path.join(d, "fifo"))
        got = scan(d)
        self.assertEqual(["dir/inner.py", "real.py"], rels(got))
        self.assertEqual((), got.errors)

    def test_symlinks_are_reported_with_their_target_and_whether_it_escapes(self):
        d = self.mk()
        make_tree(d, {"real.py": b"1\n", "dir/inner.py": b"2\n"})
        links = {"ok_file": "real.py", "ok_dir": "dir", "dir/up_ok": "../real.py", "dir/up_out": "../../x", "abs": "/etc/passwd", "dir/self": ".",
                 "dangling": "nowhere", "dir/deep": "a/b/../../../..", "weird\nname": "real.py", "vendor": "real.py"}
        for name, target in links.items():
            os.symlink(target, os.path.join(d, name))
        got = scan(d)
        by_rel = {e.rel: e for e in got.symlinks}
        self.assertEqual(sorted_bytes(links), [e.rel for e in got.symlinks], "sorted by bytes")
        for name, target in links.items():
            e = by_rel[name]
            self.assertEqual(target, e.target)
            self.assertEqual(d + "/" + name, e.path)
        self.assertEqual({"abs", "dir/up_out", "dir/deep"}, {e.rel for e in got.symlinks if e.escapes})
        self.assertEqual(["dir/inner.py", "real.py"], rels(got))

    def test_symlinks_inside_pruned_or_excluded_places_are_not_reported(self):
        d = self.mk()
        make_tree(d, {"node_modules/x.js": b"1\n", "docs/d.py": b"1\n", "ok.py": b"1\n"})
        os.symlink("/etc", os.path.join(d, "node_modules", "l1"))
        os.symlink("/etc", os.path.join(d, "docs", "l2"))
        os.symlink("/etc", os.path.join(d, "l3.log"))
        os.symlink("/etc", os.path.join(d, "l4"))
        got = scan(d, patterns=("docs", "*.log"))
        self.assertEqual(["l4"], [e.rel for e in got.symlinks])

    @unittest.skipUnless(HAVE_ORACLE, "no oracle")
    def test_symlink_listing_and_the_escape_test_equal_the_script(self):
        d = self.mk()
        make_tree(d, {"real.py": b"1\n", "dir/inner.py": b"2\n", "docs/x": b"1\n"})
        links = {"a": "real.py", "dir/b": "../real.py", "dir/c": "../../r", "d": "/abs", "dir/e": "./x/../..", "f": "..", "dir/g": ".././..",
                 "docs/h": "x", "i": "dir/", "dir/j": "a//b/../../../z", "k": "", "dir/l": "x/./../../y"}
        for name, target in links.items():
            if target == "":
                continue
            os.symlink(target, os.path.join(d, name))
        write_file(d, ".transitignore", "docs\n")
        ex, _ = files.load_exclusions(d, cfg=config())
        got = files.files_for_scan(d, ex, NO_DIFF)
        want = find_symlinks(d)
        self.assertEqual(want, [(e.rel, e.target) for e in got.symlinks])
        verdicts = bash_symlink_escapes([(rel, target) for rel, target in want], scan_dir=d)
        self.assertEqual(verdicts, [e.escapes for e in got.symlinks])

    def test_symlink_escapes_function_against_the_script(self):
        pairs = [("a", ""), ("a", "."), ("a", ".."), ("a", "b"), ("a", "../b"), ("d/a", ".."), ("d/a", "../.."), ("d/a", "../../x"),
                 ("d/e/a", "../../.."), ("d/e/a", "../.."), ("a", "/x"), ("a", "//"), ("d/a", "x/../.."), ("d/a", "x/../../.."),
                 ("d/a", "./.././.."), ("d/a", "x//y/../../.."), ("d/e/f/a", "../../../.."), ("d/a", "..//.."), ("a", "x/.."), ("a", "x/../..")]
        want = bash_symlink_escapes(pairs)
        got = [files.symlink_escapes(rel, target) for rel, target in pairs]
        self.assertEqual(want, got)

    def test_symlink_escapes_random_pairs_against_the_script(self):
        rnd = random.Random(99)
        parts = ["a", "b", "..", ".", "", "..", "c d", "x"]
        pairs = []
        for _ in range(400):
            rel = "/".join(rnd.choice(["d", "e", "f g", "h"]) for _ in range(rnd.randint(0, 3)) ) or ""
            rel = (rel + "/" if rel else "") + "link"
            target = "/".join(rnd.choice(parts) for _ in range(rnd.randint(0, 6)))
            if rnd.random() < 0.05:
                target = "/" + target
            pairs.append((rel, target))
        want = bash_symlink_escapes(pairs)
        self.assertEqual(want, [files.symlink_escapes(rel, target) for rel, target in pairs])
        self.assertIn(True, want)
        self.assertIn(False, want)

    def test_control_files(self):
        self.assertEqual((".transitignore", ".transit-allow.json", ".manifest_sha256.txt"), tuple(files.CONTROL_FILE_NAMES))
        for name in files.CONTROL_FILE_NAMES:
            self.assertTrue(files.is_control_file(name), name)
            self.assertFalse(files.is_control_file("sub/" + name), name)
            self.assertFalse(files.is_control_file(name + "x"), name)
        self.assertFalse(files.is_control_file("a.py"))

    def test_examined_counts_the_files_that_are_not_control_files(self):
        d = self.mk()
        make_tree(d, {".transitignore": b"x\n", ".transit-allow.json": b"[]\n", ".manifest_sha256.txt": b"m\n", "sub/.manifest_sha256.txt": b"n\n"})
        got = scan(d)
        self.assertEqual(4, len(got.entries))
        self.assertEqual(1, got.examined, "a nested .manifest_sha256.txt is an ordinary file")
        write_file(d, "ok.py", b"1\n")
        self.assertEqual(2, scan(d).examined)

    def test_excluded_by_patterns_counts_entries_and_a_pruned_directory_once(self):
        d = self.mk()
        make_tree(d, {"docs/a": b"1", "docs/b": b"2", "sub/docs/c": b"3", "x.log": b"4", "sub/y.log": b"5", "ok.py": b"6", "node_modules/m": b"7"})
        got = scan(d, patterns=("docs", "*.log"))
        self.assertEqual(4, got.excluded_by_patterns)
        self.assertEqual(["ok.py"], rels(got))
        self.assertEqual(0, scan(d).excluded_by_patterns, "the built-in names are not counted")
        self.assertEqual(0, scan(d, patterns=("nomatch",)).excluded_by_patterns)

    def test_nothing_scanned_follows_the_script(self):
        def make(files_, patterns):
            d = self.mk("n%d" % len(os.listdir(self.tmp)))
            make_tree(d, files_)
            return scan(d, patterns=patterns)

        got = make({"a.py": b"1", "b/c.py": b"2"}, ("*",))
        self.assertEqual(([], 0, True), (rels(got), got.examined, got.nothing_scanned))
        got = make({"a.py": b"1", ".transitignore": b"[!.]*\n"}, ("[!.]*",))
        self.assertEqual(([".transitignore"], 0, True), (rels(got), got.examined, got.nothing_scanned),
                         "a .transitignore that leaves only itself is still nothing scanned")
        got = make({"a.py": b"1"}, ("docs",))
        self.assertFalse(got.nothing_scanned, "no file was removed")
        got = make({"a.py": b"1", "node_modules/x.js": b"2"}, ("a.py",))
        self.assertTrue(got.nothing_scanned)
        got = make({"node_modules/x.js": b"2"}, ("docs",))
        self.assertFalse(got.nothing_scanned, "built-in exclusions alone are not nothing scanned")
        got = make({"docs/a.py": b"1"}, ())
        self.assertFalse(got.nothing_scanned, "no pattern, so nothing could have removed the files")
        got = make({}, ("*",))
        self.assertFalse(got.nothing_scanned, "an empty repository is not nothing scanned")
        got = make({".transitignore": b"*\n", ".manifest_sha256.txt": b"m\n"}, ("*",))
        self.assertFalse(got.nothing_scanned, "only control files: nothing was removed that counts")
        got = make({"a.py": b"1", "b.py": b"2"}, ("a.py",))
        self.assertFalse(got.nothing_scanned)
        self.assertEqual(["b.py"], rels(got))

    def test_nothing_scanned_in_a_diff_run_counts_the_changed_files_only(self):
        d = self.mk()
        make_tree(d, {"a.py": b"1", "b.py": b"2", ".transitignore": b"a.py\n"})
        base = os.path.abspath(d)
        diff_a = files.DiffSelection(active=True, keys=frozenset({base + "/a.py"}), stale_ignored=False)
        got = scan(d, patterns=("a.py",), diff=diff_a)
        self.assertEqual(([], True), (rels(got), got.nothing_scanned), "every changed file is excluded")
        diff_b = files.DiffSelection(active=True, keys=frozenset({base + "/b.py"}), stale_ignored=False)
        got = scan(d, patterns=("a.py",), diff=diff_b)
        self.assertEqual((["b.py"], False), (rels(got), got.nothing_scanned))
        diff_none = files.DiffSelection(active=True, keys=frozenset(), stale_ignored=False)
        got = scan(d, patterns=("a.py",), diff=diff_none)
        self.assertEqual(([], False), (rels(got), got.nothing_scanned), "a diff run with no changed file is not nothing scanned")

    def test_diff_selection_restricts_the_list_by_absolute_path(self):
        d = self.mk()
        make_tree(d, {"a.py": b"1", "sub/b.py": b"2", "c:d.py": b"3"})
        keys = frozenset({os.path.abspath(d) + "/a.py", os.path.abspath(d) + "/c:d.py", "/elsewhere/sub/b.py"})
        got = scan(d, diff=files.DiffSelection(active=True, keys=keys, stale_ignored=False))
        self.assertEqual(["a.py", "c:d.py"], rels(got))
        self.assertEqual(2, got.examined)
        self.assertEqual([], rels(scan(d, diff=files.DiffSelection(active=True, keys=frozenset(), stale_ignored=False))))

    def test_a_relative_or_untidy_scan_directory_matches_absolute_diff_keys_d019(self):
        d = self.mk()
        make_tree(d, {"a.py": b"1", "sub/b.py": b"2"})
        keys = frozenset({os.path.join(os.path.abspath(d), "sub", "b.py")})
        diff = files.DiffSelection(active=True, keys=keys, stale_ignored=False)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.tmp)
        for spelling in ("repo", "./repo", "repo/../repo", self.tmp + "//repo", self.tmp + "/./repo"):
            got = scan(spelling, diff=diff)
            self.assertEqual(["sub/b.py"], rels(got), spelling)
            self.assertEqual(spelling + "/sub/b.py", got.entries[0].path, "the recorded path keeps the spelling it was given")

    def test_errors_for_a_directory_that_cannot_be_listed(self):
        d = self.mk()
        make_tree(d, {"ok.py": b"1", "locked/in.py": b"2", "sub/locked/in.py": b"3", "broken/in.py": b"4", "sub/fine.py": b"5"})
        real_scandir = os.scandir

        def fake_scandir(arg):
            if isinstance(arg, int):
                try:
                    target = os.readlink("/proc/self/fd/%d" % arg)
                except OSError:
                    target = ""
                if target.endswith("/locked"):
                    raise PermissionError(errno.EACCES, "Permission denied")
                if target.endswith("/broken"):
                    raise OSError(errno.EIO, "Input/output error")
            return real_scandir(arg)

        before = fd_count()
        with mock.patch("os.scandir", side_effect=fake_scandir):
            got = scan(d)
        self.assertEqual(before, fd_count(), "no descriptor is left open")
        self.assertEqual([("broken", "io"), ("locked", "permission"), ("sub/locked", "permission")], sorted(got.errors))
        self.assertEqual(["ok.py", "sub/fine.py"], rels(got))
        self.assertEqual(1, got.listing_exit, "what find's exit status would have been")

    def test_errors_for_a_directory_that_cannot_be_opened(self):
        d = self.mk()
        make_tree(d, {"ok.py": b"1", "locked2/in.py": b"2"})
        real_open = os.open

        def fake_open(path, flags, mode=0o777, *, dir_fd=None):
            if dir_fd is not None and path == "locked2":
                raise PermissionError(errno.EACCES, "Permission denied")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("os.open", side_effect=fake_open):
            got = scan(d)
        self.assertEqual([("locked2", "permission")], list(got.errors))
        self.assertEqual(["ok.py"], rels(got))

    def test_a_clean_walk_has_exit_zero_and_no_errors(self):
        d = self.mk()
        make_tree(d, {"a.py": b"1"})
        got = scan(d)
        self.assertEqual((0, ()), (got.listing_exit, got.errors))

    def test_an_unopenable_root_is_one_error_and_never_raises(self):
        missing = os.path.join(self.tmp, "missing")
        got = scan(missing)
        self.assertEqual(((), 1), (got.entries, got.listing_exit))
        self.assertEqual(1, len(got.errors))
        self.assertIn(got.errors[0][1], ("io", "permission", "vanished"))
        write_file(self.tmp, "afile", b"x")
        got = scan(os.path.join(self.tmp, "afile"))
        self.assertEqual(((), 1), (got.entries, got.listing_exit))

    def test_an_entry_that_vanishes_during_the_walk_is_dropped_silently(self):
        d = self.mk()
        make_tree(d, {"a.py": b"1", "b.py": b"2", "sub/c.py": b"3"})
        real_scandir = os.scandir

        class Ghost:
            name = "ghost.py"
            path = "ghost.py"

            def is_dir(self, follow_symlinks=True):
                return False

            def is_symlink(self):
                return False

            def is_file(self, follow_symlinks=True):
                return True

            def stat(self, follow_symlinks=True):
                raise FileNotFoundError(errno.ENOENT, "gone")

            def inode(self):
                return 1

        class Wrapped:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                self.inner.__enter__()
                return self

            def __exit__(self, *exc):
                return self.inner.__exit__(*exc)

            def __iter__(self):
                yield Ghost()
                yield from self.inner

            def close(self):
                self.inner.close()

        with mock.patch("os.scandir", side_effect=lambda arg: Wrapped(real_scandir(arg))):
            got = scan(d)
        self.assertEqual(["a.py", "b.py", "sub/c.py"], rels(got))
        self.assertEqual((), got.errors)

    def test_a_tree_deeper_than_the_walk_limit_reports_too_deep(self):
        d = self.mk()
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for i in range(files.MAX_WALK_DEPTH + 2):
                os.mkdir("d", dir_fd=fd)
                nfd = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = nfd
                if i == 2:
                    with os.fdopen(os.open("mid.py", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "wb") as fh:
                        fh.write(b"mid\n")
        finally:
            os.close(fd)
        got = scan(d)
        self.assertEqual(["d/d/d/mid.py"], rels(got))
        self.assertEqual([("/".join(["d"] * (files.MAX_WALK_DEPTH + 1)), "too_deep")], list(got.errors))
        self.assertEqual(1, got.listing_exit)

    def test_walk_limit_is_read_at_call_time(self):
        d = self.mk()
        make_tree(d, {"a/b/c/d/e.py": b"1", "a/f.py": b"2"})
        with mock.patch.object(files, "MAX_WALK_DEPTH", 2):
            got = scan(d)
        self.assertEqual(["a/f.py"], rels(got))
        self.assertEqual([("a/b/c", "too_deep")], list(got.errors))

    def test_a_path_longer_than_path_max_is_listed_opened_and_read_f14(self):
        d = self.mk()
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        names = []
        try:
            for i in range(102):
                name = ("%03d" % i).ljust(50, "d")
                names.append(name)
                os.mkdir(name, dir_fd=fd)
                nfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = nfd
            with os.fdopen(os.open("leaf.py", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "wb") as fh:
                fh.write(b"import os\n")
        finally:
            os.close(fd)
        rel = "/".join(names + ["leaf.py"])
        self.assertGreater(len(rel), 5000)
        got = scan(d)
        self.assertEqual([rel], rels(got))
        self.assertEqual((), got.errors)
        self.assertEqual(10, got.entries[0].size)
        view = files.FileView(d, rel, Limits())
        self.assertEqual(b"import os\n", view.data())
        ofd = files.open_beneath(d, rel)
        try:
            self.assertEqual(b"import os\n", os.read(ofd, 100))
        finally:
            os.close(ofd)
        h = files.compute_hashes(d)
        want = hashlib.sha256(("%s  ./%s\n" % (hashlib.sha256(b"import os\n").hexdigest(), rel)).encode()).hexdigest()
        self.assertEqual(want, h.sha256, "a file below PATH_MAX is hashed, not replaced by the path-list hash")
        self.assertNotEqual(h.sha256, h.repo_hash)

    def test_never_walks_by_path_string(self):
        """No os.scandir/os.listdir/os.walk/os.lstat call receives a str path (they would fail beyond PATH_MAX)."""
        d = self.mk()
        make_tree(d, {"a/b/c.py": b"1", "d.py": b"2"})
        seen = []
        real_scandir, real_listdir, real_walk, real_stat = os.scandir, os.listdir, os.walk, os.stat

        def spy(real, name):
            def inner(*a, **k):
                seen.append((name, a[0] if a else None))
                return real(*a, **k)
            return inner
        with mock.patch("os.scandir", side_effect=spy(real_scandir, "scandir")), mock.patch("os.listdir", side_effect=spy(real_listdir, "listdir")), \
                mock.patch("os.walk", side_effect=spy(real_walk, "walk")):
            got = scan(d)
        self.assertEqual(["a/b/c.py", "d.py"], rels(got))
        self.assertTrue(seen)
        self.assertEqual([], [x for x in seen if not isinstance(x[1], int)], "only directory descriptors are ever listed")

    def test_a_hostile_tree_never_raises(self):
        d = self.mk()
        for name in (b"a\nb", b"\x1b]0;x\x07", b"\xff\xfe", b"x" * 255):
            write_file(d, name)
        os.symlink("loop", os.path.join(d, "loop"))
        os.mkfifo(os.path.join(d, "pipe"))
        got = scan(d)
        self.assertEqual(4, len(got.entries))


# ── open_beneath ───────────────────────────────────────────────────────────────────────────────────────────────────
class OpenBeneathTests(TmpCase):
    def read(self, d, rel):
        fd = files.open_beneath(d, rel)
        try:
            return os.read(fd, 1000)
        finally:
            os.close(fd)

    def reason(self, d, rel):
        with self.assertRaises(files.FileReadError) as cm:
            os.close(files.open_beneath(d, rel))
        return cm.exception.reason

    def test_opens_a_regular_file_read_only(self):
        d = self.mk()
        make_tree(d, {"a.py": b"hello", "sub/dir/b.py": b"deep"})
        self.assertEqual(b"hello", self.read(d, "a.py"))
        self.assertEqual(b"deep", self.read(d, "sub/dir/b.py"))
        fd = files.open_beneath(d, "a.py")
        try:
            with self.assertRaises(OSError):
                os.write(fd, b"x")
            self.assertTrue(os.get_inheritable(fd) is False, "not inherited by a child process")
        finally:
            os.close(fd)

    def test_a_trailing_slash_on_the_scan_directory_is_fine(self):
        d = self.mk()
        write_file(d, "a.py", b"x")
        self.assertEqual(b"x", self.read(d + "/", "a.py"))

    def test_a_symlink_as_the_last_component_is_vanished(self):
        d = self.mk()
        make_tree(d, {"real.py": b"secret"})
        os.symlink("real.py", os.path.join(d, "link.py"))
        os.symlink("/etc/passwd", os.path.join(d, "etc.py"))
        self.assertEqual("vanished", self.reason(d, "link.py"))
        self.assertEqual("vanished", self.reason(d, "etc.py"))

    def test_a_symlinked_component_is_vanished_whatever_it_points_at(self):
        d = self.mk()
        outside = self.mk("outside")
        make_tree(outside, {"s.py": b"outside"})
        make_tree(d, {"real/in.py": b"inside"})
        os.symlink(outside, os.path.join(d, "out"))
        os.symlink("real", os.path.join(d, "inner"))
        self.assertEqual("vanished", self.reason(d, "out/s.py"))
        self.assertEqual("vanished", self.reason(d, "inner/in.py"))

    def test_missing_directory_fifo_and_not_a_directory(self):
        d = self.mk()
        make_tree(d, {"f.py": b"x"})
        os.mkdir(os.path.join(d, "adir"))
        os.mkfifo(os.path.join(d, "fifo"))
        self.assertEqual("vanished", self.reason(d, "nope.py"))
        self.assertEqual("vanished", self.reason(d, "nodir/x.py"))
        self.assertEqual("vanished", self.reason(d, "f.py/x"))
        self.assertEqual("vanished", self.reason(d, "adir"))
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError("blocked on a FIFO")))
        signal.alarm(10)
        try:
            self.assertEqual("vanished", self.reason(d, "fifo"), "a FIFO swapped in after listing must not block the engine")
        finally:
            signal.alarm(0)

    def test_bad_rel_is_a_value_error(self):
        d = self.mk()
        for rel in ("", ".", "..", "a/../b", "a//b", "/a", "a/", "a/./b", "../x"):
            with self.subTest(rel=rel), self.assertRaises(ValueError):
                files.open_beneath(d, rel)

    def test_error_mapping(self):
        d = self.mk()
        write_file(d, "f.py", b"x")
        real_open = os.open
        for number, want in ((errno.EACCES, "permission"), (errno.EPERM, "permission"), (errno.ENOENT, "vanished"), (errno.ENOTDIR, "vanished"),
                             (errno.ELOOP, "vanished"), (errno.EIO, "io"), (errno.EMFILE, "io"), (errno.ENAMETOOLONG, "io")):
            def fake(path, flags, mode=0o777, *, dir_fd=None, _n=number):
                if path == "f.py":
                    raise OSError(_n, os.strerror(_n))
                return real_open(path, flags, mode, dir_fd=dir_fd)
            with self.subTest(errno=errno.errorcode[number]), mock.patch("os.open", side_effect=fake):
                self.assertEqual(want, self.reason(d, "f.py"))

    def test_no_descriptor_is_leaked_on_any_path(self):
        d = self.mk()
        make_tree(d, {"a/b/c.py": b"x"})
        os.symlink("a", os.path.join(d, "l"))
        os.mkfifo(os.path.join(d, "fifo"))
        before = fd_count()
        for rel in ("a/b/c.py", "l/b/c.py", "a/b/missing", "fifo", "a", "a/b"):
            try:
                os.close(files.open_beneath(d, rel))
            except files.FileReadError:
                pass
        self.assertEqual(before, fd_count())

    def test_unopenable_scan_directory(self):
        with self.assertRaises(files.FileReadError):
            files.open_beneath(os.path.join(self.tmp, "missing"), "a.py")


# ── FileView ───────────────────────────────────────────────────────────────────────────────────────────────────────
class FileViewTests(TmpCase):
    def view(self, d, rel, **limits):
        return files.FileView(d, rel, Limits(**limits))

    def test_identity(self):
        v = files.FileView("/tmp/x", "sub/App.PY", Limits())
        self.assertEqual(("/tmp/x/sub/App.PY", "sub/App.PY", "App.PY", "py"), (v.path, v.rel, v.basename, v.ext))
        self.assertEqual("/tmp/x/a.py", files.FileView("/tmp/x///", "a.py", Limits()).path)
        self.assertEqual("/a.py", files.FileView("/", "a.py", Limits()).path)
        self.assertEqual("b", files.FileView("/s", "a.b", Limits()).ext)

    def test_ext_is_taken_from_the_full_path_and_lowered_in_ascii_only(self):
        self.assertEqual("d/readme", files.FileView("/tmp/x.d", "README", Limits()).ext, "the text after the last dot of the FULL path")
        self.assertEqual("/srv/repo/makefile", files.FileView("/srv/repo", "Makefile", Limits()).ext, "no dot at all: the whole path")
        self.assertEqual("gz", files.FileView("/s", "a.b.TAR.GZ", Limits()).ext)
        self.assertEqual("", files.FileView("/s", "trailing.", Limits()).ext)
        self.assertEqual("ps1", files.FileView("/s", "x.PS1", Limits()).ext)
        self.assertEqual("\u212at", files.FileView("/s", "x.\u212At", Limits()).ext, "LC_ALL=C: only A-Z are lowered (the Kelvin sign is not a K)")
        self.assertEqual("\udce9y", files.FileView("/s", "x.\udce9Y", Limits()).ext)

    def test_data_is_read_once_and_cached(self):
        d = self.mk()
        write_file(d, "a.py", b"first")
        v = self.view(d, "a.py")
        self.assertEqual(b"first", v.data())
        write_file(d, "a.py", b"second!")
        self.assertEqual(b"first", v.data())
        v.release()
        self.assertEqual(b"second!", v.data())

    def test_data_of_an_empty_file_and_of_binary(self):
        d = self.mk()
        write_file(d, "empty", b"")
        write_file(d, "bin", bytes(range(256)) * 10)
        self.assertEqual(b"", self.view(d, "empty").data())
        self.assertEqual(bytes(range(256)) * 10, self.view(d, "bin").data())

    def test_read_errors(self):
        d = self.mk()
        make_tree(d, {"f.py": b"x"})
        os.mkdir(os.path.join(d, "adir"))
        os.symlink("f.py", os.path.join(d, "l.py"))
        for rel in ("gone.py", "adir", "l.py", "f.py/x"):
            with self.subTest(rel=rel), self.assertRaises(files.FileReadError) as cm:
                self.view(d, rel).data()
            self.assertEqual("vanished", cm.exception.reason)

    def test_too_large_is_checked_before_and_after_reading(self):
        d = self.mk()
        write_file(d, "ten", b"0123456789")
        write_file(d, "eleven", b"0123456789A")
        self.assertEqual(10, len(self.view(d, "ten", max_file_bytes=10).data()))
        with self.assertRaises(files.FileReadError) as cm:
            self.view(d, "eleven", max_file_bytes=10).data()
        self.assertEqual("too_large", cm.exception.reason)
        real_fstat = os.fstat

        def lying(fd):
            st = list(real_fstat(fd))
            st[stat.ST_SIZE] = 5
            return os.stat_result(st)
        write_file(d, "grew", b"x" * 50)
        with mock.patch("os.fstat", side_effect=lying), self.assertRaises(files.FileReadError) as cm:
            self.view(d, "grew", max_file_bytes=20).data()
        self.assertEqual("too_large", cm.exception.reason, "a file that grew since fstat is not read past the cap")
        with mock.patch("os.fstat", side_effect=lying):
            self.assertEqual(b"x" * 50, self.view(d, "grew", max_file_bytes=100).data())

    def test_io_errors_are_file_read_errors(self):
        d = self.mk()
        write_file(d, "f.py", b"x")
        v = self.view(d, "f.py")
        with mock.patch("os.read", side_effect=OSError(errno.EIO, "boom")), self.assertRaises(files.FileReadError) as cm:
            v.data()
        self.assertIn(cm.exception.reason, ("io",))

    def test_head_does_not_read_the_rest(self):
        d = self.mk()
        path = os.path.join(d, "huge.bin")
        with open(path, "wb") as fh:
            fh.write(b"HEAD")
            fh.truncate(400 * 1024 * 1024)
        v = self.view(d, "huge.bin", max_file_bytes=1 << 20)
        started = time.monotonic()
        self.assertEqual(b"HEAD" + b"\0" * 6, v.head(10), "head() does not go through data(), so the size cap is not in its way")
        self.assertEqual(8192, len(v.head()))
        self.assertLess(time.monotonic() - started, 2.0)
        with self.assertRaises(files.FileReadError) as cm:
            v.data()
        self.assertEqual("too_large", cm.exception.reason)
        write_file(d, "short", b"abc")
        self.assertEqual(b"abc", self.view(d, "short").head(100))
        self.assertEqual(b"", self.view(d, "short").head(0))

    def test_head_uses_the_cache_when_the_data_is_there(self):
        d = self.mk()
        write_file(d, "a", b"0123456789")
        v = self.view(d, "a")
        v.data()
        os.unlink(os.path.join(d, "a"))
        self.assertEqual(b"0123", v.head(4))

    def test_head_of_a_missing_file(self):
        d = self.mk()
        with self.assertRaises(files.FileReadError) as cm:
            self.view(d, "nope").head(4)
        self.assertEqual("vanished", cm.exception.reason)

    def test_first_line(self):
        d = self.mk()
        cases = {"a": (b"#!/bin/sh\necho\n", b"#!/bin/sh"), "b": (b"no newline at all", b"no newline at all"), "c": (b"", b""), "d": (b"\nsecond", b""),
                 "e": (b"#!/usr/bin/env\x00 python3\r\nx", b"#!/usr/bin/env python3\r"), "f": (b"\x00\x00\n", b""), "g": (b"a\x00\nb\n", b"a")}
        for name, (content, want) in cases.items():
            write_file(d, name, content)
            self.assertEqual(want, self.view(d, name).first_line(), name)

    def test_first_line_has_no_length_cap(self):
        d = self.mk()
        write_file(d, "long", b"#" * 200000 + b"!python\nrest\n")
        self.assertEqual(b"#" * 200000 + b"!python", self.view(d, "long").first_line())

    def test_has_long_line_equals_the_split_definition(self):
        rnd = random.Random(1)
        d = self.mk()
        for limit in range(1, 21):
            v = self.view(d, "x", long_line_bytes=limit)
            for _ in range(250):
                size = rnd.randint(0, 70)
                weights = rnd.choice((0.02, 0.1, 0.3, 0.6))
                data = bytes(10 if rnd.random() < weights else rnd.choice(b"ab\r") for _ in range(size))
                want = any(len(x) > limit for x in data.split(b"\n"))
                self.assertIs(v.target(data).has_long_line, want, (limit, data))

    def test_has_long_line_boundaries(self):
        d = self.mk()
        for limit in (1, 2, 3, 8, 9, 100, 8192):
            v = self.view(d, "x", long_line_bytes=limit)
            for n in (limit - 1, limit, limit + 1, limit + 2, 2 * limit + 1):
                if n < 0:
                    continue
                for prefix in (b"", b"\n", b"z\n" * 3):
                    for suffix in (b"", b"\n", b"\nq"):
                        data = prefix + b"a" * n + suffix
                        want = any(len(x) > limit for x in data.split(b"\n"))
                        self.assertIs(v.target(data).has_long_line, want, (limit, n, prefix, suffix))

    def test_has_long_line_of_the_file_itself_is_cached(self):
        d = self.mk()
        write_file(d, "long", b"a" * 9000 + b"\n")
        write_file(d, "short", b"a" * 8192 + b"\nb\n")
        self.assertTrue(self.view(d, "long").has_long_line())
        v = self.view(d, "short")
        self.assertFalse(v.has_long_line())
        write_file(d, "short", b"a" * 9000)
        self.assertFalse(v.has_long_line(), "computed once per file")

    def test_flat_folds_cr_lf_tab_and_has_no_cap_r08(self):
        d = self.mk()
        write_file(d, "small", b"a\r\nb\tc\n\x00d")
        self.assertEqual(b"a  b c \x00d", self.view(d, "small").flat())
        body = b'<?xml version="1.0"?>\n<!DOCTYPE a [\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n<a>' + (b"y\r\n" * 1_800_000) + b"</a>\n"
        self.assertGreater(len(body), 5 * 1024 * 1024 + 100000)
        write_file(d, "big.xml", body)
        v = self.view(d, "big.xml")
        flat = v.flat()
        self.assertEqual(len(body), len(flat), "the folded view is not cut and not emptied above 5 MiB")
        self.assertNotIn(b"\n", flat)
        self.assertIsNotNone(rx.ere_to_py(r"<!ENTITY[^>]*SYSTEM", True).search(flat))
        self.assertIs(v.flat(), flat, "cached")

    def test_target_for_the_file_and_for_derived_bytes(self):
        d = self.mk()
        write_file(d, "sub/a.PY", b"x = 1\r\ny\n")
        v = self.view(d, "sub/a.PY", long_line_bytes=100)
        t = v.target()
        self.assertIsInstance(t, Target)
        self.assertEqual((b"x = 1\r\ny\n", "a.PY", "py", False), (t.data, t.basename, t.ext, t.has_long_line))
        self.assertEqual(b"x = 1  y ", t.flat())
        derived = v.target(b"q" * 500)
        self.assertEqual((b"q" * 500, "a.PY", "py", True), (derived.data, derived.basename, derived.ext, derived.has_long_line),
                         "has_long_line is recomputed for derived data")
        self.assertEqual(b"q" * 500, derived.flat())
        self.assertEqual(b"", v.target(b"").data)

    def test_release_drops_every_buffer(self):
        d = self.mk()
        write_file(d, "a", b"one\n")
        v = self.view(d, "a")
        v.data(), v.flat(), v.has_long_line()
        write_file(d, "a", b"two\n")
        v.release()
        self.assertEqual(b"two\n", v.data())
        self.assertEqual(b"two ", v.flat())
        v.release()
        v.release()

    def test_a_view_of_a_file_that_is_a_symlink_is_not_followed(self):
        d = self.mk()
        write_file(d, "target.txt", b"secret")
        os.symlink("target.txt", os.path.join(d, "link.txt"))
        with self.assertRaises(files.FileReadError):
            self.view(d, "link.txt").data()

    def test_peak_memory_of_ninety_megabytes_of_two_byte_lines_is_under_three_times_the_file(self):
        """R-04 / F12: has_long_line must not split the buffer (rx.lines_over peaked at 19 times the input)."""
        d = self.mk()
        path = os.path.join(d, "lines.txt")
        chunk = b"a\n" * (1 << 20)
        with open(path, "wb") as fh:
            for _ in range(45):
                fh.write(chunk)
        child = textwrap.dedent('''
            import os, resource, sys
            root, path = sys.argv[1], sys.argv[2]
            sys.path.insert(0, root)
            size = os.path.getsize(path)
            resource.setrlimit(resource.RLIMIT_AS, (3 * size + 700 * 1024 * 1024,) * 2)
            from transit import files
            from transit.config import Limits
            d, name = os.path.split(path)
            view = files.FileView(d, name, Limits())
            assert len(view.data()) == size
            long_ = view.has_long_line()
            flat_len = len(view.flat())
            first = view.first_line()
            peak = 0
            with open("/proc/self/status") as status:      # VmHWM belongs to the new image; ru_maxrss also counts the parent's size at fork
                for line in status:
                    if line.startswith("VmHWM:"):
                        peak = int(line.split()[1]) * 1024
            if not peak:
                peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            print(size, peak, long_, flat_len, len(first))
        ''')
        out = subprocess.run([sys.executable, "-I", "-c", child, str(ROOT), path], capture_output=True, timeout=300)
        self.assertEqual(0, out.returncode, out.stderr[-800:])
        size, peak, long_, flat_len, first = out.stdout.split()
        self.assertEqual(90 * (1 << 20), int(size))
        self.assertEqual(b"False", long_)
        self.assertEqual(int(size), int(flat_len))
        self.assertLess(int(peak), 3 * int(size), "peak resident size %d MB" % (int(peak) >> 20))


# ── TempArea ───────────────────────────────────────────────────────────────────────────────────────────────────────
class TempAreaTests(TmpCase):
    def test_private_directory_files_and_names(self):
        area = files.TempArea(self.tmp)
        self.addCleanup(area.cleanup)
        self.assertEqual(self.tmp, os.path.dirname(area.path))
        self.assertTrue(os.path.basename(area.path).startswith("aitransit_"))
        self.assertEqual(0o700, stat.S_IMODE(os.stat(area.path).st_mode))
        f1, f2 = area.new_file(".txt"), area.new_file()
        self.assertNotEqual(f1, f2)
        self.assertTrue(f1.endswith(".txt"))
        for f in (f1, f2):
            self.assertEqual(area.path, os.path.dirname(f))
            self.assertEqual(0o600, stat.S_IMODE(os.stat(f).st_mode))
            self.assertEqual(0, os.stat(f).st_size)
            self.assertTrue(stat.S_ISREG(os.lstat(f).st_mode))
        sub = area.new_dir()
        self.assertEqual(area.path, os.path.dirname(sub))
        self.assertEqual(0o700, stat.S_IMODE(os.stat(sub).st_mode))
        self.assertNotEqual(sub, area.new_dir())
        other = files.TempArea(self.tmp)
        self.addCleanup(other.cleanup)
        self.assertNotEqual(area.path, other.path, "unpredictable name per area")

    def test_the_mode_does_not_depend_on_the_umask(self):
        old = os.umask(0)
        try:
            area = files.TempArea(self.tmp)
            self.addCleanup(area.cleanup)
            f, d = area.new_file(), area.new_dir()
            self.assertEqual(0o700, stat.S_IMODE(os.stat(area.path).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.stat(f).st_mode))
            self.assertEqual(0o700, stat.S_IMODE(os.stat(d).st_mode))
        finally:
            os.umask(old)

    def test_cleanup_removes_everything_and_is_idempotent(self):
        area = files.TempArea(self.tmp)
        sub = area.new_dir()
        write_file(sub, "x/y/z.txt", b"data")
        os.chmod(os.path.join(sub, "x", "y"), 0o500)
        os.chmod(os.path.join(sub, "x"), 0o500)
        area.new_file()
        os.symlink("/etc", os.path.join(area.path, "link"))
        area.cleanup()
        self.assertFalse(os.path.lexists(area.path))
        self.assertTrue(os.path.isdir("/etc"), "a symlink inside is removed, never followed")
        area.cleanup()
        self.assertEqual([], [n for n in os.listdir(self.tmp) if n.startswith("aitransit_")])

    def test_context_manager(self):
        with files.TempArea(self.tmp) as area:
            path = area.new_file()
            self.assertTrue(os.path.exists(path))
        self.assertFalse(os.path.exists(area.path))
        with self.assertRaises(RuntimeError):
            with files.TempArea(self.tmp) as area2:
                raise RuntimeError("boom")
        self.assertFalse(os.path.exists(area2.path), "also removed when the block raises")

    def test_an_unwritable_or_missing_tmpdir_raises_oserror(self):
        with self.assertRaises(OSError):
            files.TempArea(os.path.join(self.tmp, "missing"))
        write_file(self.tmp, "afile", b"x")
        with self.assertRaises(OSError):
            files.TempArea(os.path.join(self.tmp, "afile"))

    def test_a_suffix_cannot_make_the_path_escape(self):
        area = files.TempArea(self.tmp)
        self.addCleanup(area.cleanup)
        f = area.new_file(".json")
        self.assertEqual(area.path, os.path.dirname(f))


# ── prepare_work_dirs ──────────────────────────────────────────────────────────────────────────────────────────────
class PrepareWorkDirsTests(TmpCase):
    def test_creates_the_three_directories_with_parents(self):
        work = os.path.join(self.tmp, "a", "b", "work")
        files.prepare_work_dirs(work)
        for name in ("reports", "quarantine", "approved"):
            self.assertTrue(os.path.isdir(os.path.join(work, name)), name)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(os.path.join(work, "quarantine")).st_mode))

    def test_is_idempotent_and_tightens_an_existing_quarantine(self):
        work = os.path.join(self.tmp, "work")
        os.makedirs(os.path.join(work, "quarantine"), mode=0o755)
        os.chmod(os.path.join(work, "quarantine"), 0o755)
        write_file(work, "reports/keep.json", b"{}")
        files.prepare_work_dirs(work)
        files.prepare_work_dirs(work)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(os.path.join(work, "quarantine")).st_mode))
        self.assertTrue(os.path.exists(os.path.join(work, "reports", "keep.json")))

    def test_nothing_else_is_created(self):
        work = os.path.join(self.tmp, "work")
        files.prepare_work_dirs(work)
        self.assertEqual(["approved", "quarantine", "reports"], sorted(os.listdir(work)))

    def test_impossible_is_an_oserror(self):
        write_file(self.tmp, "afile", b"x")
        with self.assertRaises(OSError):
            files.prepare_work_dirs(os.path.join(self.tmp, "afile", "work"))
        work = os.path.join(self.tmp, "w2")
        write_file(work, "reports", b"a file where a directory should be")
        with self.assertRaises(OSError):
            files.prepare_work_dirs(work)


# ── read_repo_config_file ──────────────────────────────────────────────────────────────────────────────────────────
class ReadRepoConfigFileTests(TmpCase):
    def test_a_regular_file(self):
        d = self.mk()
        write_file(d, ".transit-allow.json", b'[{"rule": "x"}]')
        self.assertEqual((b'[{"rule": "x"}]', None), files.read_repo_config_file(d, ".transit-allow.json"))
        write_file(d, ".transitignore", b"")
        self.assertEqual((b"", None), files.read_repo_config_file(d, ".transitignore"))

    def test_absent_is_none_none(self):
        d = self.mk()
        self.assertEqual((None, None), files.read_repo_config_file(d, ".transitignore"))

    def test_exactly_at_the_limit_is_read_and_one_over_is_refused(self):
        d = self.mk()
        write_file(d, "cfg", b"a" * 100)
        self.assertEqual((b"a" * 100, None), files.read_repo_config_file(d, "cfg", max_bytes=100))
        data, note = files.read_repo_config_file(d, "cfg", max_bytes=99)
        self.assertIsNone(data)
        self.assertTrue(note)
        write_file(d, "big", b"a" * ((1 << 20) + 1))
        data, note = files.read_repo_config_file(d, "big")
        self.assertIsNone(data)
        self.assertTrue(note)
        write_file(d, "onemib", b"a" * (1 << 20))
        self.assertEqual(1 << 20, len(files.read_repo_config_file(d, "onemib")[0]))

    def test_a_symlink_is_refused_even_to_a_regular_file_inside(self):
        d = self.mk()
        write_file(d, "real.json", b"[]")
        os.symlink("real.json", os.path.join(d, ".transit-allow.json"))
        data, note = files.read_repo_config_file(d, ".transit-allow.json")
        self.assertIsNone(data)
        self.assertIn(".transit-allow.json", note)
        os.symlink("/nonexistent", os.path.join(d, ".transitignore"))
        data, note = files.read_repo_config_file(d, ".transitignore")
        self.assertIsNone(data)
        self.assertTrue(note, "a dangling link is a refusal, not 'absent'")

    def test_fifo_directory_and_device_never_block_and_are_refused(self):
        d = self.mk()
        os.mkfifo(os.path.join(d, "fifo"))
        os.mkdir(os.path.join(d, "dir"))
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError("blocked on a FIFO")))
        signal.alarm(10)
        try:
            for name in ("fifo", "dir"):
                data, note = files.read_repo_config_file(d, name)
                self.assertIsNone(data, name)
                self.assertTrue(note, name)
        finally:
            signal.alarm(0)

    def test_a_symlink_swapped_in_after_the_check_is_not_followed(self):
        """TOCTOU: lstat said 'regular file', then the name became a link. The open is O_NOFOLLOW, so the link is a refusal."""
        d = self.mk()
        write_file(d, "real.json", b"[]")
        os.symlink("real.json", os.path.join(d, ".transit-allow.json"))
        real_stat = os.stat

        def lying(path, *args, **kwargs):
            if path == ".transit-allow.json" and kwargs.get("dir_fd") is not None:
                return real_stat(os.path.join(d, "real.json"))
            return real_stat(path, *args, **kwargs)
        with mock.patch("os.stat", side_effect=lying):
            data, note = files.read_repo_config_file(d, ".transit-allow.json")
        self.assertIsNone(data)
        self.assertTrue(note)

    def test_a_symlinked_scan_directory_component_inside_the_repo_is_not_followed(self):
        d = self.mk()
        os.makedirs(os.path.join(self.tmp, "elsewhere"))
        write_file(self.tmp, "elsewhere/.transitignore", b"*\n")
        os.symlink("../elsewhere/.transitignore", os.path.join(d, ".transitignore"))
        self.assertIsNone(files.read_repo_config_file(d, ".transitignore")[0])

    def test_unreadable_is_a_note_and_never_raises(self):
        d = self.mk()
        write_file(d, "cfg", b"x")
        real_open = os.open

        def fake(path, flags, mode=0o777, *, dir_fd=None):
            if path == "cfg":
                raise PermissionError(errno.EACCES, "Permission denied")
            return real_open(path, flags, mode, dir_fd=dir_fd)
        with mock.patch("os.open", side_effect=fake):
            data, note = files.read_repo_config_file(d, "cfg")
        self.assertIsNone(data)
        self.assertTrue(note)
        with mock.patch("os.read", side_effect=OSError(errno.EIO, "boom")):
            data, note = files.read_repo_config_file(d, "cfg")
        self.assertIsNone(data)
        self.assertTrue(note)
        data, note = files.read_repo_config_file(os.path.join(self.tmp, "missing"), "cfg")
        self.assertIsNone(data)

    def test_bad_names_are_value_errors(self):
        d = self.mk()
        for name in ("", ".", "..", "a/b", "/etc/passwd", "../x", "a\0b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                files.read_repo_config_file(d, name)

    def test_no_descriptor_is_leaked(self):
        d = self.mk()
        write_file(d, "ok", b"x")
        write_file(d, "big", b"x" * 100)
        os.symlink("ok", os.path.join(d, "ln"))
        before = fd_count()
        for name, mb in (("ok", 10), ("big", 10), ("ln", 10), ("missing", 10), ("big", 50)):
            files.read_repo_config_file(d, name, max_bytes=mb)
        self.assertEqual(before, fd_count())


# ── contained_path ─────────────────────────────────────────────────────────────────────────────────────────────────
class ContainedPathTests(TmpCase):
    def test_absolute_paths(self):
        self.assertEqual("/srv/repo/a.py", files.contained_path("/srv/repo", "/srv/repo/a.py"))
        self.assertEqual("/srv/repo/sub/a.py", files.contained_path("/srv/repo", "/srv/repo/sub/a.py"))
        self.assertEqual("/srv/repo", files.contained_path("/srv/repo", "/srv/repo"))
        self.assertEqual("/srv/repo", files.contained_path("/srv/repo", "/srv/repo/"))
        self.assertIsNone(files.contained_path("/srv/repo", "/srv/other/a.py"))
        self.assertIsNone(files.contained_path("/srv/repo", "/srv/repository/a.py"))
        self.assertIsNone(files.contained_path("/srv/repo", "/srv"))
        self.assertIsNone(files.contained_path("/srv/repo", "/srv/repo/../other/a.py"))
        self.assertEqual("/srv/repo/a.py", files.contained_path("/srv/repo", "/srv/repo/x/../a.py"))

    def test_the_key_keeps_the_spelling_of_the_scan_directory_r13(self):
        """The finding must land under the key of the file's own entry, which is scan_dir + '/' + rel as given."""
        self.assertEqual("/srv//repo/a.py", files.contained_path("/srv//repo", "/srv/repo/a.py"))
        self.assertEqual("/srv/./repo/a.py", files.contained_path("/srv/./repo", "/srv/repo/a.py"))
        self.assertEqual("/srv/x/../repo/a.py", files.contained_path("/srv/x/../repo", "/srv/repo/a.py"))
        self.assertEqual("/srv//repo/sub/a.py", files.contained_path("/srv//repo", "/srv//repo/sub/./a.py"))
        d = self.mk()
        write_file(d, "sub/a.py", b"1")
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.tmp)
        got = scan("repo")
        self.assertEqual(["sub/a.py"], rels(got))
        self.assertEqual(got.entries[0].path, files.contained_path("repo", os.path.join(d, "sub", "a.py")))
        self.assertEqual(got.entries[0].path, files.contained_path("repo", "repo/sub/a.py"), "a relative path is taken relative to the working directory")
        self.assertEqual("repo", files.contained_path("repo", d))
        self.assertIsNone(files.contained_path("repo", os.path.join(self.tmp, "repo2", "a.py")))

    def test_dot_dot_scan_directory(self):
        d = self.mk()
        write_file(d, "a.py", b"1")
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(d)
        self.assertEqual("../repo/a.py", files.contained_path("../repo", os.path.join(d, "a.py")))
        self.assertEqual(scan("../repo").entries[0].path, files.contained_path("../repo", os.path.join(d, "a.py")))

    def test_root_scan_directory(self):
        self.assertEqual("/etc/passwd", files.contained_path("/", "/etc/passwd"))
        self.assertEqual("/", files.contained_path("/", "/"))

    def test_hostile_text_is_only_compared(self):
        self.assertEqual("/s/new\nline", files.contained_path("/s", "/s/new\nline"))
        self.assertEqual("/s/\x1b[0m", files.contained_path("/s", "/s/\x1b[0m"))
        self.assertEqual("/s/\udce9", files.contained_path("/s", "/s/\udce9"))
        self.assertIsNone(files.contained_path("/s", ""), "the working directory is not below /s")


# ── .diff_files ────────────────────────────────────────────────────────────────────────────────────────────────────
class DiffSelectionTests(TmpCase):
    def setUp(self):
        super().setUp()
        self.scan_dir = self.mk("scan")
        self.work = self.mk("work")
        self.base = os.path.abspath(self.scan_dir)

    def diff(self, content: bytes, since="abc", scan_dir=None):
        with open(os.path.join(self.work, ".diff_files"), "wb") as fh:
            fh.write(content)
        return files.load_diff_selection(self.work, since, scan_dir or self.scan_dir)

    def keys(self, *names):
        return frozenset(self.base + "/" + n for n in names)

    def test_no_file_means_not_active(self):
        got = files.load_diff_selection(self.work, "abc", self.scan_dir)
        self.assertEqual((False, frozenset(), False, 0), (got.active, got.keys, got.stale_ignored, got.unresolved))
        got = files.load_diff_selection(self.work, "", self.scan_dir)
        self.assertEqual((False, False), (got.active, got.stale_ignored))

    def test_stale_without_since_commit(self):
        write_file(self.work, ".diff_files", b"a.py\0")
        got = files.load_diff_selection(self.work, "", self.scan_dir)
        self.assertEqual((False, frozenset(), True, 0), (got.active, got.keys, got.stale_ignored, got.unresolved))

    def test_an_empty_file_selects_nothing(self):
        got = self.diff(b"")
        self.assertEqual((True, frozenset(), False, 0), (got.active, got.keys, got.stale_ignored, got.unresolved))

    def test_nul_format(self):
        make_tree(self.scan_dir, {"a.py": b"1", "sub/b:c.py": b"2", "\u00e9.py": b"3", "x$(touch PWNED).py": b"4", "q]r.py": b"5", "plain.py": b"6",
                                  "new\nline.py": b"7"})
        got = self.diff(b"a.py\0sub/b:c.py\0\xc3\xa9.py\0x$(touch PWNED).py\0q]r.py\0gone.py\0new\nline.py\0")
        self.assertEqual(self.keys("a.py", "sub/b:c.py", "\u00e9.py", "x$(touch PWNED).py", "q]r.py", "new\nline.py"), got.keys)
        self.assertEqual((True, 0), (got.active, got.unresolved))
        self.assertFalse(os.path.exists("PWNED"))

    def test_nul_format_last_item_without_terminator_and_empty_items(self):
        make_tree(self.scan_dir, {"a.py": b"1", "sub/b:c.py": b"2"})
        got = self.diff(b"a.py\0\0\0sub/b:c.py")
        self.assertEqual(self.keys("a.py", "sub/b:c.py"), got.keys)

    def test_nul_format_equals_the_script(self):
        make_tree(self.scan_dir, {"a.py": b"1", "sub/b:c.py": b"2", "\u00e9.py": b"3", "q]r.py": b"5", "d/e/f.py": b"6", "sp ace.py": b"7", "-x.py": b"8"})
        os.symlink("a.py", os.path.join(self.scan_dir, "link.py"))
        os.mkdir(os.path.join(self.scan_dir, "adir"))
        content = b"a.py\0sub/b:c.py\0\xc3\xa9.py\0q]r.py\0d/e/f.py\0sp ace.py\0-x.py\0gone.py\0adir\0link.py\0./a.py\0d/../a.py\0d//e/f.py\0\0"
        got = self.diff(content)
        on, want = bash_diff(self.scan_dir, self.work, "abc")
        self.assertTrue(on)
        self.assertTrue({os.path.abspath(k) for k in want if os.path.isfile(k) and not os.path.islink(k)} <= got.keys,
                        "everything the script selects is selected (a symlink never matches a listed file, so it is no loss)")
        self.assertTrue(self.keys("a.py", "sub/b:c.py", "\u00e9.py", "q]r.py", "d/e/f.py", "sp ace.py", "-x.py") <= got.keys)
        self.assertNotIn(self.base + "/link.py", got.keys, "a symlink is never listed, so it is not a key")
        self.assertNotIn(self.base + "/adir", got.keys)
        self.assertNotIn(self.base + "/gone.py", got.keys)

    def test_a_name_that_leaves_the_scan_directory_is_no_key(self):
        write_file(self.tmp, "outside.py", b"1")
        write_file(self.scan_dir, "in.py", b"1")
        got = self.diff(b"../outside.py\0in.py\0/etc/passwd\0../scan/in.py\0")
        for key in got.keys:
            self.assertTrue(key.startswith(self.base + "/"), key)
        self.assertIn(self.base + "/in.py", got.keys)
        self.assertNotIn(self.tmp + "/outside.py", got.keys)

    def test_legacy_colon_format(self):
        make_tree(self.scan_dir, {"a.py": b"1", "plain.py": b"2", "sub/x.py": b"3"})
        sd = self.scan_dir
        got = self.diff(("%s/a.py:%s/plain.py:\n" % (sd, sd)).encode())
        self.assertEqual((True, self.keys("a.py", "plain.py"), 0), (got.active, got.keys, got.unresolved))
        got = self.diff(("%s/a.py:%s/plain.py" % (sd, sd)).encode())
        self.assertEqual(self.keys("a.py"), got.keys, "the last entry without its colon is dropped, as in bash")
        got = self.diff(("%s/gone.py:%s/sub/x.py:" % (sd, sd)).encode())
        self.assertEqual((self.keys("sub/x.py"), 0), (got.keys, got.unresolved), "a deleted file is not an entry and not a problem")
        got = self.diff(("%s/no_such_file.py:" % sd).encode())
        self.assertEqual((True, frozenset(), 0), (got.active, got.keys, got.unresolved))

    def test_legacy_format_equals_the_script_for_plain_names(self):
        make_tree(self.scan_dir, {"a.py": b"1", "plain.py": b"2", "sub/x.py": b"3"})
        sd = self.scan_dir
        content = ("%s/a.py:%s/plain.py:%s/gone.py:%s/sub/x.py:%s/sub:%s/a.py:%s/sub/../a.py:\n" % ((sd,) * 7)).encode()
        got = self.diff(content)
        on, want = bash_diff(self.scan_dir, self.work, "abc")
        self.assertTrue(on)
        self.assertEqual({os.path.abspath(k) for k in want}, set(got.keys))

    def test_a_colon_in_a_name_is_rebuilt_from_the_pieces(self):
        make_tree(self.scan_dir, {"a:b.py": b"1", "sub/x:y:z.py": b"2", "p.py": b"3", "end:": b"4"})
        sd = self.scan_dir
        got = self.diff(("%s/a:b.py:%s/sub/x:y:z.py:%s/p.py:%s/end::" % (sd, sd, sd, sd)).encode())
        self.assertEqual(self.keys("a:b.py", "sub/x:y:z.py", "p.py", "end:"), got.keys)
        self.assertEqual(0, got.unresolved)

    def test_a_name_with_fifteen_colons_is_rebuilt_and_one_with_sixteen_is_not(self):
        name15 = ":".join("p%d" % i for i in range(16))
        name16 = ":".join("q%d" % i for i in range(17))
        make_tree(self.scan_dir, {name15: b"1", name16: b"2"})
        got = self.diff(("%s/%s:" % (self.scan_dir, name15)).encode())
        self.assertEqual(self.keys(name15), got.keys)
        self.assertEqual(0, got.unresolved)
        got = self.diff(("%s/%s:" % (self.scan_dir, name16)).encode())
        self.assertEqual(frozenset(), got.keys)
        self.assertGreater(got.unresolved, 0)

    def test_a_deleted_file_with_a_colon_is_counted_and_has_no_key(self):
        make_tree(self.scan_dir, {"ok.py": b"1"})
        got = self.diff(("%s/gone:thing.py:%s/ok.py:" % (self.scan_dir, self.scan_dir)).encode())
        self.assertEqual(self.keys("ok.py"), got.keys)
        self.assertEqual(1, got.unresolved, "the fragment 'thing.py' could not be rebuilt: a rare false alarm, and visible")

    def test_git_quoted_names_are_unquoted(self):
        make_tree(self.scan_dir, {"\u00e9.py": b"1", "sub/\u00e9\u00e8.py": b"2", "tab\tname.py": b"3", 'q"uote.py': b"4", "back\\slash.py": b"5",
                                  "a:\u00e9.py": b"6", "nl\nname.py": b"7", b"bad\xff.py": b"8"})
        sd = self.scan_dir
        pieces = ['%s/"\\303\\251.py"' % sd, '%s/"sub/\\303\\251\\303\\250.py"' % sd, '%s/"tab\\tname.py"' % sd, '%s/"q\\"uote.py"' % sd,
                  '%s/"back\\\\slash.py"' % sd, '%s/"a:\\303\\251.py"' % sd, '%s/"nl\\nname.py"' % sd, '%s/"bad\\377.py"' % sd]
        got = self.diff((":".join(pieces) + ":").encode())
        self.assertEqual(self.keys("\u00e9.py", "sub/\u00e9\u00e8.py", "tab\tname.py", 'q"uote.py', "back\\slash.py", "a:\u00e9.py", "nl\nname.py",
                                   "bad\udcff.py"), got.keys)
        self.assertEqual(0, got.unresolved)

    def test_a_malformed_quote_is_not_a_key_and_does_not_raise(self):
        make_tree(self.scan_dir, {"ok.py": b"1"})
        sd = self.scan_dir
        for bad in ('%s/"unterminated' % sd, '%s/"a"b"' % sd, '%s/"\\' % sd, '%s/"\\9"' % sd, '%s/""' % sd):
            got = self.diff((bad + ":%s/ok.py:" % sd).encode())
            self.assertEqual(self.keys("ok.py"), got.keys, bad)

    def test_unreadable_or_not_a_regular_file_gives_active_with_one_unresolved(self):
        os.mkdir(os.path.join(self.work, ".diff_files"))
        got = files.load_diff_selection(self.work, "abc", self.scan_dir)
        self.assertEqual((True, frozenset(), 1), (got.active, got.keys, got.unresolved))
        os.rmdir(os.path.join(self.work, ".diff_files"))
        write_file(self.work, ".diff_files", b"a.py\0")
        with mock.patch("builtins.open", side_effect=PermissionError(errno.EACCES, "no")), mock.patch("os.open", side_effect=PermissionError(errno.EACCES, "no")):
            got = files.load_diff_selection(self.work, "abc", self.scan_dir)
        self.assertEqual((True, frozenset(), 1), (got.active, got.keys, got.unresolved))

    def test_a_hostile_list_is_bounded_and_never_raises(self):
        make_tree(self.scan_dir, {"ok.py": b"1"})
        started = time.monotonic()
        got = self.diff(b":" * 300000)
        self.assertEqual(frozenset(), got.keys)
        got = self.diff(b"\0" * 300000 + b"ok.py\0")
        self.assertEqual(self.keys("ok.py"), got.keys)
        got = self.diff((self.scan_dir + "/x:").encode() * 20000)
        self.assertEqual(frozenset(), got.keys)
        got = self.diff(b"\xff\xfe\0" * 1000 + b"\0" + b"a" * 100000)
        self.assertEqual(frozenset(), got.keys)
        self.assertLess(time.monotonic() - started, 30.0)

    def test_a_key_below_path_max_is_resolved(self):
        fd = os.open(self.scan_dir, os.O_RDONLY | os.O_DIRECTORY)
        names = []
        try:
            for i in range(102):
                name = ("%03d" % i).ljust(50, "d")
                names.append(name)
                os.mkdir(name, dir_fd=fd)
                nfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = nfd
            os.close(os.open("leaf.py", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd))
        finally:
            os.close(fd)
        rel = "/".join(names + ["leaf.py"])
        got = self.diff(rel.encode() + b"\0")
        self.assertEqual(frozenset({self.base + "/" + rel}), got.keys)

    def test_relative_scan_directory_keys_are_absolute_d019(self):
        make_tree(self.scan_dir, {"a.py": b"1"})
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.tmp)
        got = self.diff(b"a.py\0", scan_dir="scan")
        self.assertEqual(frozenset({self.base + "/a.py"}), got.keys)
        got = self.diff(("%s/a.py:" % self.scan_dir).encode(), scan_dir="./scan/")
        self.assertEqual(frozenset({self.base + "/a.py"}), got.keys)

    def test_the_selection_selects_what_files_for_scan_lists(self):
        make_tree(self.scan_dir, {"a.py": b"1", "sub/b:c.py": b"2", "\u00e9.py": b"3", "other.py": b"4"})
        got = self.diff(b"a.py\0sub/b:c.py\0\xc3\xa9.py\0gone.py\0")
        listed = scan(self.scan_dir, diff=got)
        self.assertEqual(["a.py", "sub/b:c.py", "\u00e9.py"], rels(listed))


# ── compute_hashes ─────────────────────────────────────────────────────────────────────────────────────────────────
def recipe_sha256(scan_dir: str) -> str:
    cmd = 'cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum | cut -d" " -f1'
    return subprocess.run([BASH, "-c", "set -o pipefail; " + cmd, "recipe", scan_dir], capture_output=True, env=ENV_C, check=True).stdout.decode().strip()


def recipe_repo_hash(scan_dir: str) -> str:
    cmd = 'find "$1" -type f | sort | sha256sum | cut -d" " -f1'
    return subprocess.run([BASH, "-c", cmd, "recipe", scan_dir], capture_output=True, env=ENV_C, check=True).stdout.decode().strip()


@unittest.skipUnless(HAVE_ORACLE and shutil.which("sha256sum") and shutil.which("sort") and shutil.which("xargs"), "needs the shell recipe tools")
class ComputeHashesTests(TmpCase):
    def test_the_three_e19_values_of_the_golden_files(self):
        for name in ("clean", "vulnerable", "allowlisted"):
            golden = json.loads((GOLDEN / (name + ".json")).read_text())["report"]["source"]["sha256"]
            got = files.compute_hashes(str(FIXTURES / name))
            self.assertEqual(golden, got.sha256, name)
            self.assertEqual(recipe_repo_hash(str(FIXTURES / name)), got.repo_hash, name)

    def test_equals_the_recipe_on_a_tree_with_hostile_names(self):
        d = self.mk()
        names = [b"plain.txt", b"sp ace", b"back\\slash", b"new\nline", b"cr\rname", b"tab\tname", "\u00e9.py".encode(), b"bad\xff.py", b".hidden",
                 b"sub/dir/f", b"a.b", b"a/b", b"a-b", b"a0", b"A", b".git/HEAD", b".git/objects/ab/cdef", b"empty", b"x\\ny", b"\\", b"-n", b"~",
                 b"node_modules/m/index.js", b"build/out", b".transitignore", b".manifest_sha256.txt", b"sub/.manifest_sha256.txt", b"a/b.c/d"]
        for n in names:
            write_file(d, n, n + b"\n" if n != b"empty" else b"")
        os.symlink("plain.txt", os.path.join(d, "link"))
        os.symlink("sub", os.path.join(d, "dirlink"))
        os.mkfifo(os.path.join(d, "fifo"))
        got = files.compute_hashes(d)
        self.assertEqual(recipe_sha256(d), got.sha256)
        self.assertEqual(64, len(got.repo_hash))

    def test_the_escaped_form_for_a_backslash_and_a_newline(self):
        d = self.mk()
        write_file(d, b"a\\b", b"1")
        write_file(d, b"c\nd", b"2")
        write_file(d, b"e", b"3")
        want = hashlib.sha256(b"".join([
            b"\\" + hashlib.sha256(b"1").hexdigest().encode() + b"  ./a\\\\b\n",
            b"\\" + hashlib.sha256(b"2").hexdigest().encode() + b"  ./c\\nd\n",
            hashlib.sha256(b"3").hexdigest().encode() + b"  ./e\n"])).hexdigest()
        self.assertEqual(want, files.compute_hashes(d).sha256)

    def test_sort_is_by_the_bytes_of_the_whole_name(self):
        d = self.mk()
        items = [(b"a.b", b"1"), (b"a/b", b"2"), (b"a-b", b"3"), (b"a0", b"4"), (b"B", b"5"), (b"\xc3\xa9", b"6"), (b"a_", b"7x"), (b".z", b"8")]
        for name, data in items:
            write_file(d, name, data)
        got = files.compute_hashes(d)
        self.assertEqual(recipe_sha256(d), got.sha256)
        lines = b"".join(hashlib.sha256(data).hexdigest().encode() + b"  ./" + name + b"\n" for name, data in sorted(items, key=lambda x: x[0]))
        self.assertEqual(hashlib.sha256(lines).hexdigest(), got.sha256)

    def test_repo_hash_is_the_sorted_list_of_paths(self):
        d = self.mk()
        make_tree(d, {"b/x": b"1", "a.py": b"2", "a/z": b"3", ".h": b"4", "sp ace": b"5", "B": b"6"})
        os.symlink("a.py", os.path.join(d, "link"))
        got = files.compute_hashes(d)
        self.assertEqual(recipe_repo_hash(d), got.repo_hash)
        lines = "".join(d + "/" + r + "\n" for r in sorted_bytes(["b/x", "a.py", "a/z", ".h", "sp ace", "B"]))
        self.assertEqual(hashlib.sha256(lines.encode()).hexdigest(), got.repo_hash)

    def test_repo_hash_sorts_bytes_not_code_points(self):
        """U+FF01 is EF BC 81 and an escaped 0xFF byte is U+DCFF: by code point the byte sorts first, by bytes it sorts last."""
        d = self.mk()
        for name in ("\uff01.py".encode(), b"\xfftail", b"plain", "\u00e9".encode(), b"\xc3\xa9z", "\U0001f600".encode()):
            write_file(d, name, b"1")
        got = files.compute_hashes(d)
        self.assertEqual(recipe_repo_hash(d), got.repo_hash)
        self.assertEqual(recipe_sha256(d), got.sha256)

    def test_it_depends_on_content_not_only_on_names(self):
        d = self.mk()
        write_file(d, "a", b"1")
        first = files.compute_hashes(d)
        write_file(d, "a", b"2")
        second = files.compute_hashes(d)
        self.assertNotEqual(first.sha256, second.sha256)
        self.assertEqual(first.repo_hash, second.repo_hash)

    def test_no_exclusion_applies(self):
        d = self.mk()
        make_tree(d, {".git/x": b"1", "node_modules/y": b"2", "docs/z": b"3", ".transitignore": b"*\ndocs\n"})
        self.assertEqual(recipe_sha256(d), files.compute_hashes(d).sha256)

    def test_empty_directory(self):
        d = self.mk()
        empty = hashlib.sha256(b"").hexdigest()
        got = files.compute_hashes(d)
        self.assertEqual((empty, empty), (got.sha256, got.repo_hash))
        self.assertEqual(recipe_sha256(d), got.sha256)

    def test_large_and_chunked_files(self):
        d = self.mk()
        data = os.urandom(1 << 20) * 3 + b"tail"
        write_file(d, "big.bin", data)
        write_file(d, "z", b"")
        self.assertEqual(recipe_sha256(d), files.compute_hashes(d).sha256)

    def test_a_file_that_cannot_be_read_falls_back_to_the_repo_hash(self):
        d = self.mk()
        make_tree(d, {"a": b"1", "b": b"2"})
        real = files.open_beneath

        def fake(scan_dir, rel):
            if rel == "b":
                raise files.FileReadError("permission")
            return real(scan_dir, rel)
        with mock.patch.object(files, "open_beneath", side_effect=fake):
            got = files.compute_hashes(d)
        self.assertEqual(got.repo_hash, got.sha256)
        self.assertNotEqual(files.compute_hashes(d).sha256, got.sha256)

    def test_an_unlistable_directory_falls_back_to_the_repo_hash(self):
        d = self.mk()
        make_tree(d, {"a": b"1", "locked/b": b"2"})
        real_scandir = os.scandir

        def fake(arg):
            if isinstance(arg, int) and os.readlink("/proc/self/fd/%d" % arg).endswith("/locked"):
                raise PermissionError(errno.EACCES, "no")
            return real_scandir(arg)
        with mock.patch("os.scandir", side_effect=fake):
            got = files.compute_hashes(d)
        self.assertEqual(got.repo_hash, got.sha256)

    def test_a_missing_directory_does_not_raise(self):
        got = files.compute_hashes(os.path.join(self.tmp, "missing"))
        self.assertEqual(64, len(got.sha256))
        self.assertEqual(got.repo_hash, got.sha256)

    def test_hash_fields_are_lower_case_hex(self):
        d = self.mk()
        write_file(d, "a", b"1")
        got = files.compute_hashes(d)
        for value in (got.sha256, got.repo_hash):
            self.assertRegex(value, r"^[0-9a-f]{64}$")
        self.assertEqual(["sha256", "repo_hash"], [f.name for f in dataclasses.fields(files.SourceHashes)])

    def test_the_scan_directory_with_a_trailing_slash_and_the_root_spelling(self):
        d = self.mk()
        make_tree(d, {"a": b"1"})
        self.assertEqual(files.compute_hashes(d).sha256, files.compute_hashes(d + "/").sha256)


# ── what the module may not do ─────────────────────────────────────────────────────────────────────────────────────
class SourceRulesTests(unittest.TestCase):
    SOURCE = (ROOT / "transit" / "files.py").read_text(encoding="utf-8")
    TREE = ast.parse(SOURCE)

    def test_no_regular_expression_is_compiled_here(self):
        for node in ast.walk(self.TREE):
            if isinstance(node, ast.Import):
                self.assertNotIn("re", [a.name for a in node.names])
            if isinstance(node, ast.ImportFrom):
                self.assertNotEqual("re", node.module)

    def test_no_helper_that_splits_a_whole_buffer(self):
        for node in ast.walk(self.TREE):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("lines_over", "after_context", "splitlines"), "line %d" % node.lineno)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "split":
                self.assertFalse(node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in (b"\n", "\n"),
                                 "a whole-buffer split at line %d" % node.lineno)

    def test_no_shell_and_no_dynamic_code(self):
        for node in ast.walk(self.TREE):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                self.assertFalse([n for n in names if n.split(".")[0] in ("subprocess", "pickle", "marshal", "ctypes")], "line %d" % node.lineno)
            if isinstance(node, ast.keyword):
                self.assertNotEqual("shell", node.arg)
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("system", "popen", "spawnv", "execv"), "line %d" % node.lineno)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, ("eval", "exec", "compile", "__import__"), "line %d" % node.lineno)

    def test_the_frozen_names_are_there(self):
        for name in ("MAX_WALK_DEPTH", "MAX_GLOB_PATTERNS", "MAX_PATTERN_CHARS", "GLOB_METACHARS", "FileReadError", "FileEntry", "FileView", "TempArea",
                     "Exclusions", "DiffSelection", "ScanList", "SourceHashes", "open_beneath", "prepare_work_dirs", "read_repo_config_file",
                     "contained_path", "glob_match", "load_exclusions", "load_diff_selection", "files_for_scan", "compute_hashes"):
            self.assertTrue(hasattr(files, name), name)
        self.assertEqual(["path", "rel", "size"], [f.name for f in dataclasses.fields(files.FileEntry)])
        self.assertEqual(["active", "keys", "stale_ignored", "unresolved"], [f.name for f in dataclasses.fields(files.DiffSelection)])
        self.assertEqual(["entries", "errors", "excluded_by_patterns"], [f.name for f in dataclasses.fields(files.ScanList)][:3])
        for f in dataclasses.fields(files.ScanList)[3:]:
            self.assertIsNot(f.default, dataclasses.MISSING, "an additive field of ScanList has a default: " + f.name)


if __name__ == "__main__":
    unittest.main()
