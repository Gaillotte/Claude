"""Tests of transit/dispatch.py (WP-05): which scanner a file goes to (contract 8.8 rules 2 to 5). Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_dispatch.py"

The route tables are compared with ``build_pdf_filetypes`` (``routed_patterns``, ``FAMILIES``), the probes (``_rtf_head``,
``_flat_office_head``), the extension lower-casing and the shebang routing with the REAL bash functions of ``scan_pipeline.sh`` (extracted
as text and run in ``bash``, in the C locale like the hardened script), and ``classify_file`` with a recording ``run`` callback over real
files. A token-shaped credential is never written contiguously in this file.
"""
from __future__ import annotations

import fnmatch
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import build_pdf_filetypes  # noqa: E402
from tests.engine import support  # noqa: E402
from transit import dispatch  # noqa: E402
from transit.scanners import KNOWN_SCANNERS  # noqa: E402

BASH = shutil.which("bash")
SCANNER_SH = ROOT / "scan_pipeline.sh"
NEEDS_BASH = unittest.skipUnless(BASH, "bash is not installed")


def bash_function(name: str) -> str:
    """The text of the bash function ``name`` as written in scan_pipeline.sh (from ``name() {`` to the first line that is just ``}``)."""
    lines = SCANNER_SH.read_text(encoding="utf-8").split("\n")
    start = lines.index(name + "() {")
    end = lines.index("}", start)
    return "\n".join(lines[start:end + 1])


def run_bash(script: str, stdin: bytes = b"") -> bytes:
    """Run ``script`` in bash exactly as the pipeline does (C locale, errexit, nounset, pipefail); return stdout."""
    env = {"LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    proc = subprocess.run([BASH, "-c", "set -euo pipefail\n" + script], input=stdin, capture_output=True, env=env, timeout=120, check=False)
    if proc.returncode != 0:
        raise AssertionError("bash oracle failed (%d): %s" % (proc.returncode, proc.stderr.decode("utf-8", "replace")))
    return proc.stdout


def classify(test: unittest.TestCase, rel: str, data: "bytes | str" = b"", results: "dict | None" = None) -> "list[tuple[str, bool]]":
    """The ``(scanner id, sniffed)`` calls ``classify_file`` makes for a file ``rel`` holding ``data``. ``results`` maps an id to what ``run``
    answers for it (default True: a scanner that handled the file)."""
    repo = support.TempRepo({rel: data})
    test.addCleanup(repo.cleanup)
    calls: "list[tuple[str, bool]]" = []

    def run(scanner_id: str, sniffed: bool) -> bool:
        calls.append((scanner_id, sniffed))
        return (results or {}).get(scanner_id, True)

    dispatch.classify_file(repo.view(rel), run)
    return calls


RTF = b"{\\rtf1\\ansi\\deff0 {\\fonttbl{\\f0 Arial;}} hello}"
FLAT_OPC = b'<?xml version="1.0"?><pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage"/>'
WORDML = b'<w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml"/>'
EXCEL2003 = b'<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"/>'


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RouteTableTests(unittest.TestCase):
    def test_routed_patterns_equals_the_deck_oracle(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)      # build_pdf_filetypes leaves scan_pipeline.sh open
            exts, bases = build_pdf_filetypes.routed_patterns()
        mine_exts, mine_bases = dispatch.routed_patterns()
        self.assertEqual(mine_exts, exts)
        self.assertEqual(mine_bases, bases)
        self.assertIsInstance(mine_exts, set)
        self.assertIsInstance(mine_bases, set)

    def test_counts_and_shapes(self) -> None:
        exts, bases = dispatch.routed_patterns()
        self.assertEqual(len(exts), 109)
        self.assertEqual(len(bases), 7)
        self.assertTrue(all(e.startswith(".") and e == e.lower() for e in exts))
        self.assertIn("Makefile*|makefile*|GNUmakefile*", bases)
        self.assertIn("CMakeLists.txt|CMakeLists.*.txt", bases)
        self.assertEqual(len(dispatch.BASENAME_ROUTES), 7)

    def test_every_routed_id_is_a_known_scanner_and_every_known_scanner_but_unknown_is_routed(self) -> None:
        routed = set(dispatch.EXT_ROUTES.values()) | {scanner_id for _, scanner_id in dispatch.BASENAME_ROUTES}
        self.assertLessEqual(routed, set(KNOWN_SCANNERS))
        self.assertEqual(set(KNOWN_SCANNERS) - routed, {"unknown"})
        for _, scanner_id in dispatch.SHEBANG_ROUTES:
            self.assertIn(scanner_id, KNOWN_SCANNERS)

    def test_the_34_family_keys(self) -> None:
        keys = {f["key"] for f in build_pdf_filetypes.FAMILIES}
        self.assertEqual(len(keys), 34)
        routed = set(dispatch.EXT_ROUTES.values()) | {scanner_id for _, scanner_id in dispatch.BASENAME_ROUTES}
        self.assertEqual({KNOWN_SCANNERS[i] for i in routed}, keys)
        self.assertEqual({v for v in KNOWN_SCANNERS.values()} - {"unknown"}, keys)

    def test_per_family_extension_and_basename_sets_equal_the_deck(self) -> None:
        for fam in build_pdf_filetypes.FAMILIES:
            key = fam["key"]
            exts = {e for e, i in dispatch.EXT_ROUTES.items() if KNOWN_SCANNERS[i] == key}
            bases = {"|".join(p) for p, i in dispatch.BASENAME_ROUTES if KNOWN_SCANNERS[i] == key}
            self.assertEqual(exts, set(fam.get("ext", [])), "extensions of the family %s" % key)
            self.assertEqual(bases, set(fam.get("base", [])), "basename arms of the family %s" % key)

    def test_the_shebang_table_matches_the_deck(self) -> None:
        # build_pdf_filetypes lists the shebang routes of scan_unknown by scanner function; the ids map onto the same families
        ids = [i for _, i in dispatch.SHEBANG_ROUTES]
        self.assertEqual(ids, ["python"] + ["shell"] * 6 + ["ruby", "js", "php", "powershell.text", "powershell.text"])
        self.assertEqual(dispatch.RTF_SNIFFED_EXTS, frozenset({".md", ".txt", ".rst"}))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class LowerExtTests(unittest.TestCase):
    def test_examples(self) -> None:
        self.assertEqual(dispatch.lower_ext("/a/b/UPPER.PY"), ".py")
        self.assertEqual(dispatch.lower_ext("/a/b/x.tar.GZ"), ".gz")
        self.assertEqual(dispatch.lower_ext("/s/.py"), ".py")
        self.assertEqual(dispatch.lower_ext("/s/a."), ".")
        self.assertEqual(dispatch.lower_ext("a.PS1XML"), ".ps1xml")

    def test_no_dot_is_the_dot_and_the_whole_path(self) -> None:
        self.assertEqual(dispatch.lower_ext("Makefile"), ".makefile")
        self.assertEqual(dispatch.lower_ext("/s/Makefile"), "./s/makefile")
        # the text after the LAST dot of the FULL path: a dotted directory with a dotless file never looks like an extension
        self.assertEqual(dispatch.lower_ext("/srv/x.d/Makefile"), ".d/makefile")
        self.assertNotIn(dispatch.lower_ext("/srv/repo.py/README"), dispatch.EXT_ROUTES)

    def test_only_ascii_is_lowered(self) -> None:
        # the hardened script runs with LC_ALL=C: ${ext,,} changes A-Z only. str.lower would turn the Kelvin sign into k and route
        # ".<KELVIN>t" to the Kotlin scanner.
        self.assertEqual(dispatch.lower_ext("/s/x.\u212at"), ".\u212at")
        self.assertEqual(dispatch.lower_ext("/s/x.\u0130"), ".\u0130")
        self.assertEqual(dispatch.lower_ext("/s/x.\u00c4"), ".\u00c4")

    @NEEDS_BASH
    def test_equals_bash_in_the_c_locale(self) -> None:
        paths = ["/s/UPPER.PY", "/s/x.tar.GZ", "/s/.hidden", "/s/Makefile", "/srv/x.d/Makefile", "/s/a.", "/s/x.\u212at", "/s/x.\u0130",
                 "/s/x.\u00c4\u00d6", "/s/x.PS1XML", "/s/\udcff.PY", "/s/a b.C", "/s/new\nline.JS", "rel.JAR", "/s/dot.in.dir/F.Sh"]
        stdin = b"".join(os.fsencode(p) + b"\0" for p in paths)
        out = run_bash('while IFS= read -r -d "" f; do ext="${f##*.}"; ext="${ext,,}"; printf ".%s\\0" "$ext"; done', stdin)
        expected = out.split(b"\0")[:-1]
        self.assertEqual(len(expected), len(paths))
        for path, want in zip(paths, expected):
            self.assertEqual(os.fsencode(dispatch.lower_ext(path)), want, repr(path))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ProbeTests(unittest.TestCase):
    """``rtf_head`` and ``flat_office_head`` on real files, against the bash ``_rtf_head`` and ``_flat_office_head``."""

    RTF_CASES = {
        "plain": RTF,
        "leading_space": b"   " + RTF,
        "leading_mixed_whitespace": b" \t\r\n\x0b\x0c" + RTF,
        "eleven_spaces_then_rtf": b" " * 11 + b"{\\rtf",
        "twelve_spaces_then_rtf": b" " * 12 + b"{\\rtf",
        "sixteen_spaces_then_rtf": b" " * 16 + RTF,
        "mention_not_at_the_start": b"see {\\rtf1 for details",
        "script_comment": b"#!/bin/sh\n# {\\rtf\n",
        "too_short": b"{\\rt",
        "exactly_the_marker": b"{\\rtf",
        "uppercase": b"{\\RTF1\\ansi",
        "empty": b"",
        "bom_first": b"\xef\xbb\xbf" + RTF,
        "nul_prefix": b"\0\0\0" + RTF,
        "nul_inside": b"{\0\\\0r\0t\0f\0" + b"1 text",
        "nul_between_whitespace": b" \0 \0\t\0" + RTF,
        "only_whitespace": b" \n\n\t " * 5,
        "binary_noise": bytes(range(1, 40)),
    }

    FLAT_CASES = {
        "flat_opc": FLAT_OPC,
        "wordml": WORDML,
        "excel2003": EXCEL2003,
        "plain_xml": b'<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0"/>',
        "marker_cut_at_8192": b"x" * (8192 - 20) + b"schemas.microsoft.com/office/2006/xmlPackage",
        "marker_ends_at_8192": b"x" * (8192 - 44) + b"schemas.microsoft.com/office/2006/xmlPackage",
        "marker_after_8192": b"x" * 8200 + b"schemas.microsoft.com/office/2006/xmlPackage",
        "utf16_with_nuls": "<?xml version='1.0'?><w:wordDocument xmlns:w='http://schemas.microsoft.com/office/word/2003/wordml'/>".encode("utf-16-le"),
        "nul_padding_before_marker": b"\0" * 20000 + EXCEL2003,
        "nuls_do_not_count": (b"a\0" * 4000) + WORDML,
        "nuls_then_too_many_bytes": (b"a" * 8180) + b"\0" * 100 + b"schemas.microsoft.com/office/2006/xmlPackage",
        "empty": b"",
    }

    def _repo(self, cases: "dict[str, bytes]") -> support.TempRepo:
        repo = support.TempRepo({name + ".bin": data for name, data in cases.items()})
        self.addCleanup(repo.cleanup)
        return repo

    def test_rtf_head_examples(self) -> None:
        repo = self._repo(self.RTF_CASES)
        expected = {"plain": True, "leading_space": True, "leading_mixed_whitespace": True, "eleven_spaces_then_rtf": True,
                    "twelve_spaces_then_rtf": False, "sixteen_spaces_then_rtf": False, "mention_not_at_the_start": False,
                    "script_comment": False, "too_short": False, "exactly_the_marker": True, "uppercase": False, "empty": False,
                    "bom_first": False, "nul_prefix": True, "nul_inside": True, "nul_between_whitespace": True,
                    "only_whitespace": False, "binary_noise": False}
        self.assertEqual(set(expected), set(self.RTF_CASES))
        for name, want in expected.items():
            self.assertIs(dispatch.rtf_head(repo.view(name + ".bin")), want, name)

    def test_flat_office_head_examples(self) -> None:
        repo = self._repo(self.FLAT_CASES)
        expected = {"flat_opc": True, "wordml": True, "excel2003": True, "plain_xml": False, "marker_cut_at_8192": False,
                    "marker_ends_at_8192": True, "marker_after_8192": False, "utf16_with_nuls": True, "nul_padding_before_marker": True,
                    "nuls_do_not_count": True, "nuls_then_too_many_bytes": False, "empty": False}
        self.assertEqual(set(expected), set(self.FLAT_CASES))
        for name, want in expected.items():
            self.assertIs(dispatch.flat_office_head(repo.view(name + ".bin")), want, name)

    def test_the_probes_work_on_a_view_whose_data_is_already_read(self) -> None:
        repo = support.TempRepo({"a.bin": b"\0\0" + RTF, "b.bin": b"\0" * 5000 + FLAT_OPC})
        self.addCleanup(repo.cleanup)
        for rel, probe in (("a.bin", dispatch.rtf_head), ("b.bin", dispatch.flat_office_head)):
            fresh = repo.view(rel)
            warm = repo.view(rel)
            warm.data()
            self.assertTrue(probe(fresh))
            self.assertTrue(probe(warm))

    def test_a_huge_nul_prefix_costs_a_bounded_read(self) -> None:
        repo = support.TempRepo({"nul.bin": b"\0" * (3 << 20) + RTF})
        self.addCleanup(repo.cleanup)
        self.assertTrue(dispatch.rtf_head(repo.view("nul.bin")))

    @NEEDS_BASH
    def test_probes_equal_bash(self) -> None:
        rtf_repo = self._repo(self.RTF_CASES)
        names = sorted(self.RTF_CASES)
        stdin = b"".join(os.fsencode(rtf_repo.path + "/" + n + ".bin") + b"\0" for n in names)
        script = bash_function("_rtf_head") + '\nwhile IFS= read -r -d "" f; do if _rtf_head "$f"; then printf T; else printf F; fi; done'
        got = run_bash(script, stdin).decode()
        self.assertEqual(len(got), len(names))
        for name, flag in zip(names, got):
            self.assertIs(dispatch.rtf_head(rtf_repo.view(name + ".bin")), flag == "T", "_rtf_head " + name)

        flat_repo = self._repo(self.FLAT_CASES)
        names = sorted(self.FLAT_CASES)
        stdin = b"".join(os.fsencode(flat_repo.path + "/" + n + ".bin") + b"\0" for n in names)
        script = bash_function("_flat_office_head") + \
            '\nwhile IFS= read -r -d "" f; do if _flat_office_head "$f"; then printf T; else printf F; fi; done'
        got = run_bash(script, stdin).decode()
        self.assertEqual(len(got), len(names))
        for name, flag in zip(names, got):
            self.assertIs(dispatch.flat_office_head(flat_repo.view(name + ".bin")), flag == "T", "_flat_office_head " + name)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
def _shebang_oracle(lines: "list[bytes]", *, hardened: bool) -> "list[str]":
    """The scanner id bash ``scan_unknown`` picks for a file whose first line is each of ``lines`` (``unknown`` when it falls to the MIME
    check). ``hardened`` False replaces ``_shebang_interpreter_line`` by the pre-hardening identity, which is the frozen default of
    ``shebang_scanner``. The functions are the real ones of scan_pipeline.sh; the scanners are stubs that print their id."""
    tmp = tempfile.mkdtemp(prefix="shebang-oracle-")
    try:
        names = []
        for index, line in enumerate(lines):
            name = os.path.join(tmp, "f%05d" % index)
            Path(name).write_bytes(line + b"\n")
            names.append(name)
        script = "\n".join([
            bash_function("_shebang_interpreter_line"), bash_function("scan_unknown"),
            "" if hardened else '_shebang_interpreter_line() { SHEBANG_LINE="$1"; }',
            "scan_python() { printf 'python\\n'; }", "scan_shell() { printf 'shell\\n'; }", "scan_ruby() { printf 'ruby\\n'; }",
            "scan_javascript() { printf 'js\\n'; }", "scan_php() { printf 'php\\n'; }", "scan_powershell() { printf 'powershell.text\\n'; }",
            "has_cmd() { return 1; }", "record_pass() { printf 'unknown\\n'; }", "record_fail() { printf 'fail\\n'; }",
            'while IFS= read -r -d "" f; do scan_unknown "$f"; done',
        ])
        stdin = b"".join(os.fsencode(n) + b"\0" for n in names)
        return run_bash(script, stdin).decode().split("\n")[:-1]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class ShebangTests(unittest.TestCase):
    # (first line, default routing, routing with first_word_only=True)
    CASES = [
        (b"#!/bin/bash", "shell", "shell"),
        (b"#!/bin/sh", "shell", "shell"),
        (b"#!/usr/bin/env python3", "python", "python"),
        (b"#!/usr/bin/env bash", "shell", "shell"),
        (b"#!/usr/bin/env sh", "shell", "shell"),
        (b"#!/bin/zsh", "shell", "shell"),
        (b"#!/bin/ksh", "shell", "shell"),
        (b"#!/usr/bin/python3", "python", "python"),
        (b"#!/usr/bin/ruby", "ruby", "ruby"),
        (b"#!/usr/bin/env node", "js", "js"),
        (b"#!/usr/bin/php", "php", "php"),
        (b"#!/usr/bin/pwsh", "powershell.text", "powershell.text"),
        (b"#!/usr/bin/env powershell", "powershell.text", "powershell.text"),
        # F8: a shebang with arguments is not routed by the frozen default, and is by the interpreter word (D-031)
        (b"#!/bin/bash -e", None, "shell"),
        (b"#!/bin/sh -eu", None, "shell"),
        (b"#!/usr/bin/env bash -e", None, "shell"),
        (b"#!/usr/bin/env -S bash -e", None, "shell"),
        (b"#!/bin/bash\r", None, "shell"),
        (b"#!/bin/bash -e\r", None, "shell"),
        (b"#!/bin/sh -e # python is only an argument here", "python", "shell"),
        (b"#!/usr/bin/env -S python3 -u", "python", "python"),
        (b"#!/usr/bin/env python3 -u", "python", "python"),
        (b"#!/usr/bin/python3 -O", "python", "python"),
        (b"#!/usr/bin/env -S node --no-warnings", "js", "js"),
        (b"#!/usr/bin/env -u HOME FOO=1 bash -x", None, "shell"),
        # F7: the spellings of env -S
        (b"#!/usr/bin/env -Sbash -e", None, "shell"),
        (b"#!/usr/bin/env -Spython3 -u", "python", "python"),
        (b"#!/usr/bin/env --split-string=python3 -u", "python", "python"),
        (b"#!/usr/bin/env --split-string='bash -e'", None, "shell"),
        (b"#!/usr/bin/env -iSbash -e", None, "shell"),
        (b'#!/usr/bin/env -S "bash -e"', None, "shell"),
        (b"#!/usr/bin/env -S'bash -e'", None, "shell"),
        (b"#!/usr/bin/env -u python3 bash", "python", "shell"),
        (b"#!/usr/bin/env --chdir=/tmp -S bash", None, "shell"),
        (b"#!/usr/bin/env -S", None, None),
        (b"#!/usr/bin/env", None, None),
        (b"#!", None, None),
        (b"#!   ", None, None),
        (b"", None, None),
        (b"#! /bin/bash", "shell", "shell"),
        (b"not a shebang python", None, None),
        (b"# python", None, None),
        # hostile text is only compared
        (b"#!/bin/bash -e $(touch /nonexistent/x) `touch y` * ;", None, "shell"),
        (b"#!/usr/bin/env -S$(touch /nonexistent/x)bash", None, None),
    ]

    def test_cases(self) -> None:
        for line, default, hardened in self.CASES:
            self.assertEqual(dispatch.shebang_scanner(line), default, "default: %r" % line)
            self.assertEqual(dispatch.shebang_scanner(line, first_word_only=False), default, "explicit False: %r" % line)
            self.assertEqual(dispatch.shebang_scanner(line, first_word_only=True), hardened, "first_word_only: %r" % line)

    def test_480_options_in_a_row_end_and_the_interpreter_after_them_is_found(self) -> None:
        line = b"#!/usr/bin/env " + b"-S" * 480 + b" bash"
        self.assertEqual(dispatch.shebang_scanner(line, first_word_only=True), "shell")

    def test_the_line_is_cut_at_1024_bytes_before_the_words_are_read(self) -> None:
        # bash: ${1:0:1024} is split into words; anything after 1024 bytes is not an interpreter
        line = b"#!/bin/bash " + b"x" * 1100 + b" python"
        self.assertEqual(dispatch.shebang_scanner(line, first_word_only=True), "shell")
        self.assertEqual(dispatch.shebang_scanner(line), "python")     # the frozen default matches the whole line
        # a shebang whose first 1024 bytes are blank has no words, so bash matches the WHOLE original line
        blank = b"#!" + b" " * 1100 + b"python"
        self.assertEqual(dispatch.shebang_scanner(blank, first_word_only=True), "python")

    def test_a_cr_is_removed_only_at_the_end_of_the_first_1024_bytes(self) -> None:
        self.assertEqual(dispatch.shebang_scanner(b"#!/bin/bash\r", first_word_only=True), "shell")
        self.assertEqual(dispatch.shebang_scanner(b"#!/bin/bash\r\r", first_word_only=True), None)
        self.assertEqual(dispatch.shebang_scanner(b"#!/bin/bash\r -e", first_word_only=True), None)

    def test_nul_bytes_and_a_following_line_are_ignored_like_read_does(self) -> None:
        self.assertEqual(dispatch.shebang_scanner(b"#!/bin/ba\0sh", first_word_only=True), "shell")
        self.assertEqual(dispatch.shebang_scanner(b"#!/bin/bash\nprint(1)\n", first_word_only=True), "shell")
        self.assertEqual(dispatch.shebang_scanner(b"#!/bin/bash\nimport python\n"), "shell")

    def test_the_first_matching_route_wins(self) -> None:
        # python precedes the shell routes in the table: a path that names both goes to Python
        self.assertEqual(dispatch.shebang_scanner(b"#!/opt/python/bin/bash"), "python")
        self.assertEqual(dispatch.shebang_scanner(b"#!/opt/bash/bin/python3", first_word_only=True), "python")

    def test_the_star_glob_equals_fnmatchcase(self) -> None:
        rng = random.Random(0x5EB4)
        alphabet = ["#!", "/bin/", "bash", "sh", "env ", "python", "node", "php", "ruby", "pwsh", "powershell", "zsh", "ksh", " ", "/", "x", "\r", ""]
        for pattern, _ in dispatch.SHEBANG_ROUTES:
            for _ in range(400):
                subject = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 7)))
                self.assertEqual(dispatch._star_glob(pattern.encode("latin-1"), subject.encode("latin-1")),
                                 fnmatch.fnmatchcase(subject, pattern), (pattern, subject))

    def test_the_star_glob_equals_fnmatchcase_for_every_shape_of_star_pattern(self) -> None:
        rng = random.Random(0x57A4)
        patterns = ["abc", "", "*", "**", "a*", "*a", "a*b", "ab*ba", "*a*b*", "a**b", "*x*x*", "a*a*a", "abc*", "*abc", "a*bc*d"]
        for pattern in patterns:
            for _ in range(500):
                subject = "".join(rng.choice("abcx") for _ in range(rng.randint(0, 9)))
                self.assertEqual(dispatch._star_glob(pattern.encode(), subject.encode()), fnmatch.fnmatchcase(subject, pattern), (pattern, subject))

    def test_a_pattern_with_other_wildcards_still_routes_through_fnmatch(self) -> None:
        with mock.patch.object(dispatch, "SHEBANG_ROUTES", (("#!/bin/?ash", "shell"), ("#!/usr/bin/[np]*", "js"))):
            self.assertEqual(dispatch.shebang_scanner(b"#!/bin/bash"), "shell")
            self.assertEqual(dispatch.shebang_scanner(b"#!/usr/bin/pwsh"), "js")
            self.assertIsNone(dispatch.shebang_scanner(b"#!/usr/bin/ruby"))

    @NEEDS_BASH
    def test_the_hardcoded_cases_equal_bash(self) -> None:
        lines = [c[0] for c in self.CASES if b"touch" not in c[0]]
        default = _shebang_oracle(lines, hardened=False)
        hardened = _shebang_oracle(lines, hardened=True)
        for line, want_default, want_hardened in zip(lines, default, hardened):
            self.assertEqual(dispatch.shebang_scanner(line), None if want_default == "unknown" else want_default, "default %r" % line)
            self.assertEqual(dispatch.shebang_scanner(line, first_word_only=True), None if want_hardened == "unknown" else want_hardened,
                             "first_word_only %r" % line)

    @NEEDS_BASH
    def test_random_lines_equal_bash(self) -> None:
        rng = random.Random(0xD031)
        interpreters = ["/bin/bash", "/bin/sh", "/usr/bin/env", "/usr/bin/python3", "env", "/usr/local/bin/node", "/usr/bin/ruby", "/usr/bin/php",
                        "/usr/bin/pwsh", "/bin/zsh", "/bin/ksh", "/usr/bin/powershell", "bash", "python", "/opt/x/bin/ENV", "/usr/bin/envx"]
        words = ["-e", "-eu", "-S", "-Sbash", "-Spython3", "-u", "-C", "-i", "-iS", "-iSbash", "-S\"bash", "--split-string=bash",
                 "--split-string='sh -e'", "--split-string=", "--unset=FOO", "--chdir=/tmp", "--chdir", "--unset", "FOO=1", "-", "--",
                 "bash", "sh", "python3", "node", "'bash", "bash'", "\"python3", "-uHOME", "-Cdir", "-x", "-S'bash", "ruby", "php", "pwsh",
                 "-u", "-Sphp -u", "-vS", "-0S", "-Cu", "-uS", "-S-S", "x=y", "-a=b", "\"\"", "''", "$(id)", "`id`", "*", ";"]
        separators = [" ", "\t", "  ", " \t "]
        lines = []
        for _ in range(2500):
            body = rng.choice(interpreters)
            for _ in range(rng.randint(0, 6)):
                body += rng.choice(separators) + rng.choice(words)
            prefix = rng.choice(["#!"] * 12 + ["#! ", "# !", "!#", "#"])
            suffix = rng.choice([""] * 8 + ["\r", " ", "\t", "\r\r", " \r"])
            lines.append((prefix + body + suffix).encode("latin-1"))
        for pad in (1000, 1020, 1021, 1022, 1023, 1024, 1025, 1100):
            lines.append(b"#!/bin/bash " + b"x" * (pad - 12) + b" python")
            lines.append(b"#!/usr/bin/env " + b"-i " * (pad // 3) + b"bash")
            lines.append(b"#!" + b" " * pad + b"python")
            lines.append(b"#!/bin/sh" + b" " * pad + b"\r")
        default = _shebang_oracle(lines, hardened=False)
        hardened = _shebang_oracle(lines, hardened=True)
        self.assertEqual(len(default), len(lines))
        self.assertEqual(len(hardened), len(lines))
        repo = support.TempRepo()
        self.addCleanup(repo.cleanup)
        for index, line in enumerate(lines):
            repo.write("f%05d" % index, line + b"\n")
            first = repo.view("f%05d" % index).first_line()
            want_default = None if default[index] == "unknown" else default[index]
            want_hardened = None if hardened[index] == "unknown" else hardened[index]
            self.assertEqual(dispatch.shebang_scanner(first), want_default, "default %r" % line)
            self.assertEqual(dispatch.shebang_scanner(first, first_word_only=True), want_hardened, "first_word_only %r" % line)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ClassifyFileTests(unittest.TestCase):
    def test_every_extension_routes_to_its_scanner_in_any_case(self) -> None:
        for ext, scanner_id in sorted(dispatch.EXT_ROUTES.items()):
            for name in ("file" + ext, "FILE" + ext.upper(), "a.b/Mixed" + ext.capitalize()):
                calls = classify(self, name, b"plain text\n")
                self.assertEqual(calls, [(scanner_id, False)], name)

    def test_every_basename_arm_routes_and_ends_the_dispatch(self) -> None:
        samples = {
            "docker": ["Dockerfile", "Dockerfile.dev", "Dockerfile-prod", "sub/Dockerfile.py"],
            "makefile": ["Makefile", "Makefile.am", "makefile", "makefile.inc", "GNUmakefile", "GNUmakefile.local", "sub/Makefile.txt"],
            "cmake": ["CMakeLists.txt", "CMakeLists.foo.txt", "src/CMakeLists.txt", "CMakeLists.a.b.txt"],
            "manifest.package_json": ["package.json", "composer.json", "sub/package.json"],
            "manifest.requirements": ["requirements.txt", "requirements-dev.txt", "requirements_x.txt", "constraints.txt",
                                      "constraints-3.txt", "sub/requirements.txt"],
            "gradle": ["gradle.properties", "gradle-wrapper.properties", "build.gradle", "settings.gradle", "build.gradle.kts",
                       "x.gradle.kts", ".gradle", "a/b/app.gradle"],
            "setuppy": ["setup.py", "conanfile.py", "sub/setup.py"],
        }
        for scanner_id, names in samples.items():
            for name in names:
                self.assertEqual(classify(self, name, b"x\n"), [(scanner_id, False)], name)

    def test_basenames_are_case_sensitive_and_exact(self) -> None:
        self.assertEqual(classify(self, "Setup.py"), [("python", False)])
        self.assertEqual(classify(self, "dockerfile"), [("unknown", False)])
        self.assertEqual(classify(self, "MAKEFILE"), [("unknown", False)])
        self.assertEqual(classify(self, "CMakeLists.cmake"), [("cmake", False)])        # by extension, not by the txt arm
        self.assertEqual(classify(self, "CMakeLists.txt.bak"), [("unknown", False)])
        self.assertEqual(classify(self, "my.package.json"), [("json", False)])
        self.assertEqual(classify(self, "package.json.orig"), [("unknown", False)])
        self.assertEqual(classify(self, "requirements.md"), [("docs", False)])
        self.assertEqual(classify(self, "main.kts"), [("kotlin", False)])               # only *.gradle.kts is Gradle
        self.assertEqual(classify(self, "foo.main.kts"), [("kotlin", False)])

    def test_the_basename_arms_are_tried_in_table_order(self) -> None:
        self.assertEqual(classify(self, "Makefile.gradle"), [("makefile", False)])
        self.assertEqual(classify(self, "Dockerfile.gradle"), [("docker", False)])
        self.assertEqual(classify(self, "makefile.gradle.kts"), [("makefile", False)])
        self.assertEqual(classify(self, "Dockerfile.txt"), [("docker", False)])           # a basename arm beats the extension
        self.assertEqual(classify(self, "Makefile.json"), [("makefile", False)])
        self.assertEqual(classify(self, "CMakeLists.txt"), [("cmake", False)])             # not the docs scanner
        self.assertEqual(classify(self, "requirements.txt", RTF), [("manifest.requirements", False)])   # no RTF sniffing past an arm

    def test_upper_case_extensions_are_not_a_bypass(self) -> None:
        for name, scanner_id in (("UPPER.PY", "python"), ("UPPER.PS1", "powershell.text"), ("A.BAT", "batch"), ("B.Cmd", "batch"),
                                 ("C.JAR", "jar"), ("D.DOCX", "ooxml"), ("E.Rtf", "rtf"), ("F.SH", "shell"), ("G.PDF", "pdf")):
            self.assertEqual(classify(self, name, b"x")[0], (scanner_id, False), name)

    def test_a_trailing_newline_in_the_name_still_meets_the_basename_arm_like_bash(self) -> None:
        # bash: base=$(basename "$f") drops trailing newlines; the extension (${f##*.}) keeps them and routes nowhere
        self.assertEqual(classify(self, "setup.py\n", b"x"), [("setuppy", False)])
        self.assertEqual(classify(self, "Makefile\n\n", b"x"), [("makefile", False)])
        self.assertEqual(classify(self, "a.py\n", b"x"), [("unknown", False)])
        self.assertEqual(classify(self, "package.json\n", b"x"), [("manifest.package_json", False)])

    def test_a_dotted_directory_with_a_dotless_file_routes_nowhere(self) -> None:
        self.assertEqual(classify(self, "sub.py/data", b"x"), [("unknown", False)])
        self.assertEqual(classify(self, "a.sh/README", b"x"), [("unknown", False)])
        self.assertEqual(classify(self, "x.", b"x"), [("unknown", False)])

    def test_only_ascii_extension_letters_are_lowered(self) -> None:
        self.assertEqual(classify(self, "x.\u212at"), [("unknown", False)])
        self.assertEqual(classify(self, "x.\u212at", RTF), [("rtf", True)])

    # -- .xml and .pom: the scanner, then the Flat OPC probe ---------------------------------------------
    def test_xml_and_pom_run_the_xml_scanner_and_probe_for_flat_office(self) -> None:
        for name in ("a.xml", "pom.xml", "A.XML", "x.pom", "sub/b.POM"):
            self.assertEqual(classify(self, name, b"<project/>"), [("xml", False)], name)
            for marker in (FLAT_OPC, WORDML, EXCEL2003):
                self.assertEqual(classify(self, name, marker), [("xml", False), ("ooxml", True)], name)

    def test_the_flat_office_scan_is_always_asked_and_its_answer_ignored(self) -> None:
        for answer in (True, False):
            self.assertEqual(classify(self, "d.xml", FLAT_OPC, {"ooxml": answer}), [("xml", False), ("ooxml", True)])
        # the xml scanner's own answer does not stop the probe either
        self.assertEqual(classify(self, "d.xml", FLAT_OPC, {"xml": False}), [("xml", False), ("ooxml", True)])

    def test_the_flat_office_marker_must_be_in_the_first_8192_bytes(self) -> None:
        late = b"<a>" + b" " * 9000 + FLAT_OPC
        self.assertEqual(classify(self, "d.xml", late), [("xml", False)])

    # -- .md .txt .rst: the RTF probe, then the docs scanner -----------------------------------------------
    def test_docs_extensions_are_probed_for_rtf(self) -> None:
        for name in ("n.md", "n.txt", "n.rst", "N.TXT", "sub/README.MD"):
            self.assertEqual(classify(self, name, b"just text\n"), [("docs", False)], name)
            self.assertEqual(classify(self, name, RTF), [("rtf", True)], name)
            self.assertEqual(classify(self, name, b"  \n" + RTF), [("rtf", True)], name)

    def test_the_docs_scanner_runs_when_the_rtf_scanner_says_not_mine(self) -> None:
        self.assertEqual(classify(self, "n.txt", RTF, {"rtf": False}), [("rtf", True), ("docs", False)])
        self.assertEqual(classify(self, "n.md", RTF, {"rtf": True, "docs": False}), [("rtf", True)])

    def test_a_scanner_that_is_not_ported_returns_true_so_an_rtf_is_never_read_as_text(self) -> None:
        # layers' ``run`` answers True for an id the registry cannot serve (a WARN is recorded instead)
        calls = classify(self, "n.txt", RTF, {i: True for i in KNOWN_SCANNERS})
        self.assertEqual(calls, [("rtf", True)])

    def test_the_rtf_probe_is_not_asked_for_other_extensions(self) -> None:
        self.assertEqual(classify(self, "a.json", RTF), [("json", False)])
        self.assertEqual(classify(self, "a.py", RTF), [("python", False)])
        self.assertEqual(classify(self, "a.rtf", b"plain"), [("rtf", False)])
        self.assertEqual(classify(self, "a.docx", b"plain"), [("ooxml", False)])

    def test_an_rtf_that_starts_with_nul_bytes_is_still_probed_like_bash(self) -> None:
        self.assertEqual(classify(self, "n.txt", b"\0\0" + RTF), [("rtf", True)])

    # -- everything else: the RTF probe, then scan_unknown ---------------------------------------------------
    def test_an_unknown_extension_is_probed_for_rtf_then_goes_to_unknown(self) -> None:
        for name in ("script", "data.log", "a.weird", "sub/entrypoint", ".hidden", "LICENSE"):
            self.assertEqual(classify(self, name, b"echo hi\n"), [("unknown", False)], name)
            self.assertEqual(classify(self, name, RTF), [("rtf", True)], name)
            self.assertEqual(classify(self, name, RTF, {"rtf": False}), [("rtf", True), ("unknown", False)], name)

    def test_the_shebang_of_an_unknown_file_is_not_dispatch_business(self) -> None:
        # classify_file sends it to ``unknown``; scanners.unknown reads the shebang (it calls dispatch.shebang_scanner)
        self.assertEqual(classify(self, "entrypoint", b"#!/usr/bin/env python3\nimport os\n"), [("unknown", False)])

    def test_the_run_callback_is_the_only_way_out(self) -> None:
        repo = support.TempRepo({"a.py": b"x"})
        self.addCleanup(repo.cleanup)
        seen = []
        result = dispatch.classify_file(repo.view("a.py"), lambda i, s: seen.append((i, s)) or True)
        self.assertIsNone(result)
        self.assertEqual(seen, [("python", False)])


if __name__ == "__main__":
    unittest.main()
