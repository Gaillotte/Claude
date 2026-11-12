#!/usr/bin/env python3
"""Differential fuzz of transit/rx.py against the real GNU grep, for every pattern in patterns.json.

    python3 -I tests/conformance/pattern_fuzz.py [--patterns patterns.json] [--jobs N] [--quick] [--only ID ...]
                                                 [--report pattern_report.md] [--seed N] [--no-timing]
                                                 [--synthetic N]

For each pattern the bash helper's exact command is run with ``LC_ALL=C`` and the answer is compared with
rx.py on the same lines:

    grep_check / grep_check_i / _pdf_has   grep -n -E [-i] [-a] -e PATTERN FILE
    grep_check_excl                        grep -hiE -e PATTERN FILE | grep -viE -e EXCL
    grep_flat                              tr '\\r\\n\\t' '   ' | grep -iE -e PATTERN       (one document, one line)
    direct greps                           the flags the script uses (-o, -c, -A5 | tr | grep, -o | grep -v ...)

Inputs for every pattern
    (a) a shared corpus: lines of the text files in this repository (tests/fixtures/**, *.sh, *.py, *.md),
        de-duplicated, binary files and lines over 2000 bytes dropped, capped at about 150000 lines;
    (b) at least 30 POSITIVES generated from the pattern's own parse tree (random walks over alternations,
        repetitions with small counts, classes), each also placed mid-line;
    (c) NEAR-MISSES: one character deleted, duplicated, replaced, swapped, a case flip, a truncation;
    (d) hand-written edge lines for the dialect hazards (empty line, spaces, tabs, ] } \\ quotes, long runs).
A pattern is ``clean`` only if nothing disagrees AND the generated positives exercised it (some matched in grep).

Then a timing pass: each compiled pattern runs against adversarial 64 KB lines under a 2 s SIGALRM; over 0.5 s is
flagged, and real grep is timed on the same line for comparison.

Exit status is non-zero if any pattern is not clean (or slow) and is not explained in
known_pattern_divergences.json, if the synthetic ERE fuzz finds a disagreement, or if a global check fails.
Standard library only.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import multiprocessing as mp
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# RX_ROOT points the fuzz at another tree's transit/rx.py: the mutation check runs it against a deliberately broken copy
sys.path.insert(0, str(Path(os.environ.get("RX_ROOT") or ROOT)))
from transit import rx  # noqa: E402

ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
KNOWN_PATH = HERE / "known_pattern_divergences.json"
SLOW_SECONDS = 0.5
ALARM_SECONDS = 2.0
ADV_SIZE = 65536
CORPUS_CAP = 150_000


# ====================================================================================================
# running grep
# ====================================================================================================
def run(cmd: list[str], data: bytes | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=data, capture_output=True, env=ENV, timeout=timeout)


def sh(script: str, *args: str, data: bytes | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
    """Run a small pipeline with the pattern(s) passed as positional parameters, never interpolated."""
    return subprocess.run(["bash", "-c", script, "_", *args], input=data, capture_output=True, env=ENV, timeout=timeout)


def grep_cmd(pat: str, path: str, *, ci: bool, text: bool, ere: bool, extra: tuple[str, ...] = ("-n",)) -> list[str]:
    return ["grep", *extra, *(["-E"] if ere else []), *(["-i"] if ci else []), *(["-a"] if text else []),
            "-e", pat, path]


def grep_numbers(pat: str, path: str, *, ci: bool, text: bool, ere: bool) -> tuple[set[int] | None, str]:
    p = run(grep_cmd(pat, path, ci=ci, text=text, ere=ere))
    if p.returncode == 2:
        return None, p.stderr.decode("latin-1").strip()
    nums = {int(ln.split(b":", 1)[0]) for ln in p.stdout.split(b"\n") if ln}
    return nums, p.stderr.decode("latin-1").strip()


# ====================================================================================================
# the corpus
# ====================================================================================================
def build_corpus(cap: int = CORPUS_CAP, maxlen: int = 2000, seed: int = 1) -> list[bytes]:
    files: list[Path] = []
    skip = {".git", "__pycache__", "Good", "node_modules", ".claude"}
    for dirpath, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in skip]
        dp = Path(dirpath)
        rel = dp.relative_to(ROOT).parts
        for nm in names:
            if rel[:2] == ("tests", "fixtures") or nm.endswith((".sh", ".py", ".md")):
                files.append(dp / nm)
    seen: set[bytes] = set()
    lines: list[bytes] = []
    for f in sorted(files):
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if b"\0" in data:
            continue  # binary
        for ln in data.split(b"\n"):
            if len(ln) <= maxlen and ln not in seen:
                seen.add(ln)
                lines.append(ln)
    if len(lines) > cap:
        random.Random(seed).shuffle(lines)
        lines = lines[:cap]
    return lines


# ====================================================================================================
# generation from the parse tree
# ====================================================================================================
EDGE_LINES: list[bytes] = [
    b"", b" ", b"   ", b"\t", b"\t\t", b"]", b"}", b"{", b"[", b")", b"(", b"\\", b"\\\\", b"'", b'"', b"`", b"''",
    b'""', b"-", b"--", b"----", b"-----BEGIN", b"^", b"$", b"|", b"*", b"+", b"?", b".", b"..", b"../", b"..\\",
    b"=", b":", b";", b"#", b"/", b"//", b"http://", b"https://", b"\r", b"a\r", b" \r", b"\x01", b"\x7f", b"\xff",
    b"\xe2\x80\x94", b"caf\xc3\xa9", b"\x1b[0m", b"a" * 2000, b" " * 2000, b"\t" * 500, b"x" * 70 + b"=" * 70,
    b"0123456789", b"abcdefghijklmnopqrstuvwxyz", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"_", b"a_b", b"foo bar", b"Foo Bar",
    b"a b c", b" a ", b"(a)", b"[a]", b"{a}", b'"a"', b"'a'", b"a=b", b"a: b", b"a=\"b\"", b"a='b'", b"= \"\"",
    b"$x", b"${x}", b"$(x)", b"%x%", b"%2e%2e", b"\\x00", b"\\n", b"\\.",
]
NOISE_PRE = [b"", b" ", b"\t", b"x = ", b"# ", b"foo(", b'"', b"    ", b"\t\t", b"1", b"-", b"/"]
NOISE_POST = [b"", b" ", b";", b")", b" # c", b"\r", b"x", b"1", b"\t", b" }"]
POOL = b"abcxyzABCXYZ0123456789 _-.,:;'\"()[]{}<>=/\\|!?*+$^%&@#~`\t"


class Skip(Exception):
    pass


def gen_node(node, r: random.Random, groups: dict, big: bool = False) -> bytes:
    if isinstance(node, rx.Set):
        bits = sorted(node.bits)
        if not bits:
            raise Skip
        printable = [b for b in bits if 32 <= b < 127]
        pool = printable if printable and r.random() < 0.92 else bits
        return bytes([r.choice(pool)])
    if isinstance(node, rx.Cat):
        return b"".join(gen_node(x, r, groups, big) for x in node.items)
    if isinstance(node, rx.Alt):
        return gen_node(r.choice(node.items), r, groups, big)
    if isinstance(node, rx.Rep):
        lo = node.lo
        hi = node.hi if node.hi is not None else lo + 3
        top = min(hi, lo + (6 if big else 3))
        n = r.randint(lo, top)
        return b"".join(gen_node(node.node, r, groups, big) for _ in range(n))
    if isinstance(node, rx.Group):
        s = gen_node(node.node, r, groups, big)
        groups[node.index] = s
        return s
    if isinstance(node, rx.Backref):
        return groups.get(node.index, b"")
    return b""  # Assert, Empty


def gen_positive(parsed, r: random.Random, ci: bool) -> bytes | None:
    for _ in range(5):
        try:
            s = gen_node(parsed.ast, r, {}, big=r.random() < 0.15)
        except Skip:
            return None
        if b"\n" in s or b"\0" in s:
            continue
        if ci:
            s = bytes((b ^ 32) if (65 <= (b & ~32) <= 90 and r.random() < 0.35) else b for b in s)
        return s
    return None


def mutations(s: bytes, r: random.Random, extra_pool: bytes) -> list[bytes]:
    out: list[bytes] = []
    if not s:
        return [b"x"]
    pool = POOL + extra_pool
    for _ in range(6):
        i = r.randrange(len(s))
        kind = r.randrange(7)
        if kind == 0:
            m = s[:i] + s[i + 1:]
        elif kind == 1:
            m = s[:i] + s[i:i + 1] + s[i:]
        elif kind == 2:
            m = s[:i] + bytes([r.choice(pool)]) + s[i + 1:]
        elif kind == 3 and len(s) > 1:
            j = min(i, len(s) - 2)
            m = s[:j] + s[j + 1:j + 2] + s[j:j + 1] + s[j + 2:]
        elif kind == 4:
            c = s[i]
            m = s[:i] + bytes([c ^ 32 if 65 <= (c & ~32) <= 90 else c]) + s[i + 1:]
        elif kind == 5:
            m = s[:i]
        else:
            m = s[:i] + bytes([r.choice(pool)]) + s[i:]
        if b"\n" not in m and b"\0" not in m:
            out.append(m)
    return out


def literal_pool(parsed_ast) -> bytes:
    got: set[int] = set()

    def walk(n):
        if isinstance(n, rx.Set):
            if len(n.bits) <= 6:
                got.update(n.bits)
        elif isinstance(n, (rx.Cat, rx.Alt)):
            for x in n.items:
                walk(x)
        elif isinstance(n, (rx.Rep, rx.Group)):
            walk(n.node)

    walk(parsed_ast)
    return bytes(sorted(b for b in got if b not in (10, 0)))


def make_extras(pattern: str, ci: bool, r: random.Random, n_pos: int = 60,
                min_bearing: int = 40) -> tuple[list[bytes], list[tuple[int, str]], int]:
    """Generated lines for one pattern, a tag per line (index, kind: pos / wrapped / near / edge), and the number of
    DISTINCT positives found (a pattern with a tiny language, such as a literal, has only a few; it is then padded with
    positives placed in different surroundings so that at least ``min_bearing`` lines carry one)."""
    parsed = rx.parse_ere(pattern, ci)
    pool = literal_pool(parsed.ast)
    lines: list[bytes] = []
    tags: list[str] = []
    positives: list[bytes] = []
    for _ in range(n_pos * 3):
        p = gen_positive(parsed, r, ci)
        if p is not None and p not in positives:
            positives.append(p)
        if len(positives) >= n_pos:
            break
    for p in positives:
        lines.append(p)
        tags.append("pos")
        for _ in range(3):
            lines.append(r.choice(NOISE_PRE) + p + r.choice(NOISE_POST))
            tags.append("wrapped")
    tries = 0
    while positives and len(set(ln for ln, tg in zip(lines, tags) if tg in ("pos", "wrapped"))) < min_bearing and tries < 400:
        tries += 1
        lines.append(r.choice(NOISE_PRE) * r.randint(1, 2) + r.choice(positives) + r.choice(NOISE_POST) * r.randint(1, 2)
                     + bytes([r.choice(POOL)]) * r.randint(0, 1))
        tags.append("wrapped")
    for p in positives[:30]:
        for m in mutations(p, r, pool):
            lines.append(m)
            tags.append("near")
            lines.append(r.choice(NOISE_PRE) + m + r.choice(NOISE_POST))
            tags.append("near")
    for e in EDGE_LINES:
        lines.append(e)
        tags.append("edge")
    # edge lines built around the pattern's own literals
    for ch in pool[:12]:
        c = bytes([ch])
        for t in (c, c * 3, b" " + c + b" ", c * 300):
            lines.append(t)
            tags.append("edge")
    # unique, keep tag of the first occurrence
    seen: set[bytes] = set()
    ul: list[bytes] = []
    ut: list[str] = []
    for ln, tg in zip(lines, tags):
        if ln not in seen:
            seen.add(ln)
            ul.append(ln)
            ut.append(tg)
    return ul, [(i, t) for i, t in enumerate(ut)], len(positives)


# ====================================================================================================
# cases
# ====================================================================================================
@dataclass
class Case:
    id: str
    kind: str            # line | extract | excl | flat | pipe_o_excl | pem
    pattern: str
    excl: str | None
    ci: bool
    text: bool           # grep -a
    ere: bool
    helper: str
    mode: str
    line: int
    function: str
    flags: str
    pattern2_ere: bool = True
    note: str = ""


def cases_from_inventory(records: list[dict]) -> tuple[list[Case], list[dict]]:
    cases: list[Case] = []
    unresolved: list[dict] = []
    for rec in records:
        pat = rec.get("pattern")
        if pat is None:
            unresolved.append(rec)
            continue
        mode, shape, flags = rec["mode"], rec.get("shape", "match"), rec.get("flags", "")
        base = dict(id=rec["id"], pattern=pat, excl=rec.get("excl"), helper=rec["helper"], mode=mode,
                    line=rec["line"], function=rec["enclosing_function"], flags=flags)
        ere = rec.get("dialect", "ere") == "ere"
        if mode in ("line", "line_i", "line_a"):
            cases.append(Case(kind="line", ci=mode == "line_i", text=mode == "line_a", ere=True, **base))
        elif mode == "excl":
            cases.append(Case(kind="excl", ci=True, text=False, ere=True, **base))
        elif mode == "flat":
            cases.append(Case(kind="flat", ci=True, text=False, ere=True, **base))
        elif mode == "direct":
            f1 = flags.split("|")[0]
            ci = "i" in f1
            text = "a" in f1
            if shape in ("match", "count"):
                cases.append(Case(kind="line", ci=ci, text=text, ere=ere, **base))
            elif shape == "extract":
                cases.append(Case(kind="extract", ci=ci, text=text, ere=ere, **base))
            elif shape == "pipe2" and rec.get("context_lines"):
                cases.append(Case(kind="pem", ci=ci, text=text, ere=ere, **base))
            elif shape == "pipe2" and "o" in f1 and rec.get("flags2", "").count("v"):
                cases.append(Case(kind="pipe_o_excl", ci=ci, text=text, ere=ere, **base))
            elif shape == "pipe2":
                # two independent stages: first as a line/extract check, second as an extract/line check
                b1 = dict(base)
                b1["id"] = rec["id"] + "/1"
                b1["excl"] = None
                cases.append(Case(kind="extract" if "o" in f1 else "line", ci=ci, text=text, ere=ere, **b1))
                f2 = rec.get("flags2", "")
                b2 = dict(base)
                b2["id"] = rec["id"] + "/2"
                b2["pattern"] = rec["excl"]
                b2["excl"] = None
                cases.append(Case(kind="extract" if "o" in f2 else "line", ci="i" in f2, text="a" in f2,
                                  ere="E" in f2, **b2))
            else:
                unresolved.append(rec)
        else:
            unresolved.append(rec)
    return cases, unresolved


@dataclass
class Result:
    id: str
    kind: str
    status: str = "clean"          # clean | DIVERGES | LATENT_BUG | TRANSLATION_FAILED | UNEXERCISED
    tested: int = 0
    grep_pos: int = 0
    py_pos: int = 0
    generated: int = 0
    generated_matched: int = 0
    disagreements: list[dict] = field(default_factory=list)
    n_disagree: int = 0
    error: str = ""
    warnings: list[str] = field(default_factory=list)
    src: str = ""
    seconds: float = 0.0
    dfa: bool = False
    distinct: int = 0


def add_dis(res: Result, text: bytes, grep_says, py_says, tag: str) -> None:
    res.n_disagree += 1
    if len(res.disagreements) < 6:
        res.disagreements.append({"line": text[:200].decode("latin-1"), "grep": grep_says, "python": py_says, "tag": tag})


def line_offsets(buf: bytes) -> list[int]:
    offs = [0]
    for m in re.finditer(b"\n", buf):
        offs.append(m.end())
    return offs


def check_line_case(c: Case, corpus_path: str, corpus: bytes, corpus_offs: list[int], r: random.Random) -> Result:
    res = Result(c.id, c.kind)
    try:
        comp = rx.ere_to_py(c.pattern, c.ci)
        res.src = rx.ere_to_py_source(c.pattern, c.ci).decode("latin-1")
        res.warnings = rx.parse_ere(c.pattern, c.ci).warnings
    except rx.EREError as exc:
        # does grep accept it?
        nums, err = grep_numbers(c.pattern, corpus_path, ci=c.ci, text=c.text, ere=c.ere)
        res.status = "TRANSLATION_FAILED" if nums is not None else "LATENT_BUG"
        res.error = f"rx: {exc}" + ("" if nums is not None else f"; grep also rejects it: {err}")
        return res
    extras, tags, distinct = make_extras(c.pattern, c.ci, r)
    res.distinct = distinct
    tag_of = [t for _, t in tags]
    extras_buf = b"\n".join(extras) + b"\n"
    ex_path = os.path.join(os.path.dirname(corpus_path), "extras_" + hashlib.sha1(c.id.encode()).hexdigest()[:12])
    with open(ex_path, "wb") as f:
        f.write(extras_buf)
    try:
        g_corpus, err1 = grep_numbers(c.pattern, corpus_path, ci=c.ci, text=c.text, ere=c.ere)
        g_extra, err2 = grep_numbers(c.pattern, ex_path, ci=c.ci, text=c.text, ere=c.ere)
    finally:
        os.unlink(ex_path)
    if g_corpus is None or g_extra is None:
        res.status = "LATENT_BUG"
        res.error = f"grep rejects the pattern (exit 2): {err1 or err2}"
        return res
    # production path on the corpus: one search over the whole buffer, then lines
    py_corpus: set[int] = set()
    for ls, _le in rx.matching_lines(comp, corpus):
        py_corpus.add(bisect.bisect_right(corpus_offs, ls))
    nc = len(corpus_offs) - (1 if corpus.endswith(b"\n") else 0)
    res.tested = nc + len(extras)
    for ln in sorted(g_corpus ^ py_corpus):
        text = corpus[corpus_offs[ln - 1]:corpus_offs[ln] - 1] if ln < len(corpus_offs) else b""
        add_dis(res, text, ln in g_corpus, ln in py_corpus, "corpus")
    # reference path on the generated lines: one search per line
    gen_ok = 0
    for i, ln in enumerate(extras):
        py = comp.search(ln) is not None
        gr = (i + 1) in g_extra
        if py != gr:
            add_dis(res, ln, gr, py, tag_of[i])
        if tag_of[i] in ("pos", "wrapped"):
            res.generated += 1
            gen_ok += gr
    res.generated_matched = gen_ok
    res.grep_pos = len(g_corpus) + len(g_extra)
    res.py_pos = len(py_corpus) + sum(1 for ln in extras if comp.search(ln) is not None)
    # the linear-time matcher (rx's fallback for pathological lines) is held to the same standard
    if rx.dfa_available(comp):
        d_corpus = {bisect.bisect_right(corpus_offs, ls) for ls, _le in rx.dfa_matching_lines(comp, corpus)}
        for ln in sorted(g_corpus ^ d_corpus)[:6]:
            add_dis(res, corpus[corpus_offs[ln - 1]:corpus_offs[ln] - 1], ln in g_corpus, ln in d_corpus, "dfa corpus")
        res.n_disagree += max(0, len(g_corpus ^ d_corpus) - 6)
        eoffs = line_offsets(extras_buf)
        d_extra = {bisect.bisect_right(eoffs, ls) for ls, _le in rx.dfa_matching_lines(comp, extras_buf)}
        for ln in sorted(g_extra ^ d_extra)[:6]:
            add_dis(res, extras[ln - 1], ln in g_extra, ln in d_extra, "dfa generated")
        res.n_disagree += max(0, len(g_extra ^ d_extra) - 6)
        res.dfa = True
    # the whole-buffer path must agree with the per-line path on the generated lines too
    whole = rx.search_lines(comp, extras_buf)
    if whole != bool(g_extra):
        add_dis(res, b"<generated lines as one buffer>", bool(g_extra), whole, "search_lines")
    finish(res)
    return res


def finish(res: Result) -> None:
    if res.status != "clean":
        return
    if res.n_disagree:
        res.status = "DIVERGES"
    elif res.generated_matched == 0:
        res.status = "UNEXERCISED"


def check_extract_case(c: Case, corpus_path: str, corpus: bytes, corpus_offs: list[int], r: random.Random) -> Result:
    """grep -o: compare the matched text, line by line, as well as which lines match."""
    res = check_line_case(c, corpus_path, corpus, corpus_offs, r)
    if res.status in ("TRANSLATION_FAILED", "LATENT_BUG"):
        return res
    comp = rx.ere_to_py(c.pattern, c.ci)
    extras, _tags, _d = make_extras(c.pattern, c.ci, random.Random(r.random()))
    buf = b"\n".join(extras) + b"\n"
    g = run(["grep", "-o", *(["-E"] if c.ere else []), *(["-i"] if c.ci else []), "-e", c.pattern], buf)
    want = [x for x in g.stdout.split(b"\n")[:-1]]
    got = rx.only_matching(comp, buf)
    res.tested += len(extras)
    if want != got:
        # find first differing position for the example
        for k in range(max(len(want), len(got))):
            a = want[k] if k < len(want) else None
            b = got[k] if k < len(got) else None
            if a != b:
                add_dis(res, (a or b"")[:100] + b" <> " + (b or b"")[:100], (a or b"<none>").decode("latin-1")[:60],
                        (b or b"<none>").decode("latin-1")[:60], "only_matching")
                break
    finish(res)
    return res


def check_excl_case(c: Case, corpus_path: str, corpus: bytes, corpus_offs: list[int], r: random.Random) -> Result:
    res = Result(c.id, c.kind)
    try:
        pat = rx.ere_to_py(c.pattern, True)
        exc = rx.ere_to_py(c.excl or "", True)
        res.src = rx.ere_to_py_source(c.pattern, True).decode("latin-1") + "  EXCL  " + \
            rx.ere_to_py_source(c.excl or "", True).decode("latin-1")
    except rx.EREError as e:
        res.status = "TRANSLATION_FAILED"
        res.error = f"rx: {e}"
        return res
    extras, tags, distinct = make_extras(c.pattern, True, r)
    res.distinct = distinct
    # lines that carry the exclusion too, so both sides of the test are reached
    ex_parsed = rx.parse_ere(c.excl or "", True)
    base_pos = [ln for ln, (_, t) in zip(extras, tags) if t == "pos"][:25]
    for ln in base_pos:
        for _ in range(2):
            e = gen_positive(ex_parsed, r, True)
            if e is not None and b"\n" not in e:
                extras.append(ln + r.choice([b" ", b"", b"\t"]) + e)
                tags.append((len(extras) - 1, "excl_mix"))
                extras.append(e + b" " + ln)
                tags.append((len(extras) - 1, "excl_mix"))
    tag_of = [t for _, t in tags]
    ex_buf = b"\n".join(extras) + b"\n"
    ex_path = os.path.join(os.path.dirname(corpus_path), "xextras_" + hashlib.sha1(c.id.encode()).hexdigest()[:12])
    with open(ex_path, "wb") as f:
        f.write(ex_buf)
    try:
        for path, buf, tg in ((corpus_path, corpus, None), (ex_path, ex_buf, tag_of)):
            p = sh('grep -hiE -e "$1" "$3" 2>/dev/null | grep -viE -e "$2" 2>/dev/null', c.pattern, c.excl or "", path)
            status = sh('grep -hiE -e "$1" "$3" 2>/dev/null | grep -viE -e "$2" >/dev/null', c.pattern, c.excl or "", path)
            if run(["grep", "-hiE", "-e", c.pattern, path]).returncode == 2 or \
                    run(["grep", "-viE", "-e", c.excl or "", os.devnull]).returncode == 2:
                res.status = "LATENT_BUG"
                res.error = "grep rejects one of the two patterns (exit 2): the helper reads this as 'no match' for ever"
                return res
            want = [x for x in p.stdout.split(b"\n")[:-1]]
            got = [buf[ls:le] for ls, le in rx.excl_lines(pat, exc, buf)]
            res.tested += buf.count(b"\n")
            if want != got:
                ws, gs = Counter(want), Counter(got)
                for ln in list((ws - gs).elements())[:3]:
                    add_dis(res, ln, True, False, "excl")
                for ln in list((gs - ws).elements())[:3]:
                    add_dis(res, ln, False, True, "excl")
                res.n_disagree += max(0, sum((ws - gs).values()) + sum((gs - ws).values()) - 6)
            if rx.dfa_available(pat) and rx.dfa_available(exc):
                dgot = [buf[ls:le] for ls, le in rx.dfa_matching_lines(pat, buf) if not rx.dfa_search(exc, buf[ls:le])]
                if dgot != want:
                    add_dis(res, b"<excl through the linear matcher>", len(want), len(dgot), "dfa excl")
            if (status.returncode == 0) != rx.search_excl(pat, exc, buf):
                add_dis(res, b"<search_excl on whole file>", status.returncode == 0, rx.search_excl(pat, exc, buf), "status")
            res.grep_pos += len(want)
            res.py_pos += len(got)
            if tg is not None:
                for i, ln in enumerate(extras):
                    if tag_of[i] in ("pos", "wrapped"):
                        res.generated += 1
                        res.generated_matched += run(["grep", "-qiE", "-e", c.pattern], ln + b"\n").returncode == 0
    finally:
        os.unlink(ex_path)
    finish(res)
    return res


def split_doc(s: bytes, r: random.Random) -> bytes:
    """Cut a positive at random places and rejoin with a line break, tab or CRLF."""
    if len(s) < 2:
        return s
    cuts = sorted(r.sample(range(1, len(s)), min(len(s) - 1, r.randint(1, 4))))
    out, prev = [], 0
    for k in cuts:
        out.append(s[prev:k])
        prev = k
    out.append(s[prev:])
    seps = [b"\n", b"\r\n", b"\t", b"\n\n", b"\n  ", b"\r"]
    return b"".join(p + (r.choice(seps) if i < len(out) - 1 else b"") for i, p in enumerate(out))


def make_docs(c: Case, r: random.Random, n: int = 360) -> tuple[list[bytes], list[str]]:
    parsed = rx.parse_ere(c.pattern, c.ci)
    pool = literal_pool(parsed.ast)
    docs: list[bytes] = []
    tags: list[str] = []
    positives = [p for p in (gen_positive(parsed, r, c.ci) for _ in range(120)) if p is not None]
    for p in positives[:90]:
        docs.append(p)
        tags.append("pos")
        docs.append(b"junk line\n" + p + b"\nmore junk\n")
        tags.append("wrapped")
        docs.append(split_doc(p, r))
        tags.append("split")
        docs.append(split_doc(b"x " + p + b" y", r))
        tags.append("split")
    for p in positives[:40]:
        for m in mutations(p, r, pool):
            docs.append(split_doc(m, r))
            tags.append("near")
    for e in EDGE_LINES[:25]:
        docs.append(e + b"\n" + e)
        tags.append("edge")
    # chunks of real lines
    return docs[: n * 4], tags[: n * 4]


def check_flat_case(c: Case, corpus_path: str, corpus: bytes, corpus_offs: list[int], r: random.Random) -> Result:
    res = Result(c.id, c.kind)
    try:
        comp = rx.ere_to_py(c.pattern, True)
        res.src = rx.ere_to_py_source(c.pattern, True).decode("latin-1")
    except rx.EREError as e:
        res.status = "TRANSLATION_FAILED"
        res.error = f"rx: {e}"
        return res
    docs, tags = make_docs(c, r)
    # corpus chunks: 150 documents of 1-12 consecutive real lines
    clines = corpus.split(b"\n")
    for _ in range(150):
        s = r.randrange(max(1, len(clines) - 12))
        docs.append(b"\n".join(clines[s:s + r.randint(1, 12)]) + r.choice([b"", b"\n"]))
        tags.append("corpus")
    # one grep per document through the helper's own pipeline would be slow: fold with the real tr, mark the document
    # boundary with \x02 (which tr leaves alone), turn it into a newline afterwards, and let one grep number the lines.
    blob = b"".join(d.replace(b"\x02", b"") + b"\x02" for d in docs)
    p = sh("tr '\\r\\n\\t' '   ' | tr '\\002' '\\n' | grep -n -iE -e \"$1\"", c.pattern, data=blob)
    p0 = sh("tr '\\r\\n\\t' '   ' | tr '\\002' '\\n' | grep -c -iE -e \"$1\"", c.pattern, data=blob)
    if p.returncode == 2 or (p.returncode not in (0, 1)) or p0.returncode == 2:
        res.status = "LATENT_BUG"
        res.error = "grep rejects the pattern (exit 2): " + p.stderr.decode("latin-1").strip()
        return res
    want = {int(x.split(b":", 1)[0]) for x in p.stdout.split(b"\n") if x}
    res.tested = len(docs)
    for i, d in enumerate(docs):
        d = d.replace(b"\x02", b"")
        got = rx.search_flat(comp, d)
        has = (i + 1) in want
        if rx.dfa_available(comp):
            view = rx.flat_view(d)
            dgot = bool(view) and rx.dfa_search(comp, view)
            if dgot != has:
                add_dis(res, d[:200], has, dgot, "dfa " + tags[i])
        # an empty document has no line at all in grep; the folded view of "\n" is one blank line
        if got != has:
            add_dis(res, d[:200], has, got, tags[i])
        if tags[i] == "pos":
            res.generated += 1
            res.generated_matched += has
    res.grep_pos = len(want)
    res.py_pos = sum(1 for d in docs if rx.search_flat(comp, d.replace(b"\x02", b"")))
    finish(res)
    return res


def check_pipe_o_excl_case(c: Case, corpus_path: str, corpus: bytes, corpus_offs: list[int], r: random.Random) -> Result:
    """grep -ohIE PATTERN FILE | grep -viE EXCL : the exclusion is tested against the matched TEXT, not the line."""
    res = Result(c.id, c.kind)
    try:
        comp = rx.ere_to_py(c.pattern, c.ci)
        exc = rx.ere_to_py(c.excl or "", True)
        res.src = rx.ere_to_py_source(c.pattern, c.ci).decode("latin-1")
    except rx.EREError as e:
        res.status = "TRANSLATION_FAILED"
        res.error = f"rx: {e}"
        return res
    extras, tags, distinct = make_extras(c.pattern, c.ci, r, n_pos=80)
    res.distinct = distinct
    # real-looking tokens: a positive between delimiters, with and without a placeholder word in it
    ex_parsed = rx.parse_ere(c.excl or "", True)
    more: list[bytes] = []
    for ln in [e for e, (_, t) in zip(extras, tags) if t == "pos"][:40]:
        more.append(ln)
        more.append(b"key=" + ln + b" more")
        more.append(b"[" + ln + b"]")
        e = gen_positive(ex_parsed, r, True)
        if e is not None and len(ln) > 8:
            k = r.randrange(1, len(ln) - 1)
            more.append(ln[:k] + e + ln[k:])
    extras = extras + more
    tag_of = [t for _, t in tags] + ["wrapped"] * len(more)
    buf = b"\n".join(extras) + b"\n"
    big = b"\n".join(extras) + b"\n" + corpus[: 3_000_000]
    for name, data in (("generated", buf), ("generated+corpus", big)):
        p = sh('grep -ohIE -e "$1" 2>/dev/null | grep -viE -e "$2" 2>/dev/null', c.pattern, c.excl or "", data=data)
        st = sh('grep -ohIE -e "$1" 2>/dev/null | grep -viE -e "$2" >/dev/null', c.pattern, c.excl or "", data=data)
        first = run(["grep", "-ohIE", "-e", c.pattern], data)
        if first.returncode == 2:
            res.status = "LATENT_BUG"
            res.error = "grep rejects the pattern: " + first.stderr.decode("latin-1").strip()
            return res
        want = p.stdout.split(b"\n")[:-1]
        toks = rx.only_matching(comp, data)
        got = [t for t in toks if exc.search(t) is None]
        res.tested += data.count(b"\n")
        raw_want = first.stdout.split(b"\n")[:-1]
        if raw_want != toks:
            for k in range(max(len(raw_want), len(toks))):
                a = raw_want[k] if k < len(raw_want) else None
                b = toks[k] if k < len(toks) else None
                if a != b:
                    add_dis(res, (a or b"<none>") + b" <> " + (b or b"<none>"), (a or b"").decode("latin-1")[:50],
                            (b or b"").decode("latin-1")[:50], "grep -o tokens (" + name + ")")
                    break
        if want != got:
            add_dis(res, b"<excl filter output differs>", len(want), len(got), "grep -o | grep -v (" + name + ")")
        if (st.returncode == 0) != bool(got):
            add_dis(res, b"<status>", st.returncode == 0, bool(got), "status (" + name + ")")
        res.grep_pos += len(raw_want)
        res.py_pos += len(toks)
    for i, ln in enumerate(extras):
        if tag_of[i] in ("pos", "wrapped"):
            res.generated += 1
            res.generated_matched += run(["grep", "-qE", *(["-i"] if c.ci else []), "-e", c.pattern], ln + b"\n").returncode == 0
    finish(res)
    return res


def check_pem_case(c: Case, corpus_path: str, corpus: bytes, corpus_offs: list[int], r: random.Random) -> Result:
    """grep -E -A5 -e HEADER FILE | tr '\\r\\n\\t' '   ' | grep -E -e HEADER-AND-BODY"""
    res = Result(c.id, c.kind)
    p2 = c.excl or ""
    try:
        c1 = rx.ere_to_py(c.pattern, False)
        c2 = rx.ere_to_py(p2, False)
        res.src = rx.ere_to_py_source(c.pattern).decode("latin-1") + "  THEN  " + rx.ere_to_py_source(p2).decode("latin-1")
    except rx.EREError as e:
        res.status = "TRANSLATION_FAILED"
        res.error = f"rx: {e}"
        return res
    parsed2 = rx.parse_ere(p2, False)
    docs: list[bytes] = []
    tags: list[str] = []
    for _ in range(140):
        full = gen_positive(parsed2, r, False)
        if full is None:
            continue
        head = gen_positive(rx.parse_ere(c.pattern, False), r, False) or b""
        # header, then body lines of assorted lengths, then unrelated lines
        body = bytes(r.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(r.choice([0, 20, 59, 60, 64, 70, 120])))
        parts = [head] + [body[k:k + 64] for k in range(0, len(body), 64)]
        gap = [b"x"] * r.choice([0, 0, 1, 3, 5, 6, 8])
        docs.append(b"\n".join(parts[:1] + gap + parts[1:]) + r.choice([b"", b"\n"]))
        tags.append("pos")
        docs.append(split_doc(full, r))
        tags.append("split")
        docs.append(b"junk\n" + full + b"\nmore\n")
        tags.append("wrapped")
        for m in mutations(full, r, b"-AB+/ "):
            docs.append(split_doc(m, r))
            tags.append("near")
    clines = corpus.split(b"\n")
    for _ in range(100):
        s = r.randrange(max(1, len(clines) - 10))
        docs.append(b"\n".join(clines[s:s + 10]))
        tags.append("corpus")
    res.tested = len(docs)
    with tempfile.TemporaryDirectory() as td:
        pth = os.path.join(td, "doc")
        for i, d in enumerate(docs):
            with open(pth, "wb") as f:
                f.write(d)
            st = sh("grep -E -A5 -e \"$1\" \"$3\" 2>/dev/null | tr '\\r\\n\\t' '   ' | grep -E -e \"$2\" >/dev/null", c.pattern, p2, pth)
            a5 = sh("grep -E -A5 -e \"$1\" \"$2\" 2>/dev/null", c.pattern, pth)
            if i == 0 and sh("grep -E -e \"$1\" /dev/null", c.pattern).returncode == 2:
                res.status = "LATENT_BUG"
                res.error = "grep rejects the header pattern"
                return res
            view = rx.after_context(c1, d, 5)
            if view != a5.stdout:
                add_dis(res, d[:200], a5.stdout[:80].decode("latin-1"), view[:80].decode("latin-1"), "after_context (-A5 output)")
            # tr maps every newline to a space, so the second grep reads ONE line that ends with a space
            folded = view.translate(rx._FLAT_TABLE)
            py = bool(folded) and c2.search(folded) is not None
            gr = st.returncode == 0
            if py != gr:
                add_dis(res, d[:200], gr, py, tags[i])
            res.grep_pos += gr
            res.py_pos += py
            if tags[i] == "pos":
                res.generated += 1
                res.generated_matched += gr
    finish(res)
    return res


CHECKERS = {"line": check_line_case, "extract": check_extract_case, "excl": check_excl_case, "flat": check_flat_case,
            "pipe_o_excl": check_pipe_o_excl_case, "pem": check_pem_case}

def hazards(c: Case) -> list[str]:
    """What the parser can say about a pattern that does not mean what its author probably meant."""
    out: list[str] = []
    for pat, ci in ((c.pattern, c.ci), (c.excl if c.kind in ("excl", "pipe_o_excl", "pem") else None, c.ci or c.kind == "excl")):
        if not pat:
            continue
        try:
            out += rx.parse_ere(pat, ci).warnings
        except rx.EREError:
            pass
    return sorted(set(out))


# ----- worker plumbing (fork: the corpus is shared copy-on-write) -----
_G: dict = {}


def _work_case(args) -> dict:
    c, seed = args
    t0 = time.perf_counter()
    r = random.Random(f"{seed}:{c.id}")
    try:
        res = CHECKERS[c.kind](c, _G["corpus_path"], _G["corpus"], _G["offs"], r)
    except Exception as exc:  # a crash in the checker is a failure of the gate, not of the pattern
        res = Result(c.id, c.kind, status="CHECKER_CRASH", error=f"{type(exc).__name__}: {exc}")
    res.seconds = time.perf_counter() - t0
    res.warnings = hazards(c)
    return res.__dict__


# ====================================================================================================
# timing
# ====================================================================================================
def adversarial_inputs(pattern: str, ci: bool, r: random.Random) -> list[tuple[str, bytes]]:
    parsed = rx.parse_ere(pattern, ci)
    sets: list[frozenset] = []

    def walk(n):
        if isinstance(n, rx.Set):
            sets.append(n.bits)
        elif isinstance(n, (rx.Cat, rx.Alt)):
            for x in n.items:
                walk(x)
        elif isinstance(n, (rx.Rep, rx.Group)):
            walk(n.node)

    walk(parsed.ast)
    pumps: list[int] = []

    def pick(bits: frozenset) -> int | None:
        pr = [b for b in sorted(bits) if 32 <= b < 127]
        if not pr:
            return None
        for pref in (32, 97, 48):
            if pref in pr:
                return pref
        return pr[0]

    # classes first (largest sets are the usual quantified ones), then single literals
    for bits in sorted(sets, key=lambda s: -len(s)):
        ch = pick(bits)
        if ch is not None and ch not in pumps:
            pumps.append(ch)
        if len(pumps) >= 4:
            break
    for bits in sets:
        if len(bits) == 1:
            ch = next(iter(bits))
            if 32 <= ch < 127 and ch not in pumps:
                pumps.append(ch)
            if len(pumps) >= 6:
                break
    out: list[tuple[str, bytes]] = [("a*65536", b"a" * ADV_SIZE), ("'a '*32768", b"a " * (ADV_SIZE // 2))]
    for ch in pumps:
        c = bytes([ch])
        name = repr(c.decode())
        out.append((f"{name}*65536", c * ADV_SIZE))
    for ch in pumps[:3]:
        c = bytes([ch])
        out.append((f"{c.decode()!r}*65000+tail", c * 65000 + b"\x01~\x01"))
    # the pattern's own positive, repeated without its last byte (an almost-match many times over)
    for _ in range(3):
        p = gen_positive(parsed, r, ci)
        if p and len(p) > 2:
            unit = p[:-1]
            out.append((f"positive[:-1]*{ADV_SIZE // (len(unit) + 1)}", (unit + b" ") * (ADV_SIZE // (len(unit) + 1))))
            break
    # a prefix of the pattern's first literal run repeated
    return out


GUARD_BUDGET = 0.25   # seconds re may spend before rx hands the buffer to the linear matcher
GUARD_LIMIT = 0.6     # a guarded search must finish within this


def timing_for(args) -> dict:
    pid, pattern, ci, seed = args
    r = random.Random(f"{seed}:t:{pid}")
    row = {"id": pid, "inputs": [], "max": 0.0, "worst": "", "timeouts": 0, "guard_max": 0.0, "dfa_max": 0.0,
           "disagree": 0, "dfa": False}
    try:
        comp = rx.ere_to_py(pattern, ci)
    except rx.EREError:
        return row
    row["dfa"] = rx.dfa_available(comp)
    inputs = adversarial_inputs(pattern, ci, r)
    for name, data in inputs:
        t0 = time.perf_counter()
        status = "ok"
        ans_re = None
        try:
            with rx.time_limit(ALARM_SECONDS):
                ans_re = comp.search(data) is not None
        except rx.RegexTimeout:
            status = "TIMEOUT"
        dt = time.perf_counter() - t0
        rec = {"name": name, "seconds": round(dt, 4), "status": status}
        # the mitigation: the same call the engine would make
        t0 = time.perf_counter()
        try:
            ans_guard = rx.search_lines(comp, data, budget=GUARD_BUDGET)
        except rx.RegexTimeout:
            ans_guard = None
        rec["guard_seconds"] = round(time.perf_counter() - t0, 4)
        row["guard_max"] = max(row["guard_max"], rec["guard_seconds"])
        if row["dfa"]:
            t0 = time.perf_counter()
            ans_dfa = rx.dfa_search(comp, data)
            rec["dfa_seconds"] = round(time.perf_counter() - t0, 4)
            row["dfa_max"] = max(row["dfa_max"], rec["dfa_seconds"])
            if ans_dfa != ans_guard or (ans_re is not None and ans_re != ans_dfa):
                row["disagree"] += 1
                rec["answers"] = {"re": ans_re, "guarded": ans_guard, "dfa": ans_dfa}
        elif ans_guard is None:
            rec["unguarded"] = True
        row["inputs"].append(rec)
        if dt > row["max"]:
            row["max"], row["worst"] = dt, name
        if status == "TIMEOUT":
            row["timeouts"] += 1
            if row["timeouts"] >= 3:
                break
    if row["max"] > SLOW_SECONDS:
        # real grep on the same slow inputs, for comparison
        byname = dict(inputs)
        for inp in row["inputs"]:
            if inp["seconds"] > SLOW_SECONDS:
                t0 = time.perf_counter()
                try:
                    run(["grep", "-cE", *(["-i"] if ci else []), "-e", pattern], byname[inp["name"]] + b"\n", timeout=30)
                    inp["grep_seconds"] = round(time.perf_counter() - t0, 4)
                except subprocess.TimeoutExpired:
                    inp["grep_seconds"] = ">30"
    return row


def alarm_self_test() -> dict:
    """The guard must really interrupt a runaway match: (a|aa)+$ against a^60 b is exponential in re."""
    import re as _re
    comp = _re.compile(rb"(a|aa)+$")
    data = b"a" * 60 + b"b"
    t0 = time.perf_counter()
    try:
        with rx.time_limit(1.0):
            comp.search(data)
        return {"interrupted": False, "seconds": time.perf_counter() - t0}
    except rx.RegexTimeout:
        return {"interrupted": True, "seconds": round(time.perf_counter() - t0, 3)}


# ====================================================================================================
# global behaviours (binary files, the folded view, the 5 MB cap)
# ====================================================================================================
def global_checks() -> list[dict]:
    out: list[dict] = []

    def rec(name: str, grep_says, rx_says, note: str = "", expect_equal: bool = True) -> None:
        out.append({"name": name, "grep": grep_says, "rx": rx_says, "equal": grep_says == rx_says,
                    "expected_equal": expect_equal, "note": note})

    # -- NUL bytes ------------------------------------------------------------------------------
    cases = [(b"x\x00a\n", r"^a"), (b"a\x00b\n", r"a.b"), (b"b\x00a\n", r"b.*a"), (b"a\x00\n", r"a$"), (b"\x00a\n", r"a")]
    for data, pat in cases:
        comp = rx.ere_to_py(pat)
        g_default = run(["grep", "-qE", "-e", pat], data).returncode == 0
        g_a = run(["grep", "-qaE", "-e", pat], data).returncode == 0
        rec(f"NUL {data!r} {pat!r}: grep default vs binary='grep'", g_default, rx.search_lines(comp, data, binary="grep"),
            "a NUL ends a line once grep decides the file is binary")
        rec(f"NUL {data!r} {pat!r}: grep -a vs binary='text'", g_a, rx.search_lines(comp, data, binary="text"))
    comp = rx.ere_to_py("a")
    rec("grep -I on a file with a NUL", run(["grep", "-qIE", "-e", "a"], b"a\x00b\n").returncode == 0,
        rx.search_lines(comp, b"a\x00b\n", binary="skip"))
    # grep_check_excl on a binary file: the first grep prints nothing, so the helper says "no match"
    p = sh('grep -hiE -e "$1" "$3" 2>/dev/null | grep -viE -e "$2" >/dev/null', "secret", "zzzz", "/dev/stdin", data=b"secret\x00\n")
    rec("grep_check_excl on a file holding a NUL (bash answer vs rx binary='text')", p.returncode == 0,
        rx.search_excl("secret", "zzzz", b"secret\x00\n"),
        "bash returns FALSE (the rule is blind to any file with a NUL byte); rx does not copy that",
        expect_equal=False)
    out[-1]["known_id"] = "excl_blind_spot"
    rec("grep_check_excl on a file holding a NUL (bash answer vs rx binary='grep')", p.returncode == 0,
        rx.search_excl("secret", "zzzz", b"secret\x00\n", binary="grep"))
    # -- the folded view and the cap ------------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        for size, label in ((rx.FLAT_CAP, "5242880 bytes"), (rx.FLAT_CAP + 1, "5242881 bytes")):
            path = os.path.join(td, "f")
            body = b"<!ENTITY a SYSTEM \"file:///etc/passwd\">"
            data = body + b" " * (size - len(body))
            with open(path, "wb") as f:
                f.write(data)
            helper = ('grep_flat() { [[ "$(wc -c < "$2" 2>/dev/null || echo 0)" -le 5242880 ]] || return 1; '
                      "tr '\\r\\n\\t' '   ' < \"$2\" | grep -iE -e \"$1\" >/dev/null; }; grep_flat \"$1\" \"$2\"")
            g = sh(helper, r"<!ENTITY[^>]*[[:space:]]SYSTEM", path)
            comp = rx.ere_to_py(r"<!ENTITY[^>]*[[:space:]]SYSTEM", True)
            rec(f"grep_flat on a file of {label}", g.returncode == 0, rx.search_flat(comp, data),
                "over the cap the bash helper returns 1: the file is not cut, it is skipped")
        data = b"<!ENTITY\n  a\n\tSYSTEM\r\n\"file:///x\">\n"
        path = os.path.join(td, "g")
        Path(path).write_bytes(data)
        g = sh(helper, r"<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+[\"'](file:|/)", path)
        comp = rx.ere_to_py(r"<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+[\"'](file:|/)", True)
        rec("grep_flat across newline, tab and CRLF", g.returncode == 0, rx.search_flat(comp, data))
    # -- a hostile line must neither hide a real finding nor stall the scan ------------------------------------
    hostile_cases = [
        (r"certutil(\.exe)?[^|&]*[-/]decode[^|&]*\.(exe|dll|bat|cmd|ps1|vbs)", True),
        (r"\{\{[^}]*(request\.|user\.|\.env\.)", False),
        (r"<script[^>]+src=[\"']?http://", True),
        (r"curl\s+.*\|\s*(bash|sh)|wget\s+.*\|\s*(bash|sh)", False),
    ]
    r = random.Random(7)
    for pat, ci in hostile_cases:
        parsed = rx.parse_ere(pat, ci)
        positive = gen_positive(parsed, r, ci) or b""
        unit = positive[:-1] + b" "
        hostile = unit * (ADV_SIZE // len(unit))
        comp = rx.ere_to_py(pat, ci)
        for label, data, want in (("hostile line only", hostile + b"\n", False),
                                  ("hostile line, then a real finding on the next line", hostile + b"\n" + positive + b"\n", True),
                                  ("a real finding, then the hostile line", positive + b"\n" + hostile + b"\n", True)):
            g = run(["grep", "-qE", *(["-i"] if ci else []), "-e", pat], data).returncode == 0
            t0 = time.perf_counter()
            got = rx.search_lines(comp, data, budget=GUARD_BUDGET)
            dt = time.perf_counter() - t0
            out.append({"name": f"{label}: {pat[:50]}", "grep": g, "rx": got, "equal": g == got and dt < GUARD_LIMIT,
                        "expected_equal": True, "note": f"guarded search took {dt:.3f} s, limit {GUARD_LIMIT} s; "
                                                         f"answer should be {want}"})
    # the folded view of a 4.5 MB document of unterminated declarations (grep_flat has no line to cut it at)
    pat = r"<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+[\"'](file:|/)"
    comp = rx.ere_to_py(pat, True)
    helper = ("tr '\\r\\n\\t' '   ' | grep -iE -e \"$1\" >/dev/null")
    for label, tail in (("4.5 MB of <!ENTITY with no '>'", b""),
                        ("the same, with a real external entity at the end", b'<!ENTITY x SYSTEM "file:///etc/passwd">\n')):
        doc = b"<!ENTITY a\n" * 400_000 + tail
        g = sh(helper, pat, data=doc).returncode == 0
        t0 = time.perf_counter()
        got = rx.search_flat(comp, doc, budget=GUARD_BUDGET)
        dt = time.perf_counter() - t0
        out.append({"name": f"grep_flat on {label} ({len(doc) // 1024} KB)", "grep": g, "rx": got,
                    "equal": g == got and dt < 5.0, "expected_equal": True,
                    "note": f"guarded search took {dt:.2f} s (the linear matcher walks 4.5 MB in pure Python)"})
    # -- empty input ----------------------------------------------------------------------------
    for pat in ("x*", "^$", ""):
        comp = rx.ere_to_py(pat)
        rec(f"empty file, pattern {pat!r}", run(["grep", "-qE", "-e", pat], b"").returncode == 0, rx.search_lines(comp, b""))
        rec(f"one empty line, pattern {pat!r}", run(["grep", "-qE", "-e", pat], b"\n").returncode == 0, rx.search_lines(comp, b"\n"))
        rec(f"no trailing newline, pattern {pat!r}", run(["grep", "-qE", "-e", pat], b"ab").returncode == 0, rx.search_lines(comp, b"ab"))
    return out


# ====================================================================================================
# synthetic EREs: a second, pattern-independent gate for the translator itself
# ====================================================================================================
SYN_ATOMS = ["a", "b", "c", "x", "-", ".", "]", "[", "{", "}", ",", "1", "2", " ", "\\\\", "^", "$", "(", ")", "|", "*", "+",
             "?", "[ab]", "[^a]", "[[:alpha:]]", "[[:space:]]", "[^[:space:]]", "\\w", "\\W", "\\s", "\\S", "\\b",
             "\\B", "\\<", "\\>", "a{2}", "{1,2}", "{,2}", "{2,}", "(a|b)", "(a)", "\\1", "\\2", "\\.", "\\d", "\\n",
             "[]a]", "[^]a]", "[a-c]", "[\\\\]", "[a\\\\]", "[^a-c]", "()", "(|a)", "(a|)", "a*", "b+", "c?", "\\(", "\\)",
             "\\{", "[a-]", "[-a]", "\\`", "\\'", "[a-c-e]", "[:a:]", "[^]", "\\", "a{", "a{1", "a{1,", "a{,}", "a{1,2,3}",
             "a{}", "((a))", "(a(b))\\2", "(a*)*", "(a|b)+", "(a+)+", "a*?", "a+?", "a??", "a*+", "a++", "(ab|a)(bc|c)",
             "(a{2,3})*", "(a{2})+", "(ab+)+", "(a|ab)*", "(a?)*", "(a*){2,3}", "x(a{1,2}){2,3}y", "(a+){2}", "(^a)*", "(b|^)+",
             "\\<a", "a\\>", "\\bab\\b", "[^b]\\b", "(\\b)+a"]
SYN_ALPHA = list("abcx -.[]{},12\\^$()|*+?_\t")


def synthetic_gate(n: int, seed: int) -> dict:
    r = random.Random(seed)
    stats = {"patterns": n, "grep_rejects": 0, "grep_rejects_rx_accepts": 0, "rx_rejects_valid": 0, "unsupported": 0,
             "valid": 0, "mismatches": [], "ignore_case": 0, "no_simplify_checked": 0}
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "lines")
        for _ in range(n):
            k = r.randint(1, 8)
            pat = "".join(r.choice(SYN_ATOMS) for _ in range(k))
            ci = r.random() < 0.3
            lines = list({"".join(r.choice(SYN_ALPHA) for _ in range(r.randint(0, 9))) for _ in range(50)})
            lines += [pat, pat.replace("\\", ""), "a" + pat + "b", "aa", "abab", "a b", "ab1", "x-"]
            lines = [x.encode("latin-1") for x in lines if "\n" not in x]
            Path(path).write_bytes(b"\n".join(lines) + b"\n")
            nums, err = grep_numbers(pat, path, ci=ci, text=False, ere=True)
            try:
                comp = rx.ere_to_py(pat, ci)
                got_err = None
            except rx.UnsupportedERE:
                stats["unsupported"] += 1
                continue
            except rx.EREError as e:
                comp, got_err = None, str(e)
            if nums is None:
                stats["grep_rejects"] += 1
                if comp is not None and "stack overflow" not in err and "memory exhausted" not in err:
                    stats["grep_rejects_rx_accepts"] += 1
                    stats["mismatches"].append({"pattern": pat, "ci": ci, "what": "rx accepts a pattern grep rejects: " + err})
                continue
            if comp is None:
                stats["rx_rejects_valid"] += 1
                stats["mismatches"].append({"pattern": pat, "ci": ci, "what": "rx rejects a pattern grep accepts: " + str(got_err)})
                continue
            stats["valid"] += 1
            stats["ignore_case"] += ci
            have = {i + 1 for i, ln in enumerate(lines) if comp.search(ln)}
            raw = rx.ere_to_py(pat, ci, simplify=False)
            have_raw = {i + 1 for i, ln in enumerate(lines) if raw.search(ln)}
            stats["no_simplify_checked"] += 1
            have_dfa = {i + 1 for i, ln in enumerate(lines) if rx.dfa_search(comp, ln + b"\n")} if rx.dfa_available(comp) else nums
            stats["dfa_checked"] = stats.get("dfa_checked", 0) + (1 if rx.dfa_available(comp) else 0)
            if have != nums or have_raw != nums or have_dfa != nums:
                bad = sorted((have ^ nums) | (have_raw ^ nums) | (have_dfa ^ nums))[:2]
                stats["mismatches"].append({"pattern": pat, "ci": ci, "what": "line sets differ",
                                            "lines": [lines[i - 1].decode("latin-1") for i in bad],
                                            "grep_matches": [i in nums for i in bad], "rx_matches": [i in have for i in bad],
                                            "rx_unsimplified_matches": [i in have_raw for i in bad],
                                            "dfa_matches": [i in have_dfa for i in bad],
                                            "src": rx.ere_to_py_source(pat, ci).decode("latin-1")})
    stats["lattice"] = nested_lattice()
    for m in stats["lattice"]["mismatches"]:
        stats["mismatches"].append(m)
    return stats


QUANTS = ["*", "+", "?", "{2}", "{2,3}", "{1,3}", "{0,2}", "{2,}", "{3}", "{1}", "{0}", "{,2}"]


def nested_lattice() -> dict:
    """Every inner x outer quantifier pair on an atom and on a group, anchored three ways, on a^0..a^10 and ab strings.

    This is what the simplifier rewrites ((a+)+ -> a+, (a{2,3})* ...), so it is held to grep exhaustively, not by sampling."""
    out = {"patterns": 0, "mismatches": []}
    words = [b"a" * k for k in range(0, 11)] + [b"ab" * k for k in range(1, 5)] + [b"aab", b"aba", b"b", b"abab" + b"a"]
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "w")
        Path(path).write_bytes(b"\n".join(words) + b"\n")
        for atom in ("a", "(ab)", "(a|b)", "[ab]"):
            for qi in QUANTS:
                for qo in QUANTS:
                    for wrap in ("^%s$", "^%s", "%s$", "%s"):
                        pat = wrap % (f"({atom}{qi}){qo}" if not atom.startswith("(") else f"({atom}{qi}){qo}")
                        nums, _err = grep_numbers(pat, path, ci=False, text=False, ere=True)
                        if nums is None:
                            continue
                        out["patterns"] += 1
                        for simp in (True, False):
                            comp = rx.ere_to_py(pat, False, simplify=simp)
                            have = {i + 1 for i, w in enumerate(words) if comp.search(w)}
                            if have != nums:
                                out["mismatches"].append({"pattern": pat, "ci": False, "what": f"nested repetition lattice (simplify={simp})",
                                                          "lines": [words[i - 1].decode() for i in sorted(have ^ nums)[:2]],
                                                          "src": rx.ere_to_py_source(pat, False, simplify=simp).decode("latin-1")})
    return out


# ====================================================================================================
# known divergences, report
# ====================================================================================================
def load_known() -> dict[tuple[str, str], dict]:
    if not KNOWN_PATH.exists():
        return {}
    out = {}
    for e in json.loads(KNOWN_PATH.read_text(encoding="utf-8")):
        out[(e["id"], e.get("kind", "disagreement"))] = e
    return out


def kind_of_status(status: str) -> str:
    return {"DIVERGES": "disagreement", "LATENT_BUG": "latent_bug", "UNEXERCISED": "unexercised",
            "TRANSLATION_FAILED": "translation", "CHECKER_CRASH": "checker"}.get(status, status)


def verify_examples(known: dict, cases: dict) -> list[dict]:
    """Entries of kind latent_bug may carry example lines: grep and rx must agree on each, and agree with the recorded answer."""
    out = []
    for (kid, kind), e in known.items():
        if kind != "latent_bug" or kid not in cases:
            continue
        c = cases[kid]
        for ex in e.get("examples", []):
            data = ex["line"].encode("latin-1") + b"\n"
            g = run(["grep", "-qE", *(["-i"] if c.ci else []), "-e", c.pattern], data).returncode == 0
            comp = rx.ere_to_py(c.pattern, c.ci)
            r_ = rx.search_lines(comp, data)
            out.append({"id": kid, "line": ex["line"], "grep": g, "rx": r_, "recorded": ex["grep_matches"],
                        "intended": ex.get("intended_to_match"), "ok": g == r_ == ex["grep_matches"]})
    return out


def md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def write_report(path: Path, ctx: dict) -> None:
    results: list[dict] = ctx["results"]
    cases: dict[str, Case] = ctx["cases"]
    timing: dict[str, dict] = ctx["timing"]
    known = ctx["known"]
    L: list[str] = []
    A = L.append
    A("# Pattern conformance: rx.py against GNU grep\n")
    A(f"Generated by `tests/conformance/pattern_fuzz.py` on {time.strftime('%Y-%m-%d %H:%M:%S')}. "
      f"`{ctx['grep_version']}`, `LC_ALL=C`, Python {sys.version.split()[0]}.\n")
    A(f"Source of the patterns: `{ctx['source']}` (sha256 `{ctx['source_sha'][:16]}`), seed {ctx['seed']}. "
      f"Corpus: {ctx['corpus_lines']} real lines (sha256 `{ctx['corpus_sha'][:16]}`).\n")
    n = len(results)
    clean = [x for x in results if x["status"] == "clean"]
    by_status = Counter(x["status"] for x in results)
    A("## Summary\n")
    A(f"- Patterns checked: **{n}**; clean: **{len(clean)}**; not clean: **{n - len(clean)}** "
      f"({', '.join(f'{k} {v}' for k, v in sorted(by_status.items()) if k != 'clean') or 'none'}).")
    unexplained = ctx["unexplained"]
    A(f"- Unexplained (not in known_pattern_divergences.json): **{len(unexplained)}**.")
    A(f"- Lines compared: {sum(x['tested'] for x in results):,}; lines carrying a generated positive that matched in grep: "
      f"{sum(x['generated_matched'] for x in results):,} of {sum(x['generated'] for x in results):,}; every pattern had at "
      f"least {min(x['generated_matched'] for x in results)} such lines matched by grep, and "
      f"{sum(1 for x in results if x.get('distinct', 99) < 30)} patterns have fewer than 30 DISTINCT positives (small languages).")
    if ctx["timing"]:
        slow = [t for t in timing.values() if t["max"] > SLOW_SECONDS]
        A(f"- Timing: {len(timing)} patterns on adversarial 64 KB lines; **{len(slow)}** slower than {SLOW_SECONDS} s "
          f"(alarm {ALARM_SECONDS} s); alarm self-test: "
          f"{'interrupted a runaway match after ' + str(ctx['alarm']['seconds']) + ' s' if ctx['alarm']['interrupted'] else 'DID NOT INTERRUPT'}.")
    syn = ctx.get("synthetic")
    if syn:
        A(f"- Synthetic EREs (translator only, no pipeline pattern): {syn['patterns']} generated, {syn['valid']} accepted by grep and "
          f"compared line by line ({syn['ignore_case']} with -i; each also compiled without simplification, and {syn.get('dfa_checked', 0)} through the linear matcher), "
          f"{syn['grep_rejects']} rejected by grep, {syn['unsupported']} refused by rx as unsupported; "
          f"**{len(syn['mismatches'])} disagreements**. Plus the nested-repetition lattice (every inner x outer quantifier pair on four "
          f"atoms, four anchorings, simplified and not): {syn['lattice']['patterns']} patterns against grep.")
    A("")
    A("## Inventory\n")
    recs = ctx["records"]

    A("| helper | call sites | pattern records | what it runs |")
    A("|---|---:|---:|---|")
    what = {"grep_check": "`grep -qE -e P FILE`", "grep_check_i": "`grep -qiE -e P FILE`",
            "grep_check_excl": "`grep -hiE -e P FILE | grep -viE -e X`", "grep_flat": "`tr '\\r\\n\\t' '   ' < FILE | grep -iE -e P` (skipped over 5 MB)",
            "_pdf_has": "`grep -qaE -e P FILE`", "grep": "direct: `-qiE`, `-oE`, `-c`, `-A5 | tr | grep`, `-o | grep -v`, and 8 BRE"}
    tot_s = tot_r = 0
    for h in ("grep_check", "grep_check_i", "grep_check_excl", "grep_flat", "_pdf_has", "grep"):
        hr = [r for r in recs if r["helper"] == h]
        nr = len(hr)
        ns = sum(1 for r in hr if not r.get("parent_line")) + len({r["parent_line"] for r in hr if r.get("parent_line")})
        tot_s += ns
        tot_r += nr
        A(f"| {h if h != 'grep' else 'grep (direct)'} | {ns} | {nr} | {what[h]} |")
    A(f"| **total** | **{tot_s}** | **{tot_r}** | the credential-format site (line 903) is one call site and 18 records, one per provider |")
    A("")
    dyn = {}
    for r in recs:
        if r.get("dynamic"):
            dyn.setdefault((r["line"], r.get("pattern_text", "")), []).append(r)
    A(f"Dynamic patterns (the pattern word holds a shell variable): **{len(dyn)}** call sites. Each is resolved by running the "
      f"defining assignment(s) in a clean bash, never by re-implementing them, and the resolved text is then fuzzed like any other:\n")
    for (ln, txt), rs in sorted(dyn.items()):
        r0 = rs[0]
        A(f"- line {ln}, `{r0['enclosing_function']}`, `{r0['helper']}`: `{md_escape(txt[:70])}` -> {len(rs)} pattern(s), {r0.get('resolved_by', 'UNRESOLVED')}")
    A("")
    A("## By helper\n")
    A("| helper | mode | patterns | clean | not clean |")
    A("|---|---|---:|---:|---:|")
    rows: dict[tuple[str, str], list[int]] = {}
    for x in results:
        c = cases[x["id"]]
        k = (c.helper, c.mode)
        v = rows.setdefault(k, [0, 0, 0])
        v[0] += 1
        v[1] += x["status"] == "clean"
        v[2] += x["status"] != "clean"
    for (h, m), v in sorted(rows.items()):
        A(f"| {h} | {m} | {v[0]} | {v[1]} | {v[2]} |")
    A("")
    if ctx["unresolved"]:
        A("## Not fuzzed (the pattern text cannot be known statically)\n")
        for rec in ctx["unresolved"]:
            A(f"- line {rec['line']} `{rec['enclosing_function']}` `{rec['helper']}`: `{md_escape(rec.get('pattern_text', rec.get('pattern_raw', '')))}`")
        A("")
    A("## Global behaviours\n")
    A("| check | grep | rx | result |")
    A("|---|---|---|---|")
    for g in ctx["globals"]:
        res = "same" if g["equal"] else ("DIFFERS (documented)" if not g["expected_equal"] else "**DIFFERS**")
        A(f"| {md_escape(g['name'])} | {g['grep']} | {g['rx']} | {res} |")
    A("")
    A("## Latent bugs in the bash patterns\n")
    haz = [x for x in results if x.get("warnings")]
    if not haz:
        A("None found by the parser's hazard checks (stray backslash escapes such as `\\d`, a backslash inside a bracket "
          "expression, `+?` / `*?`, an empty alternative, a word boundary next to a character that cannot be a word "
          "character).\n")
    else:
        A("These patterns behave identically in bash and in rx, so they are not translation errors; they are rules that do not "
          "mean what they were probably written to mean. Each is verified below against the real grep.\n")
        for x in haz:
            c = cases[x["id"]]
            kn = known.get((x["id"], "latent_bug"))
            A(f"### `{x['id']}` — line {c.line}, `{c.function}`{'' if kn else ' (NOT IN THE REGISTER)'}\n")
            A(f"- pattern: `{md_escape(c.pattern)}`")
            for w in x["warnings"]:
                A(f"- {md_escape(w)}")
            if kn:
                A(f"- register: **{kn.get('decision', '')}** — {kn.get('reason', '')}")
            for pr in [p for p in ctx["proofs"] if p["id"] == x["id"]]:
                A(f"  - `{md_escape(pr['line'])}` -> grep {'matches' if pr['grep'] else 'does NOT match'}, rx {'matches' if pr['rx'] else 'does NOT match'}"
                  f"{' (this line is the kind of code the rule was written to catch)' if pr['intended'] else ''}")
            A("")
    A("## Problem patterns\n")
    problems = [x for x in results if x["status"] != "clean"]
    if not problems:
        A("None.\n")
    for x in problems:
        c = cases[x["id"]]
        kk = (x["id"], kind_of_status(x["status"]))
        kn = known.get(kk)
        A(f"### `{x['id']}` — {x['status']}{'' if kn else ' (UNEXPLAINED)'}\n")
        A(f"- line {c.line} in `{c.function}`, `{c.helper}` ({c.mode}), flags `{c.flags}`")
        A(f"- pattern: `{md_escape(c.pattern)}`" + (f"\n- exclusion / second pattern: `{md_escape(c.excl)}`" if c.excl else ""))
        if x["error"]:
            A(f"- error: {md_escape(x['error'])}")
        A(f"- lines tested {x['tested']}, grep matched {x['grep_pos']}, rx matched {x['py_pos']}, generated positives "
          f"{x['generated_matched']}/{x['generated']}, disagreements {x['n_disagree']}")
        for d in x["disagreements"][:4]:
            A(f"  - [{d['tag']}] `{md_escape(d['line'])}`: grep={d['grep']} python={d['python']}")
        if kn:
            A(f"- known: **{kn.get('decision', '')}** — {kn.get('reason', '')}")
        A("")
    A("## Timing flags\n")
    slow = sorted((t for t in timing.values() if t["max"] > SLOW_SECONDS), key=lambda t: -t["max"])
    A(f"Raw `re` is run with a {ALARM_SECONDS} s alarm on each adversarial 64 KB line. `guarded` is "
      f"`rx.search_lines(..., budget={GUARD_BUDGET})`: re for up to {GUARD_BUDGET} s, then the linear matcher. "
      f"`dfa` is the linear matcher alone; `grep` is the real grep on the same line.\n")
    if not slow:
        A(f"No pattern took more than {SLOW_SECONDS} s on any adversarial input.\n")
    else:
        A("| id | line | worst input | re s | guarded s | dfa s | grep s | answers agree | pattern | explained |")
        A("|---|---:|---|---:|---:|---:|---:|---|---|---|")
        for t in slow:
            c = cases[t["id"]]
            w = max(t["inputs"], key=lambda i: i["seconds"])
            kn = known.get((t["id"], "timing"))
            A(f"| {t['id']} | {c.line} | {md_escape(t['worst'])} | {w['seconds']}{' (alarm)' if w['status'] == 'TIMEOUT' else ''} | "
              f"{t['guard_max']} | {t['dfa_max'] if t['dfa'] else 'n/a'} | {w.get('grep_seconds', '')} | "
              f"{'yes' if not t['disagree'] else '**NO**'} | `{md_escape(c.pattern[:80])}` | {'yes (mitigated, see register)' if kn else '**NO**'} |")
        A("")
    gm = [t for t in timing.values()]
    if gm:
        A(f"Across all {len(gm)} compiled patterns the slowest guarded search took {max(t['guard_max'] for t in gm):.3f} s "
          f"and the slowest linear-matcher run {max(t['dfa_max'] for t in gm):.3f} s; "
          f"{sum(1 for t in gm if t['disagree'])} patterns had guarded / dfa / re answers that disagreed; "
          f"{sum(1 for t in gm if not t['dfa'])} pattern records have no linear matcher: the 18 credential records share one exclusion "
          f"(KNOWN_CRED_EXCL) that contains a back-reference, and it only ever runs on the text of one matched token.\n")
    A("## All patterns\n")
    A("`grep+` lines grep matched; `gen+` lines carrying a generated positive that grep matched / lines generated; "
      "`distinct` different positives the parse tree produced (a literal has one; such a pattern is padded with the same "
      "positive in different surroundings so that at least 40 lines carry one).\n")
    A("| id | line | function | helper | mode | tested | grep+ | gen+ | distinct | status | max s |")
    A("|---|---:|---|---|---|---:|---:|---:|---:|---|---:|")
    for x in sorted(results, key=lambda x: cases[x["id"]].line):
        c = cases[x["id"]]
        t = timing.get(x["id"])
        A(f"| {x['id']} | {c.line} | {c.function} | {c.helper} | {c.mode} | {x['tested']} | {x['grep_pos']} | "
          f"{x['generated_matched']}/{x['generated']} | {x.get('distinct', '')} | {x['status']} | {round(t['max'], 3) if t else ''} |")
    A("")
    path.write_text("\n".join(L), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patterns", default=str(HERE / "patterns.json"))
    ap.add_argument("--report", default=str(HERE / "pattern_report.md"))
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2)))
    ap.add_argument("--seed", type=int, default=20261112)
    ap.add_argument("--quick", action="store_true", help="a 20000-line corpus and no timing pass")
    ap.add_argument("--no-timing", action="store_true")
    ap.add_argument("--only", nargs="*", default=[], help="pattern ids (or substrings) to check")
    ap.add_argument("--synthetic", type=int, default=2000, help="synthetic EREs to compare (0 to skip)")
    ap.add_argument("--locale", default="C", help="LC_ALL for the real grep (default C; C.utf8 measures the locale divergence "
                                                   "and is expected to fail the gate)")
    a = ap.parse_args(argv)
    ENV["LC_ALL"] = a.locale

    records = json.loads(Path(a.patterns).read_text(encoding="utf-8"))
    cases_l, unresolved = cases_from_inventory(records)
    if a.only:
        cases_l = [c for c in cases_l if any(o in c.id for o in a.only)]
    cases = {c.id: c for c in cases_l}
    if len(cases) != len(cases_l):
        dup = [k for k, v in Counter(c.id for c in cases_l).items() if v > 1]
        print("duplicate case ids:", dup, file=sys.stderr)
        return 2

    gv = run(["grep", "--version"]).stdout.decode().splitlines()[0]
    corpus_lines = build_corpus(cap=20_000 if a.quick else CORPUS_CAP)
    corpus = b"\n".join(corpus_lines) + b"\n"
    offs = line_offsets(corpus)
    tmpdir = tempfile.mkdtemp(prefix="rxfuzz_")
    corpus_path = os.path.join(tmpdir, "corpus.txt")
    Path(corpus_path).write_bytes(corpus)
    _G.update(corpus=corpus, corpus_path=corpus_path, offs=offs)
    print(f"{gv}; {len(cases)} patterns; corpus {len(corpus_lines)} lines, {len(corpus)} bytes; jobs {a.jobs}", flush=True)

    t0 = time.time()
    ctx_mp = mp.get_context("fork")
    with ctx_mp.Pool(a.jobs) as pool:
        results = []
        for i, d in enumerate(pool.imap_unordered(_work_case, [(c, a.seed) for c in cases_l], chunksize=1), 1):
            results.append(d)
            if i % 40 == 0:
                print(f"  {i}/{len(cases_l)} patterns ({time.time() - t0:.0f}s)", flush=True)
    timing: dict[str, dict] = {}
    alarm = alarm_self_test()
    if not (a.quick or a.no_timing):
        jobs = [(c.id, c.pattern, c.ci, a.seed) for c in cases_l if c.kind != "pem"]
        jobs += [(c.id + "/hdr", c.pattern, False, a.seed) for c in cases_l if c.kind == "pem"]
        jobs += [(c.id + "/body", c.excl, False, a.seed) for c in cases_l if c.kind == "pem"]
        jobs += [(c.id + "/excl", c.excl, True, a.seed) for c in cases_l if c.kind in ("excl", "pipe_o_excl") and c.excl]
        print(f"timing pass: {len(jobs)} compiled patterns, alarm self-test {alarm}", flush=True)
        with ctx_mp.Pool(a.jobs) as pool:
            for row in pool.imap_unordered(timing_for, jobs, chunksize=1):
                timing[row["id"]] = row
        for jid in list(timing):
            if "/" in jid and jid.rsplit("/", 1)[1] in ("hdr", "body", "excl"):
                base = jid.rsplit("/", 1)[0]
                if base not in cases:
                    continue
                cur = timing.get(base)
                sub = timing.pop(jid)
                if cur is None:
                    cur = dict(sub, id=base)
                    timing[base] = cur
                    continue
                keep = sub if sub["max"] > cur["max"] else cur
                merged = dict(keep, id=base, worst=keep["worst"] + (f" [{jid.rsplit('/', 1)[1]} pattern]" if keep is sub else ""))
                merged["guard_max"] = max(sub["guard_max"], cur["guard_max"])
                merged["dfa_max"] = max(sub["dfa_max"], cur["dfa_max"])
                merged["disagree"] = sub["disagree"] + cur["disagree"]
                merged["dfa"] = sub["dfa"] and cur["dfa"]
                merged["timeouts"] = sub["timeouts"] + cur["timeouts"]
                timing[base] = merged
    glob = global_checks()
    syn = synthetic_gate(a.synthetic, a.seed) if a.synthetic else None

    known = load_known()
    results.sort(key=lambda d: cases[d["id"]].line)
    unexplained: list[str] = []
    for d in results:
        if d["status"] != "clean" and (d["id"], kind_of_status(d["status"])) not in known:
            unexplained.append(f"{d['id']} ({d['status']})")
    for pid, t in timing.items():
        if t["max"] > SLOW_SECONDS and (pid, "timing") not in known:
            unexplained.append(f"{pid} (timing {t['max']:.2f}s on {t['worst']})")
        if t["disagree"]:
            unexplained.append(f"{pid} (guarded / linear / re answers disagree on an adversarial line)")
        if t["guard_max"] > GUARD_LIMIT:
            unexplained.append(f"{pid} (guarded search still took {t['guard_max']:.2f}s)")
    for d in results:
        for w in d.get("warnings", []):
            if (d["id"], "latent_bug") not in known:
                unexplained.append(f"{d['id']} (hazard: {w[:90]})")
                break
    proofs = verify_examples(known, cases)
    for pr in proofs:
        if not pr["ok"]:
            unexplained.append(f"example for {pr['id']} does not behave as recorded: {pr}")
    for g in glob:
        if g["expected_equal"] and not g["equal"]:
            unexplained.append("global: " + g["name"])
        if not g["expected_equal"] and ("global:" + g.get("known_id", ""), "global") not in known:
            unexplained.append("global difference without a register entry: " + g["name"])
    if syn and syn["mismatches"]:
        unexplained.append(f"synthetic: {len(syn['mismatches'])} disagreements")
    if not alarm["interrupted"] and not (a.quick or a.no_timing):
        unexplained.append("the SIGALRM guard did not interrupt a runaway match")

    ctx = {"results": results, "cases": cases, "timing": timing, "known": known, "unexplained": unexplained, "proofs": proofs,
           "records": records,
           "unresolved": unresolved, "globals": glob, "synthetic": syn, "alarm": alarm, "grep_version": gv,
           "source": records[0].get("source", "") if records else "", "source_sha": records[0].get("source_sha256", "") if records else "",
           "seed": a.seed, "corpus_lines": len(corpus_lines), "corpus_sha": hashlib.sha256(corpus).hexdigest()}
    write_report(Path(a.report), ctx)
    for t in timing.values():
        if t["max"] <= SLOW_SECONDS:
            t["inputs"] = f"{len(t['inputs'])} inputs, all under {SLOW_SECONDS} s"
    machine = {"grep": gv, "seed": a.seed, "corpus_lines": len(corpus_lines),
               "patterns": len(results), "clean": sum(1 for d in results if d["status"] == "clean"),
               "unexplained": unexplained, "results": results, "timing": timing, "globals": glob, "synthetic": syn,
               "alarm_self_test": alarm, "unresolved": [{k: r_[k] for k in ("id", "line", "helper") if k in r_} for r_ in unresolved]}
    Path(a.report).with_suffix(".json").write_text(json.dumps(machine, indent=1), encoding="utf-8")
    for p in Path(tmpdir).iterdir():
        p.unlink()
    os.rmdir(tmpdir)
    print(f"{len(results)} patterns, {machine['clean']} clean, {len(unexplained)} unexplained -> {a.report}", flush=True)
    for u in unexplained[:30]:
        print("  UNEXPLAINED:", u)
    return 1 if unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
