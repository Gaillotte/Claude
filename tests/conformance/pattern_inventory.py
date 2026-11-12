#!/usr/bin/env python3
"""Static inventory of every regular-expression call site in scan_pipeline.sh.

    python3 -I tests/conformance/pattern_inventory.py [scan_pipeline.sh] [--out patterns.json] [--summary]

The Python engine will apply these patterns in-process (transit/rx.py), so the first question is
"which patterns are there, how does bash hand each one to grep, and which cannot be read statically".
This tool answers it without running the script.

What it extracts
    * the four helpers   grep_check (line), grep_check_i (line_i), grep_check_excl (excl), grep_flat (flat);
    * the fifth helper   _pdf_has (line_a, ``grep -qaE`` with the arguments in the order FILE PATTERN);
    * every DIRECT grep invocation outside the helpers (mode ``direct``): ``grep -qiE``, ``grep -oE``,
      ``grep -E -A5``, and the few that are BRE (no -E) or fixed-string, recorded with ``dialect``.

How
    The file is tokenised by a small bash lexer, not by splitting lines: heredoc bodies and comments are
    skipped, backslash-newline continuations are joined, and the quoting is resolved the way bash resolves it
    ('..' literal, ".." with only \\$ \\` \\" \\\\ escaped, adjacent pieces concatenated, so the idiom
    '"'"' yields one quote). shlex was tried first and is wrong for this file: shlex.split(posix=True) keeps
    the backslash in "\\$" while bash drops it, so the known-credential pattern would end in ``\\$`` instead of
    ``$``. Every static word is therefore checked against real bash (``printf %s WORD``) at the end of the run;
    a mismatch is an error, not a warning.

A pattern is ``dynamic`` when its word contains an unexpanded variable or command substitution. Those are
resolved where possible by evaluating the defining assignments in a clean bash (``resolved`` is then true and
``pattern`` holds the text bash would hand to grep); what stays unresolved is listed by ``--summary``.

Standard library only.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / "scan_pipeline.sh"
DEFAULT_OUT = Path(__file__).resolve().parent / "patterns.json"

# helper -> (mode, case-insensitive, arg order, flag text bash applies)
HELPERS: dict[str, tuple[str, bool, str, str]] = {
    "grep_check": ("line", False, "PF", "-qE -e"),
    "grep_check_i": ("line_i", True, "PF", "-qiE -e"),
    "grep_check_excl": ("excl", True, "PEF", "-hiE -e PAT FILE | grep -viE -e EXCL"),
    "grep_flat": ("flat", True, "PF", "tr '\\r\\n\\t' '   ' < FILE | grep -iE -e"),
    "_pdf_has": ("line_a", False, "FP", "-qaE"),
}

OPCHARS = set(";&|<>()")
NAME_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
NAME_CHARS = NAME_START | set("0123456789")
SPECIAL_PARAMS = set("@*#?-$!0123456789")


class LexError(Exception):
    pass


@dataclass
class Word:
    raw: str
    line: int
    end_line: int
    parts: list[tuple[str, str]]  # ("lit", text) | ("dyn", raw text of the expansion)
    quoted: bool = False
    glob: bool = False  # an unquoted * ? [ that bash would try to expand

    @property
    def dynamic(self) -> bool:
        return any(k == "dyn" for k, _ in self.parts)

    @property
    def value(self) -> str:
        return "".join(t for k, t in self.parts if k == "lit")

    @property
    def text(self) -> str:
        """The word with each expansion left as written, e.g. ``(^|x)(${ARR[$k]})``."""
        return "".join(t for _, t in self.parts)


@dataclass
class Op:
    text: str
    line: int


class Lexer:
    def __init__(self, text: str) -> None:
        self.s = text
        self.n = len(text)
        self.line_starts = [0]
        for m in re.finditer("\n", text):
            self.line_starts.append(m.end())
        self.tokens: list[Word | Op] = []
        self.heredoc_ranges: list[tuple[int, int]] = []  # (first, last) physical lines of heredoc bodies
        self.pending: list[tuple[str, bool]] = []
        self.nested: list[tuple[int, int]] = []  # text ranges of $( ) and backtick bodies, lexed afterwards

    def lineno(self, i: int) -> int:
        return bisect.bisect_right(self.line_starts, i)

    # -- skipping helpers (used inside expansions, where only the extent matters) ------------------------
    def skip_squote(self, i: int) -> int:
        j = self.s.find("'", i + 1)
        if j < 0:
            raise LexError(f"unterminated ' at line {self.lineno(i)}")
        return j + 1

    def skip_dquote(self, i: int) -> int:
        s, n = self.s, self.n
        i += 1
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
            elif c == '"':
                return i + 1
            elif c == "$" and i + 1 < n and s[i + 1] in "({":
                i = self.skip_expansion(i)
            elif c == "`":
                i = self.skip_backtick(i)
            else:
                i += 1
        raise LexError("unterminated \"")

    def skip_backtick(self, i: int) -> int:
        s, n = self.s, self.n
        i += 1
        while i < n:
            if s[i] == "\\":
                i += 2
            elif s[i] == "`":
                return i + 1
            else:
                i += 1
        raise LexError("unterminated `")

    def skip_expansion(self, i: int) -> int:
        """i is at '$' followed by '(' or '{'. Return the index after the matching close."""
        s, n = self.s, self.n
        open_c = s[i + 1]
        close_c = ")" if open_c == "(" else "}"
        depth = 0
        j = i + 1
        while j < n:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                j = self.skip_squote(j)
                continue
            if c == '"':
                j = self.skip_dquote(j)
                continue
            if c == "`":
                j = self.skip_backtick(j)
                continue
            if c == "$" and j + 1 < n and s[j + 1] == "'":
                j = self.skip_squote(j + 1)
                continue
            if c == "#" and open_c == "(" and (j == 0 or s[j - 1] in " \t\n;"):
                while j < n and s[j] != "\n":
                    j += 1
                continue
            if c == open_c:
                depth += 1
            elif c == close_c:
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        raise LexError(f"unterminated expansion at line {self.lineno(i)}")

    # -- word -------------------------------------------------------------------------------------------
    def read_ansi_c(self, i: int) -> tuple[str, int]:
        """i is at the opening ' of $'...'. Return (decoded, index after the closing ')."""
        s = self.s
        out: list[str] = []
        j = i + 1
        simple = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
                  "e": "\x1b", "E": "\x1b", "\\": "\\", "'": "'", '"': '"', "?": "?"}
        while j < self.n:
            c = s[j]
            if c == "'":
                return "".join(out), j + 1
            if c == "\\" and j + 1 < self.n:
                d = s[j + 1]
                if d in simple:
                    out.append(simple[d])
                    j += 2
                elif d == "x":
                    m = re.match(r"[0-9a-fA-F]{1,2}", s[j + 2:j + 4])
                    if not m:
                        out.append("\\x")
                        j += 2
                    else:
                        out.append(chr(int(m.group(), 16)))
                        j += 2 + len(m.group())
                elif d in "01234567":
                    m = re.match(r"[0-7]{1,3}", s[j + 1:j + 4])
                    out.append(chr(int(m.group(), 8) & 0xFF))  # type: ignore[union-attr]
                    j += 1 + len(m.group())  # type: ignore[union-attr]
                else:
                    out.append("\\" + d)
                    j += 2
            else:
                out.append(c)
                j += 1
        raise LexError("unterminated $'")

    def read_word(self, i: int) -> tuple[Word, int]:
        s, n = self.s, self.n
        start = i
        parts: list[tuple[str, str]] = []
        quoted = False
        glob = False
        lit: list[str] = []

        def flush() -> None:
            if lit:
                parts.append(("lit", "".join(lit)))
                lit.clear()

        while i < n:
            c = s[i]
            if c in " \t\n" or c in OPCHARS:
                break
            if c == "\\":
                if i + 1 < n and s[i + 1] == "\n":
                    i += 2
                    continue
                lit.append(s[i + 1] if i + 1 < n else "\\")
                quoted = True
                i += 2
            elif c == "'":
                j = self.skip_squote(i)
                lit.append(s[i + 1:j - 1])
                quoted = True
                i = j
            elif c == '"':
                quoted = True
                i += 1
                while True:
                    if i >= n:
                        raise LexError(f"unterminated \" at line {self.lineno(start)}")
                    d = s[i]
                    if d == '"':
                        i += 1
                        break
                    if d == "\\":
                        e = s[i + 1] if i + 1 < n else ""
                        if e == "\n":
                            i += 2
                        elif e in ('$', '`', '"', "\\"):
                            lit.append(e)
                            i += 2
                        else:
                            lit.append("\\")
                            i += 1
                    elif d == "$":
                        e = s[i + 1] if i + 1 < n else ""
                        if e in "({":
                            j = self.skip_expansion(i)
                            if e == "(" and s[i + 2:i + 3] != "(":
                                self.nested.append((i + 2, j - 1))
                            flush()
                            parts.append(("dyn", s[i:j]))
                            i = j
                        elif e in NAME_START or e in SPECIAL_PARAMS:
                            j = i + 1
                            if e in NAME_START:
                                while j < n and s[j] in NAME_CHARS:
                                    j += 1
                            else:
                                j += 1
                            flush()
                            parts.append(("dyn", s[i:j]))
                            i = j
                        else:
                            lit.append("$")
                            i += 1
                    elif d == "`":
                        j = self.skip_backtick(i)
                        self.nested.append((i + 1, j - 1))
                        flush()
                        parts.append(("dyn", s[i:j]))
                        i = j
                    else:
                        lit.append(d)
                        i += 1
            elif c == "$":
                e = s[i + 1] if i + 1 < n else ""
                if e == "'":
                    text, i = self.read_ansi_c(i + 1)
                    lit.append(text)
                    quoted = True
                elif e == '"':
                    i += 1  # locale-translated string: same as "..."
                elif e in "({":
                    j = self.skip_expansion(i)
                    if e == "(" and s[i + 2:i + 3] != "(":
                        self.nested.append((i + 2, j - 1))
                    flush()
                    parts.append(("dyn", s[i:j]))
                    i = j
                elif e in NAME_START or e in SPECIAL_PARAMS:
                    j = i + 1
                    if e in NAME_START:
                        while j < n and s[j] in NAME_CHARS:
                            j += 1
                    else:
                        j += 1
                    flush()
                    parts.append(("dyn", s[i:j]))
                    i = j
                else:
                    lit.append("$")
                    i += 1
            elif c == "`":
                j = self.skip_backtick(i)
                self.nested.append((i + 1, j - 1))
                flush()
                parts.append(("dyn", s[i:j]))
                i = j
            else:
                if c in "*?[":
                    glob = True
                lit.append(c)
                i += 1
        flush()
        return Word(s[start:i], self.lineno(start), self.lineno(max(start, i - 1)), parts, quoted, glob), i

    # -- tokeniser --------------------------------------------------------------------------------------
    def read_heredocs(self, i: int) -> int:
        """i is just after a newline with heredocs pending: consume their bodies."""
        s = self.s
        for delim, strip in self.pending:
            first = self.lineno(i)
            while True:
                if i >= self.n:
                    raise LexError(f"unterminated heredoc {delim!r}")
                j = s.find("\n", i)
                end = self.n if j < 0 else j
                body = s[i:end]
                if strip:
                    body = body.lstrip("\t")
                i = self.n if j < 0 else j + 1
                if body == delim:
                    self.heredoc_ranges.append((first, self.lineno(i - 1) if j >= 0 else self.lineno(end)))
                    break
        self.pending = []
        return i

    def tokenise(self, start: int = 0, end: int | None = None) -> list[Word | Op]:
        s = self.s
        if end is not None:
            self.n = end
        n = self.n
        i = start
        toks = self.tokens
        while i < n:
            c = s[i]
            if c == "\n":
                toks.append(Op("\n", self.lineno(i)))
                i += 1
                if self.pending:
                    i = self.read_heredocs(i)
                continue
            if c in " \t":
                i += 1
                continue
            if c == "\\" and i + 1 < n and s[i + 1] == "\n":
                i += 2
                continue
            if c == "#":
                while i < n and s[i] != "\n":
                    i += 1
                continue
            if c in OPCHARS:
                j = i
                while j < n and s[j] in OPCHARS and not (s[j] == "(" and j > i and s[j - 1] in "&|;"):
                    j += 1
                    if s[i] in "()" or (j - i >= 3):
                        break
                op = s[i:j]
                # "<<" / "<<-" opens a heredoc, "<<<" is a here-string
                if op in ("<<", "<<-"):
                    k = j
                    while k < n and s[k] in " \t":
                        k += 1
                    w, k2 = self.read_word(k)
                    self.pending.append((w.value, op == "<<-"))
                    toks.append(Op(op, self.lineno(i)))
                    toks.append(w)
                    i = k2
                    continue
                toks.append(Op(op, self.lineno(i)))
                i = j
                continue
            w, i2 = self.read_word(i)
            if i2 == i:
                raise LexError(f"no progress at line {self.lineno(i)}: {s[i:i + 20]!r}")
            # "2>" "&>" style file-descriptor prefixes are glued to the operator: keep as a Word, the
            # argument collector drops them together with the redirect.
            toks.append(w)
            i = i2
        return toks

    def all_streams(self) -> list[list[Word | Op]]:
        """The main token stream followed by the stream of every command substitution found (recursively)."""
        streams = [self.tokenise()]
        done = 0
        while done < len(self.nested):
            a, b = self.nested[done]
            done += 1
            sub = Lexer.__new__(Lexer)
            sub.s, sub.n, sub.line_starts = self.s, self.n, self.line_starts
            sub.tokens, sub.heredoc_ranges, sub.pending, sub.nested = [], self.heredoc_ranges, [], self.nested
            streams.append(sub.tokenise(a, b))
        return streams


# -- function map ---------------------------------------------------------------------------------------
FUNC_DEF = re.compile(r"^(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{?")


def function_map(lines: list[str], heredoc_lines: set[int]) -> list[str]:
    """For every physical line (1-based index) the top-level function it sits in, or '' at file level."""
    out = [""] * (len(lines) + 2)
    cur = ""
    for no, text in enumerate(lines, start=1):
        if no not in heredoc_lines:
            m = FUNC_DEF.match(text)
            if m and not text.startswith((" ", "\t")):
                cur = m.group(1)
        out[no] = cur
        if no not in heredoc_lines and (text.rstrip() == "}" or (FUNC_DEF.match(text) and text.rstrip().endswith("}"))):
            cur = ""  # end of a function, or a one-line definition such as ``grep_check() { ...; }``
    return out


# -- bash evaluation (verification and resolution) -----------------------------------------------------
def bash_eval_words(raws: list[str]) -> list[str]:
    """Expand each raw static word with real bash. One process; results NUL-separated."""
    if not raws:
        return []
    script = "set -f\n" + "".join(f"printf '%s\\0' {r}\n" for r in raws)
    with tempfile.TemporaryDirectory() as d:
        p = subprocess.run(["bash", "--noprofile", "--norc", "-c", script], cwd=d, capture_output=True,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, timeout=60)
    if p.returncode != 0:
        raise RuntimeError("bash could not expand the static words: " + p.stderr.decode("utf-8", "replace"))
    out = p.stdout.decode("utf-8", "surrogateescape").split("\0")
    if out and out[-1] == "":
        out.pop()
    if len(out) != len(raws):
        raise RuntimeError(f"bash returned {len(out)} words for {len(raws)}")
    return out


def bash_eval_with_prelude(prelude: str, expr: str) -> str:
    """Run ``prelude`` (plain assignments) in a clean bash and return what ``printf %s expr`` prints."""
    script = "set -f\n" + prelude + "\nprintf '%s' " + expr + "\n"
    with tempfile.TemporaryDirectory() as d:
        p = subprocess.run(["bash", "--noprofile", "--norc", "-c", script], cwd=d, capture_output=True,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, timeout=60)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode("utf-8", "replace"))
    return p.stdout.decode("utf-8", "surrogateescape")


# -- call-site extraction ------------------------------------------------------------------------------
TERMINATORS = {"\n", ";", ";;", "&&", "||", "|", "&", ")", "|&", ";&", ";;&"}
REDIRECTS = {"<", ">", ">>", "<<", "<<-", "<<<", ">&", "<&", "&>", "&>>", ">|"}


def statement_args(toks: list[Word | Op], k: int) -> tuple[list[Word], int]:
    """Arguments of the command whose name token is toks[k]: stops at a control operator, skips redirections."""
    args: list[Word] = []
    j = k + 1
    while j < len(toks):
        t = toks[j]
        if isinstance(t, Op):
            if t.text in TERMINATORS:
                break
            if t.text in REDIRECTS:
                # the redirect target is the next word; a glued fd number before it was already taken
                if args and re.fullmatch(r"[0-9]+", args[-1].raw) and args[-1].end_line == t.line:
                    args.pop()
                j += 2
                continue
            break
        args.append(t)
        j += 1
    return args, j


def pipeline_stages(toks: list[Word | Op], k: int) -> list[tuple[list[int], str]]:
    """The stages of the pipeline that feeds toks[k], earliest first, as (index of the stage's first word, text).

    A stage is the run of words between two ``|`` operators; a newline directly after ``|`` continues the
    pipeline in bash and is skipped here. Leading ``if`` / ``!`` / ``{`` / ``while`` words are dropped."""
    stages: list[tuple[list[int], str]] = []
    j = k - 1
    while j >= 0 and isinstance(toks[j], Op) and toks[j].text in ("|", "|&"):
        j -= 1
        while j >= 0 and isinstance(toks[j], Op) and toks[j].text == "\n":
            j -= 1
        words: list[str] = []
        idx: list[int] = []
        while j >= 0:
            t = toks[j]
            if isinstance(t, Op):
                if t.text in ("|", "|&", "&&", "||", ";", "\n", "(", "{", ";;"):
                    break
                words.append(t.text)
            else:
                words.append(t.raw)
                idx.append(j)
            j -= 1
        words.reverse()
        while words and words[0] in ("if", "elif", "while", "until", "!", "{", "then", "do", "else"):
            words.pop(0)
        stages.append((idx, " ".join(words)))
        # a "|" before this stage continues the chain
    stages.reverse()
    return stages


def stage_text(toks: list[Word | Op], k: int, limit: int = 90) -> str:
    """Raw text of the pipeline stage immediately before toks[k] (what feeds a grep that reads stdin)."""
    st = pipeline_stages(toks, k)
    if not st:
        return ""
    txt = st[-1][1]
    return (txt[:limit] + "...") if len(txt) > limit else txt


def parse_grep_options(args: list[Word]) -> tuple[str, list[Word], list[Word], int | None]:
    """Return (flag letters, pattern words, file words, -A context). Handles -e PAT, bundled flags, -A5."""
    flags = ""
    pats: list[Word] = []
    rest: list[Word] = []
    context: int | None = None
    end_opts = False
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if not end_opts and v == "--":
            end_opts = True
        elif not end_opts and v.startswith("--"):
            flags += " " + v
        elif not end_opts and v.startswith("-") and len(v) > 1:
            letters = v[1:]
            j = 0
            while j < len(letters):
                ch = letters[j]
                if ch == "e":  # -e PATTERN (the next word, or the rest of this one)
                    if j + 1 < len(letters):
                        pats.append(Word(a.raw, a.line, a.end_line, [("lit", letters[j + 1:])]))
                    elif i + 1 < len(args):
                        pats.append(args[i + 1])
                        i += 1
                    break
                if ch in "ABCm":  # takes a count
                    num = letters[j + 1:]
                    if not num and i + 1 < len(args):
                        num = args[i + 1].value
                        i += 1
                    if ch in "AC" and num.isdigit():
                        context = int(num)
                    flags += ch
                    break
                flags += ch
                j += 1
        else:
            rest.append(a)
        i += 1
    if not pats and rest:
        pats.append(rest.pop(0))
    return flags, pats, rest, context


@dataclass
class Site:
    helper: str
    mode: str
    flags: str
    patterns: list[Word]
    line: int
    end_line: int
    fn: str
    file_arg: str
    dialect: str = "ere"
    context: int | None = None
    notes: list[str] = field(default_factory=list)
    pipeline: str = ""
    tok: int = -1
    second: "Site | None" = None  # a later grep in the same pipeline, fused into this one
    shape: str = "match"
    between: str = ""  # the commands between the two greps of a fused pipeline


def extract(path: Path) -> tuple[list[Site], dict]:
    text = path.read_text(encoding="utf-8", errors="surrogateescape")
    lx = Lexer(text)
    streams = lx.all_streams()
    toks = streams[0]
    lines = text.split("\n")
    heredoc_lines: set[int] = set()
    for a, b in lx.heredoc_ranges:
        heredoc_lines.update(range(a, b + 1))
    fmap = function_map(lines, heredoc_lines)
    sites: list[Site] = []
    stats = {"tokens": sum(len(x) for x in streams), "streams": len(streams),
             "heredoc_bodies": len(lx.heredoc_ranges), "heredoc_lines": len(heredoc_lines)}
    names = set(HELPERS) | {"grep", "egrep"}

    for stream in streams:
        by_tok: dict[int, Site] = {}
        for k, t in enumerate(stream):
            if not isinstance(t, Word) or t.raw not in names:
                continue
            nxt = stream[k + 1] if k + 1 < len(stream) else None
            if isinstance(nxt, Op) and nxt.text == "(":  # a function definition: grep_check() {
                continue
            prev = stream[k - 1] if k > 0 else None
            if isinstance(prev, Word) and prev.raw in ("function", "command", "type", "which", "has_cmd"):
                continue
            args, _end = statement_args(stream, k)
            fn = fmap[t.line] if t.line < len(fmap) else ""
            if t.raw in ("grep", "egrep") and fn in HELPERS:
                continue  # the implementation of a helper, not a call site
            if t.raw in HELPERS:
                mode, ci, order, flagtxt = HELPERS[t.raw]
                want = len(order)
                if len(args) < want:
                    raise LexError(f"line {t.line}: {t.raw} has {len(args)} arguments, expected {want}")
                by = dict(zip(order, args))
                pats = [by["P"]] + ([by["E"]] if "E" in by else [])
                sites.append(Site(t.raw, mode, flagtxt, pats, t.line, max(a.end_line for a in args), fn,
                                  by["F"].raw))
                continue
            flags, pats, files, ctx = parse_grep_options(args)
            if not pats:
                continue
            dialect = "ere" if ("E" in flags or t.raw == "egrep") else "fixed" if "F" in flags else \
                "pcre" if "P" in flags else "bre"
            file_arg = " ".join(f.raw for f in files) if files else "<stdin: " + (stage_text(stream, k) or "?") + ">"
            site = Site("grep", "direct", "-" + flags.strip(), pats[:1], t.line, max(a.end_line for a in args), fn,
                        file_arg, dialect, ctx, tok=k)
            site.shape = "extract" if "o" in flags else "count" if "c" in flags else "match"
            # A grep fed by another grep (possibly through tr): fuse the two into one record.
            stages = pipeline_stages(stream, k)
            if stages:
                site.pipeline = " | ".join(txt for _, txt in stages)[:400]
            feeder = None
            for idx, _txt in stages:
                feeder = next((by_tok[i] for i in idx if i in by_tok), None) or feeder
            if feeder is not None:
                feeder.second = site
                feeder.shape = "pipe2"
                feeder.patterns = feeder.patterns + site.patterns[:1]
                feeder.between = " | ".join(txt for idx, txt in stages if not any(i in by_tok for i in idx))
                feeder.end_line = max(feeder.end_line, site.end_line)
                continue
            by_tok[k] = site
            sites.append(site)
    stats["words"] = sum(1 for st in streams for t in st if isinstance(t, Word))
    stats["grep_words_in_helpers"] = sum(1 for st in streams for t in st if isinstance(t, Word)
                                         and t.raw in ("grep", "egrep") and fmap[t.line] in HELPERS)
    stats["grep_words_total"] = sum(1 for st in streams for t in st if isinstance(t, Word) and t.raw in ("grep", "egrep"))
    return sites, {"stats": stats, "text": text, "lexer": lx, "tokens": toks, "fmap": fmap,
                   "heredoc_lines": heredoc_lines}


# -- resolution of dynamic patterns -------------------------------------------------------------------
ASSIGN = re.compile(r"^(?:local\s+|declare\s+(?:-[A-Za-z]+\s+)?)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)


def collect_assignments(toks: list[Word | Op], fmap: list[str]) -> dict[tuple[str, str], list[Word]]:
    """(function, NAME) -> the assigned words, for simple ``NAME=word`` / ``local NAME=word`` statements."""
    out: dict[tuple[str, str], list[Word]] = {}
    for k, t in enumerate(toks):
        if not isinstance(t, Word):
            continue
        raw = t.raw
        if raw in ("local", "declare", "readonly", "export") and k + 1 < len(toks) and isinstance(toks[k + 1], Word):
            t2 = toks[k + 1]
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)=", t2.raw)
            if m and not t2.raw.startswith(m.group(1) + "=("):
                out.setdefault((fmap[t2.line], m.group(1)), []).append(t2)
            continue
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)(\+?)=", raw)
        if m and (k == 0 or isinstance(toks[k - 1], Op)):
            if m.group(2) == "+":
                continue
            out.setdefault((fmap[t.line], m.group(1)), []).append(t)
    return out


def assignment_value(w: Word) -> Word:
    """The right-hand side of ``NAME=value`` as its own Word (so it can be evaluated like any other)."""
    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*=", w.raw)
    assert m
    rest_raw = w.raw[m.end():]
    return Word(rest_raw, w.line, w.end_line, [])


def resolve_all(sites: list[Site], ctx: dict, source: Path) -> list[dict]:
    toks = ctx["tokens"]
    fmap = ctx["fmap"]
    assigns = collect_assignments(toks, fmap)
    lines = ctx["text"].split("\n")
    records: list[dict] = []
    seen_ids: dict[str, int] = {}

    # The known-credential tables are the one place where a pattern is assembled by a loop. They are executed
    # as written (the contiguous top-level block that defines them), not re-implemented here.
    cred_block = None
    start = next((i for i, l in enumerate(lines, 1) if l.startswith("KNOWN_CRED_NAMES=(")), None)
    end = next((i for i, l in enumerate(lines, 1) if l.startswith("KNOWN_CRED_EXCL=")), None)
    if start and end:
        cred_block = "\n".join(lines[start - 1:end])

    def eval_cred(expr: str) -> str:
        assert cred_block
        return bash_eval_with_prelude(cred_block, expr)

    def mkid(fn: str, mode: str, p: str, e: str | None, extra: str = "") -> str:
        h = hashlib.sha1((mode + "\0" + p + "\0" + (e or "") + extra).encode("utf-8", "surrogateescape")).hexdigest()[:8]
        base = f"{fn or 'top'}:{h}"
        n = seen_ids.get(base, 0) + 1
        seen_ids[base] = n
        return base if n == 1 else f"{base}#{n}"

    # first pass: verify static words against real bash
    static_words: list[Word] = []
    for s in sites:
        for w in s.patterns:
            if not w.dynamic:
                static_words.append(w)
    expanded = bash_eval_words([w.raw for w in static_words])
    mism = [(w, v) for w, v in zip(static_words, expanded) if w.value != v]
    if mism:
        w, v = mism[0]
        raise RuntimeError(f"lexer disagrees with bash on {len(mism)} words; first at line {w.line}: "
                           f"lexer={w.value!r} bash={v!r}")
    ctx["stats"]["static_words_verified_against_bash"] = len(static_words)

    for s in sites:
        base_rec = {
            "helper": s.helper, "mode": s.mode, "flags": s.flags, "patterns": len(s.patterns),
            "line": s.line, "end_line": s.end_line, "enclosing_function": s.fn,
            "dynamic": any(w.dynamic for w in s.patterns),
            "file_argument_text": s.file_arg, "dialect": s.dialect,
        }
        if s.context is not None:
            base_rec["context_lines"] = s.context
        if s.mode == "direct":
            base_rec["shape"] = s.shape
            if s.second is not None:
                base_rec["dialect2"] = s.second.dialect
                base_rec["flags2"] = s.second.flags
                base_rec["between"] = s.between
            elif s.pipeline:
                base_rec["pipeline"] = s.pipeline
        if any(w.glob and not w.quoted for w in s.patterns):
            base_rec["unquoted_glob"] = True
        pats = s.patterns
        if not base_rec["dynamic"]:
            rec = dict(base_rec)
            rec["pattern"] = pats[0].value
            rec["pattern_raw"] = pats[0].raw
            if len(pats) > 1:
                rec["excl"] = pats[1].value
                rec["excl_raw"] = pats[1].raw
            rec["id"] = mkid(s.fn, s.mode, rec["pattern"], rec.get("excl"))
            rec["resolved"] = False
            records.append(rec)
            continue

        # ---- dynamic ----
        rec = dict(base_rec)
        rec["pattern_raw"] = pats[0].raw
        rec["pattern_text"] = pats[0].text
        if len(pats) > 1:
            rec["excl_raw"] = pats[1].raw
            rec["excl_text"] = pats[1].text
        rec["dynamic_vars"] = sorted({d for w in pats for k_, d in w.parts if k_ == "dyn"})
        # (1) "${KNOWN_CRED_ALL}" / "${KNOWN_CRED_EXCL}": evaluate the table block
        # (2) "(^|..)(${KNOWN_CRED_PATS[$_k]})(..|\$)": one record per table entry
        # (3) "$VAR" for a variable with a single static assignment in the same function or file level
        raw = pats[0].raw
        children: list[dict] = []
        try:
            if "KNOWN_CRED_PATS[" in raw and cred_block:
                n = int(eval_cred('"${#KNOWN_CRED_PATS[@]}"'))
                for idx in range(n):
                    expr = raw.replace("${KNOWN_CRED_PATS[$_k]}", "${KNOWN_CRED_PATS[%d]}" % idx)
                    val = eval_cred(expr)
                    name = eval_cred('"${KNOWN_CRED_NAMES[%d]}"' % idx)
                    c = dict(rec)
                    c.update({"pattern": val, "resolved": True, "resolved_by": f"KNOWN_CRED_PATS[{idx}] ({name})",
                              "parent_line": s.line})
                    if len(pats) > 1:
                        c["excl"] = eval_cred(pats[1].raw)
                    children.append(c)
            elif any(v in raw for v in ("KNOWN_CRED_ALL", "KNOWN_CRED_EXCL")) and cred_block:
                c = dict(rec)
                c["pattern"] = eval_cred(raw)
                if len(pats) > 1:
                    c["excl"] = eval_cred(pats[1].raw)
                c.update({"resolved": True, "resolved_by": "executed the KNOWN_CRED_* definitions"})
                children.append(c)
            else:
                names = [m.group(1) or m.group(2) for m in re.finditer(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))",
                                                                     " ".join(pats[0].text.split("\0")))]
                prelude = []
                ok = bool(names) and all(d.startswith("$") and not d.startswith("$(") for d in rec["dynamic_vars"])
                for nm in sorted(set(names)):
                    cands = assigns.get((s.fn, nm)) or assigns.get(("", nm))
                    if not cands or len(cands) != 1 or assigns_dynamic(cands[0]):
                        ok = False
                        break
                    prelude.append(cands[0].raw)
                if ok:
                    val = bash_eval_with_prelude("\n".join(prelude), raw)
                    c = dict(rec)
                    c.update({"pattern": val, "resolved": True,
                              "resolved_by": "the single static assignment of " + ", ".join(sorted(set(names)))})
                    if len(pats) > 1:
                        c["excl"] = bash_eval_with_prelude("\n".join(prelude), pats[1].raw)
                    children.append(c)
        except Exception as exc:  # leave it unresolved and say why
            rec["resolve_error"] = str(exc)[:200]
        if not children:
            rec["pattern"] = None
            rec["resolved"] = False
            rec["id"] = mkid(s.fn, s.mode, rec["pattern_raw"], rec.get("excl_raw"), str(s.line))
            records.append(rec)
            continue
        for c in children:
            c["id"] = mkid(s.fn, s.mode, c["pattern"], c.get("excl"), c.get("resolved_by", ""))
            records.append(c)
    return records


def assigns_dynamic(w: Word) -> bool:
    return w.dynamic


# -- the cross-check -----------------------------------------------------------------------------------
def independent_count(text: str, heredoc_lines: set[int]) -> dict[str, int]:
    """Count helper-name occurrences by a regex over non-comment, non-heredoc lines (not using the lexer)."""
    counts = {h: 0 for h in HELPERS}
    for no, line in enumerate(text.split("\n"), start=1):
        if no in heredoc_lines:
            continue
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        m_c = re.search(r"\s#\s", line)
        if m_c and line[:m_c.start()].count('"') % 2 == 0 and line[:m_c.start()].count("'") % 2 == 0:
            line = line[:m_c.start()]  # trailing comment
        for h in HELPERS:
            for m in re.finditer(r"(?<![A-Za-z0-9_])" + re.escape(h) + r"(?![A-Za-z0-9_])", line):
                tail = line[m.end():].lstrip()
                if tail.startswith("()"):
                    continue  # definition
                # inside a quoted string on this line? crude: odd number of quotes before it
                head = line[:m.start()]
                if head.count('"') % 2 == 1 and head.count("'") % 2 == 0:
                    continue
                counts[h] += 1
    return counts


def independent_grep_words(text: str, heredoc_lines: set[int]) -> int:
    """Occurrences of the word grep/egrep in code (not comments, heredocs or strings), found with a regex."""
    n = 0
    for no, line in enumerate(text.split("\n"), start=1):
        if no in heredoc_lines or line.lstrip().startswith("#"):
            continue
        m_c = re.search(r"\s#\s", line)
        if m_c and line[:m_c.start()].count('"') % 2 == 0 and line[:m_c.start()].count("'") % 2 == 0:
            line = line[:m_c.start()]
        for m in re.finditer(r"(?<![A-Za-z0-9_-])e?grep(?![A-Za-z0-9_-])", line):
            head = line[:m.start()]
            if head.count('"') % 2 == 1 and head.count("'") % 2 == 0:
                continue
            if head.count("'") % 2 == 1:
                continue
            n += 1
    return n


def build(source: Path) -> tuple[list[dict], dict]:
    sites, ctx = extract(source)
    records = resolve_all(sites, ctx, source)
    # stable order: by line, then id
    records.sort(key=lambda r: (r["line"], r["id"]))
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    for r in records:
        r["source"] = "scan_pipeline.sh"
        r["source_sha256"] = sha
    ind = independent_count(ctx["text"], ctx["heredoc_lines"])
    found = {h: sum(1 for s in sites if s.helper == h) for h in HELPERS}
    ctx["stats"]["independent_count"] = ind
    ctx["stats"]["grep_words_regex"] = independent_grep_words(ctx["text"], ctx["heredoc_lines"])
    ctx["stats"]["grep_words_lexer"] = ctx["stats"]["grep_words_total"]
    ctx["stats"]["lexer_count"] = found
    ctx["stats"]["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    ctx["stats"]["source"] = str(source)
    ctx["stats"]["source_lines"] = ctx["text"].count("\n")
    return records, ctx["stats"]


def summarise(records: list[dict], stats: dict) -> str:
    from collections import Counter
    out: list[str] = []
    out.append(f"source: {stats['source']}  sha256 {stats['source_sha256'][:16]}  lines {stats['source_lines']}")
    by = Counter()
    for r in records:
        if r.get("parent_line"):
            continue
        by[r["helper"]] += 1
    out.append("call sites by helper: " + ", ".join(f"{h}={c}" for h, c in sorted(by.items())))
    out.append(f"records (after expanding table entries): {len(records)}")
    out.append(f"independent count of helper names (regex): {stats['independent_count']}")
    out.append(f"lexer count by helper:                     {stats['lexer_count']}")
    direct = [r for r in records if r["mode"] == "direct" and not r.get("parent_line")]
    out.append(f"grep/egrep words in code: lexer {stats['grep_words_total']} ({stats['grep_words_in_helpers']} inside the helper "
               f"definitions, the rest at call sites), independent line-regex {stats['grep_words_regex']} (crude: skips words after an odd quote)")
    out.append(f"direct grep records (a fused pipeline counts once): {len(direct)}")
    out.append(f"static pattern words verified against real bash: {stats['static_words_verified_against_bash']}")
    dyn = [r for r in records if r["dynamic"] and not r.get("parent_line")]
    seen_parent = set()
    out.append(f"dynamic call sites: {len(dyn)}")
    for r in records:
        if not r["dynamic"]:
            continue
        key = (r["line"], r["pattern_text"] if "pattern_text" in r else "")
        if key in seen_parent:
            continue
        seen_parent.add(key)
        how = r.get("resolved_by", "UNRESOLVED")
        out.append(f"  line {r['line']:5d} {r['enclosing_function']:28s} {r['helper']:16s} {r['pattern_text'][:70]!r:74s} -> {how}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", nargs="?", default=str(DEFAULT_SOURCE))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--summary", action="store_true", help="print counts and every dynamic site")
    ap.add_argument("--no-write", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="do not write: exit 1 if the patterns found differ from --out (ids, pattern text, flags), "
                         "ignoring line numbers; use it in CI so patterns.json cannot go stale")
    a = ap.parse_args(argv)
    source = Path(a.source)
    records, stats = build(source)
    if a.check:
        have = json.loads(Path(a.out).read_text(encoding="utf-8"))
        key = lambda r: (r["id"], r.get("pattern"), r.get("excl"), r["mode"], r["flags"])  # noqa: E731
        want, got = {key(r) for r in have}, {key(r) for r in records}
        if want == got:
            print(f"{a.out} is current: {len(got)} patterns")
            return 0
        for k in sorted(got - want, key=str)[:10]:
            print("new or changed:", k[0], repr((k[1] or "")[:80]))
        for k in sorted(want - got, key=str)[:10]:
            print("gone or changed:", k[0], repr((k[1] or "")[:80]))
        print(f"{a.out} is stale: regenerate it with  python3 -I tests/conformance/pattern_inventory.py")
        return 1
    if not a.no_write:
        Path(a.out).write_text(json.dumps(records, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    if stats["independent_count"] != stats["lexer_count"]:
        print("WARNING: lexer and independent counts differ", file=sys.stderr)
    if a.summary or a.no_write:
        print(summarise(records, stats))
    else:
        print(f"{len(records)} records written to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
