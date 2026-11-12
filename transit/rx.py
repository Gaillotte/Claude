"""POSIX ERE (as GNU grep -E reads it) translated to Python ``re`` for BYTES, and the grep helpers on top.

scan_pipeline.sh applies 293 pattern rules through ``grep -qE`` and friends. The Python engine does the same matching
in-process, and this module is the only place a rule regex is compiled. Nothing here is guessed from the POSIX text:
every behaviour below was read off GNU grep 3.11 (LC_ALL=C) and is pinned by tests/conformance/test_rx.py, whose
expected values come from running grep. The differential fuzz (tests/conformance/pattern_fuzz.py) compares this module
with the real grep on every pattern in the pipeline, and on thousands of synthetic EREs.

Entry points
    ere_to_py(pattern, ignore_case)   -> bytes ``re.Pattern`` with grep's per-line semantics (compiled with re.MULTILINE)
    search_lines / matching_lines     grep -q / the matching lines, over a whole buffer
    search_excl / excl_lines          grep_check_excl      (pattern, and not exclusion, both case-insensitive)
    flat_view / search_flat           grep_flat            (CR LF TAB folded to spaces; over 5 MB: skipped)
    only_matching / after_context     grep -o / grep -A<n>
    rule() / registered()             a registry so a CI gate can enumerate every compiled rule
    time_limit()                      SIGALRM guard;  ``budget=`` on the search functions: re first, then the linear matcher

What differs between GNU ERE and Python ``re``, and what this module does about it
    * Lines.  grep matches line by line, so ``[^x]``, ``.``, ``\\s`` and ``\\W`` can never consume a newline. The
      translator removes ``\\n`` from every class it emits and compiles with ``re.MULTILINE``, which lets one
      ``search`` over a whole buffer give the per-line answer without a Python loop.
    * Repetition of a repetition.  ``a+?``, ``a*?``, ``a??`` are NOT lazy in ERE; they are ``(a+)?`` and so on.
      ``a*+`` / ``a++`` are not possessive either. Nested repetitions are emitted as a group (never as a Python
      lazy or possessive operator) and, where that is exactly equivalent, flattened (``(a+)+`` -> ``a+``) because the
      nested form backtracks exponentially in ``re`` and linearly in grep.
    * ``*``, ``+``, ``?`` with nothing before them (``*a``, ``(+a)``, ``a|*b``) repeat the empty expression, as in grep.
    * ``{`` that does not start a valid interval is a literal brace; ``{}``, ``{2,1}``, ``{1,2,3}`` and ``{65536}``
      are errors, ``{,3}`` is ``{0,3}``. (glibc ``parse_dup_op``.)
    * A bracket expression: ``]`` first is a member, backslash is an ordinary member (``[\\s]`` is backslash or s),
      ``-`` is literal only first or last, ranges are by byte value (and, under -i, ordered after upper-casing, as glibc
      does: ``[Z-a]`` is an error with -i), ``[:alpha:]`` outside a bracket is an error.
    * ``\\d`` is NOT a digit class in grep: an unknown escape is the character itself, so ``\\d`` matches the letter d.
      The same for ``\\n``, ``\\t``, ``\\x41`` (the letters n, t, x41). ``\\w \\W \\s \\S \\b \\B \\< \\>`` are the GNU
      operators, and ``\\` `` / ``\\'`` anchor the line (grep applies them per line).
    * A ``)`` with no open group is a literal; ``(`` unmatched is an error. A newline in a pattern separates patterns.
    * Case folding is ASCII only (the C locale), done on the parsed sets so ``[^a-c]`` under -i excludes both cases.
    * ``\\b`` and ``\\B`` are written out as look-arounds over ASCII word bytes; Python 3.11's own ``\\B`` does not
      match the empty string, grep's does.

Pathological lines
    grep is automaton-based and linear; ``re`` backtracks. ``curl[^|]*http://`` is fast on every real file and takes
    seconds on one 64 KB line that repeats ``curl x`` and never reaches ``http://`` (the fuzz finds 42 to 45 of the 294 pipeline
    cases above 0.5 s, 15 to 18 of them stopped by its 2 s alarm). Every pattern without a back-reference therefore also has a lazy DFA built from the same parse
    tree (``dfa_search``); ``search_lines(..., budget=0.25)`` lets ``re`` run that long and then finishes the buffer
    with the DFA, which is linear on any input. The same ``budget=`` is on every search function. ``time_limit`` needs
    the main thread and POSIX; an engine that scans in threads must use ``dfa_search`` for long lines instead.

Refused rather than guessed (``UnsupportedERE``)
    grep matches most patterns with its own DFA but a pattern with a back-reference with glibc, and the two disagree in
    corners: ``[.x.]`` and ``[=x=]``, a ``{`` at the start of an expression or after an anchor, an anchor repeated next to a
    back-reference, a back-reference to a group that can be empty or is repeated. None occurs in the pipeline.

``Parsed.warnings`` names patterns that parse and match but probably do not mean what their author meant: a stray
``\\d``, a backslash inside a bracket, ``+?``, an empty alternative (the rule matches every line), and a ``\\b`` next to a
character that cannot be a word character (``\\b(a|rand\\(\\))\\b`` never finds ``rand();``). The fuzz turns each into a
finding that must be recorded.

Not reproduced (see tests/conformance/known_pattern_divergences.json)
    * Leftmost-longest.  For "does this line match" it cannot matter; for ``grep -o`` (the text of the match) it
      can, with an ambiguous alternation. ``only_matching`` uses Python's leftmost-first.
    * Locale.  Everything is the C locale: one byte is one character.
    * grep's binary-file handling, which is selectable: ``binary="text"`` (``grep -a``, the default), ``"grep"`` (a NUL
      ends a line, as grep does once it decides a file is binary) and ``"skip"`` (``grep -I``).

Not thread-safe (the DFA caches are mutated while matching). Standard library only.
"""
from __future__ import annotations

import re
import signal
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

__all__ = [
    "EREError", "UnsupportedERE", "RegexTimeout", "Parsed", "parse_ere", "ere_to_py_source", "ere_to_py", "search_lines",
    "matching_lines", "search_excl", "excl_lines", "dfa_available", "dfa_search", "dfa_matching_lines", "flat_view",
    "search_flat", "only_matching", "time_limit", "lines_over", "after_context", "Rule", "rule", "registered",
    "compiled_patterns", "FLAT_CAP",
]

FLAT_CAP = 5_242_880  # grep_flat: a file larger than this is not searched at all (bash returns "no match")
DUP_MAX = 0x7FFF  # RE_DUP_MAX of GNU regex
NL = 10


class EREError(ValueError):
    """The pattern is one GNU grep rejects (exit status 2), or one this module refuses to translate.

    In bash an invalid pattern makes ``if grep_check ...`` read false forever: the rule is silently inert.
    Here it is an exception at the moment the rule is compiled."""


class UnsupportedERE(EREError):
    """A construct grep accepts but this module deliberately does not translate (see the module docstring)."""


class RegexTimeout(Exception):
    """Raised by ``time_limit`` when a match runs past its budget."""


# --------------------------------------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------------------------------------
class Node:
    __slots__ = ()


class Empty(Node):
    __slots__ = ()


@dataclass(frozen=True)
class Set(Node):
    bits: frozenset  # byte values; never contains 10 (newline)


@dataclass(frozen=True)
class Cat(Node):
    items: tuple


@dataclass(frozen=True)
class Alt(Node):
    items: tuple


@dataclass(frozen=True)
class Rep(Node):
    node: Node
    lo: int
    hi: int | None  # None = unbounded


@dataclass(frozen=True)
class Group(Node):
    node: Node
    index: int


@dataclass(frozen=True)
class Backref(Node):
    index: int


@dataclass(frozen=True)
class Assert(Node):
    kind: str  # bol eol wordb nwordb wstart wend


@dataclass
class Parsed:
    ast: Node
    ngroups: int
    has_backref: bool
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------------------------
# character sets (C locale)
# --------------------------------------------------------------------------------------------------------
def _rng(*spans: tuple[int, int]) -> frozenset:
    out: set[int] = set()
    for a, b in spans:
        out.update(range(a, b + 1))
    out.discard(NL)
    return frozenset(out)


_ALL = _rng((0, 255))
_UPPER = _rng((65, 90))
_LOWER = _rng((97, 122))
_DIGIT = _rng((48, 57))
_CLASSES: dict[bytes, frozenset] = {
    b"alpha": _UPPER | _LOWER,
    b"upper": _UPPER,
    b"lower": _LOWER,
    b"digit": _DIGIT,
    b"alnum": _UPPER | _LOWER | _DIGIT,
    b"xdigit": _DIGIT | _rng((65, 70), (97, 102)),
    b"space": _rng((9, 13), (32, 32)),
    b"blank": _rng((9, 9), (32, 32)),
    b"punct": _rng((33, 47), (58, 64), (91, 96), (123, 126)),
    b"print": _rng((32, 126)),
    b"graph": _rng((33, 126)),
    b"cntrl": _rng((0, 31), (127, 127)),
}
_WORD = _UPPER | _LOWER | _DIGIT | frozenset({95})
_SPACE = _CLASSES[b"space"]
_NOT_WORD = _ALL - _WORD
_NOT_SPACE = _ALL - _SPACE


def _upper(b: int) -> int:
    return b - 32 if 97 <= b <= 122 else b


def _fold(bits: frozenset) -> frozenset:
    """Add the other case of every ASCII letter in the set (the C locale's case folding)."""
    extra = set()
    for b in bits:
        if 65 <= b <= 90:
            extra.add(b + 32)
        elif 97 <= b <= 122:
            extra.add(b - 32)
    return bits | extra if extra else bits


# --------------------------------------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------------------------------------
_MISSING = -1
_ERROR = -2


class _Parser:
    def __init__(self, pat: bytes, ignore_case: bool) -> None:
        self.p = pat
        self.n = len(pat)
        self.i = 0
        self.ic = ignore_case
        self.ngroups = 0
        self.completed: set[int] = set()
        self.depth = 0
        self.has_backref = False
        self.anchor_repeated = False
        self.literal_brace_at = -1
        self.warnings: list[str] = []

    # -- atoms ---------------------------------------------------------------------------------------
    def lit(self, b: int) -> Node:
        if b == NL:  # cannot occur: patterns are split on newline first
            raise EREError("newline in pattern")
        if self.ic and (65 <= b <= 90 or 97 <= b <= 122):
            return Set(frozenset({b | 32, b & ~32}))
        return Set(frozenset({b}))

    def sset(self, bits: frozenset) -> Node:
        bits = frozenset(bits - {NL})
        return Set(_fold(bits) if self.ic else bits)

    def parse_alt(self) -> Node:
        initial = set(self.completed)
        branches = [self.parse_cat()]
        while self.i < self.n and self.p[self.i] == 0x7C:  # |
            self.i += 1
            # a group closed in an earlier branch cannot be back-referenced from a later one
            accumulated = set(self.completed)
            self.completed = set(initial)
            branches.append(self.parse_cat())
            self.completed |= accumulated
        return branches[0] if len(branches) == 1 else Alt(tuple(branches))

    def parse_cat(self) -> Node:
        items: list[Node] = []
        while self.i < self.n:
            c = self.p[self.i]
            if c == 0x7C:  # |
                break
            if c == 0x29 and self.depth > 0:  # ) closing the current group
                break
            items.append(self.parse_piece())
        if not items:
            return Empty()
        return items[0] if len(items) == 1 else Cat(tuple(items))

    def parse_piece(self) -> Node:
        atom = self.parse_atom()
        if isinstance(atom, Assert) and self.i < self.n and self.p[self.i] in (0x2A, 0x2B, 0x3F, 0x7B):
            # grep's two matchers read a repetition applied to an anchor differently (glibc: "an anchor cannot be
            # repeated", the operator starts a new expression; the DFA: a repetition of the anchor)
            if self.p[self.i] == 0x7B:
                raise UnsupportedERE("an interval directly after an anchor")
            self.anchor_repeated = True
        leading = isinstance(atom, Empty)  # an operator with nothing before it
        ops = 0
        while self.i < self.n:
            c = self.p[self.i]
            if c in (0x2A, 0x2B, 0x3F, 0x7B):
                ops += 1
                if ops == 2 and c != 0x7B:
                    self.warnings.append("repetition of a repetition (%s): +? *? ?? *+ are not lazy or possessive in ERE" %
                                         self.p[max(0, self.i - 1):self.i + 1].decode("latin-1"))
            if c == 0x7B and leading:
                raise UnsupportedERE("an interval after a repetition operator that has nothing to repeat")
            if c == 0x2A:  # *
                self.i += 1
                atom = Rep(atom, 0, None)
            elif c == 0x2B:  # +
                self.i += 1
                atom = Rep(atom, 1, None)
            elif c == 0x3F:  # ?
                self.i += 1
                atom = Rep(atom, 0, 1)
            elif c == 0x7B:  # {
                iv = self.try_interval()
                if iv is None:
                    self.literal_brace_at = self.i  # not an interval: the brace is a literal and starts the next piece
                    self.warnings.append("'{' that does not start a valid interval is a literal brace")
                    break
                atom = Rep(atom, iv[0], iv[1])
            else:
                break
        return atom

    def try_interval(self) -> tuple[int, int | None] | None:
        """At '{'. Return (lo, hi) and advance, None (position unchanged) if the brace is a literal, or raise."""
        p, n = self.p, self.n
        j = self.i + 1

        def fetch_number(j: int) -> tuple[int, int, str]:
            num = _MISSING
            while True:
                if j >= n:
                    return _ERROR, j, ""
                c = p[j]
                j += 1
                if c == 0x7D:  # }
                    return num, j, "}"
                if c == 0x2C:  # ,
                    return num, j, ","
                if c == 0x5C:  # a backslash sequence is never a digit
                    j += 1
                    num = _ERROR
                    continue
                if not (0x30 <= c <= 0x39) or num == _ERROR:
                    num = _ERROR
                elif num == _MISSING:
                    num = c - 0x30
                else:
                    num = min(DUP_MAX + 1, num * 10 + c - 0x30)

        start, j, tok = fetch_number(j)
        if start == _MISSING:
            if tok == ",":
                start = 0
            else:
                raise EREError("Invalid content of \\{\\}")
        end = _ERROR
        if start != _ERROR:
            if tok == "}":
                end = start
            elif tok == ",":
                end, j, tok = fetch_number(j)
        if start == _ERROR or end == _ERROR:
            return None
        if (end != _MISSING and start > end) or tok != "}":
            raise EREError("Invalid content of \\{\\}")
        if (end if end != _MISSING else start) > DUP_MAX:
            raise EREError("Regular expression too big")
        self.i = j
        return start, (None if end == _MISSING else end)

    def parse_atom(self) -> Node:
        p = self.p
        c = p[self.i]
        if c in (0x2A, 0x2B, 0x3F):  # * + ? with nothing before: repetition of the empty expression
            self.warnings.append("repetition operator at start of expression")
            if self.depth > 0 and self.i + 1 < self.n and p[self.i + 1] == 0x29:
                # glibc skips the operator and then reads the ')' as the first character of a new expression, so the group
                # stays open (an error, or a different pattern if a later ')' closes it); the DFA reads an empty group
                raise UnsupportedERE("a repetition operator with nothing to repeat directly before ')'")
            return Empty()
        if c == 0x7B and self.i == self.literal_brace_at:
            self.i += 1
            return self.lit(c)
        if c == 0x7B:
            # '{' at the start of an expression: the DFA reads a valid interval as a repetition of nothing, glibc
            # drops only the '{' and keeps "2}" as text; they disagree, so do not pick one
            raise UnsupportedERE("'{' at the start of an expression")
        self.i += 1
        if c == 0x28:  # (
            self.ngroups += 1
            idx = self.ngroups
            self.depth += 1
            inner = self.parse_alt()
            if self.i >= self.n or p[self.i] != 0x29:
                raise EREError("Unmatched ( or \\(")
            self.i += 1
            self.depth -= 1
            self.completed.add(idx)
            return Group(inner, idx)
        if c == 0x29:  # ) with no open group is an ordinary character
            return self.lit(c)
        if c == 0x2E:  # .
            return self.sset(_ALL)
        if c == 0x5E:
            return Assert("bol")
        if c == 0x24:
            return Assert("eol")
        if c == 0x5B:  # [
            return self.parse_bracket()
        if c == 0x5C:  # backslash
            if self.i >= self.n:
                raise EREError("Trailing backslash")
            d = p[self.i]
            self.i += 1
            if 0x31 <= d <= 0x39:
                k = d - 0x30
                if k not in self.completed:
                    raise EREError("Invalid back reference")
                self.has_backref = True
                return Backref(k)
            if d == 0x77:
                return self.sset(_WORD)
            if d == 0x57:
                return self.sset(_NOT_WORD)
            if d == 0x73:
                return self.sset(_SPACE)
            if d == 0x53:
                return self.sset(_NOT_SPACE)
            if d == 0x62:
                return Assert("wordb")
            if d == 0x42:
                return Assert("nwordb")
            if d == 0x3C:
                return Assert("wstart")
            if d == 0x3E:
                return Assert("wend")
            if d == 0x60:  # \`
                return Assert("bol")
            if d == 0x27:  # \'
                return Assert("eol")
            if 0x30 <= d <= 0x39 or 0x41 <= d <= 0x5A or 0x61 <= d <= 0x7A:
                self.warnings.append(f"stray backslash before {chr(d)!r}: grep reads \\{chr(d)} as the letter {chr(d)!r} itself")
            return self.lit(d)  # \d, \n, \t, \x ... : the character itself
        return self.lit(c)

    # -- bracket expressions -------------------------------------------------------------------------
    def bracket_symbol(self, kind: int) -> bytes:
        """At the character after '[' + kind. Return the name up to kind + ']' (at most 32 bytes)."""
        p, n = self.p, self.n
        j = self.i
        name = bytearray()
        while True:
            if j >= n or len(name) >= 32:
                raise EREError("Unmatched [, [^, [:, [., or [=")
            if p[j] == kind and j + 1 < n and p[j + 1] == 0x5D:
                self.i = j + 2
                return bytes(name)
            name.append(p[j])
            j += 1

    def parse_bracket(self) -> Node:
        p, n = self.p, self.n
        negate = False
        if self.i < n and p[self.i] == 0x5E:
            negate = True
            self.i += 1
        content_start = self.i
        members: set[int] = set()
        first = True
        complex_element = False  # a class or a range was seen (dfa.c's colon warning)

        def element(accept_hyphen: bool) -> tuple[int | None, frozenset | None]:
            """Parse one element. Returns (single byte, None) or (None, class members)."""
            if self.i >= n:
                raise EREError("Unmatched [, [^, [:, [., or [=")
            c = p[self.i]
            if c == 0x5B and self.i + 1 < n and p[self.i + 1] in (0x3A, 0x2E, 0x3D):  # [: [. [=
                kind = p[self.i + 1]
                self.i += 2
                name = self.bracket_symbol(kind)
                if kind == 0x3A:
                    if name not in _CLASSES:
                        raise EREError("Invalid character class name")
                    return None, _CLASSES[name]
                if len(name) != 1:
                    raise EREError("Invalid collation character")
                # grep hands a bracket holding [.x.] or [=x=] to glibc's matcher instead of its own DFA, and the two
                # disagree in corners (a case-insensitive pattern with \n and [.a.] matched nothing). No pipeline
                # pattern uses either, so refuse rather than guess.
                raise UnsupportedERE("collating symbols [.x.] and equivalence classes [=x=] are not translated")
            if c == 0x2D and not accept_hyphen:
                # a '-' that is not first and not a range end must be the last member
                if not (self.i + 1 < n and p[self.i + 1] == 0x5D):
                    raise EREError("Invalid range end")
            self.i += 1
            return c, None

        while True:
            if self.i >= n:
                raise EREError("Unmatched [, [^, [:, [., or [=")
            if p[self.i] == 0x5D and not first:
                self.i += 1
                break
            single, cls = element(accept_hyphen=first)
            first = False
            if single == 0x5C:
                nb = p[self.i] if self.i < n else 0
                if (0x41 <= nb <= 0x5A or 0x61 <= nb <= 0x7A) and nb != 0x5C:
                    self.warnings.append("backslash inside a bracket expression is an ordinary member: "
                                         "[\\%s] is a backslash or %r, not a shorthand class" % (chr(nb), chr(nb)))
                elif nb == 0x5D and self.i + 1 < n and p[self.i + 1] == 0x5D:
                    self.warnings.append("[...\\]] : the backslash does not escape the ], the bracket ends at the first ]")
            if cls is not None:
                complex_element = True
                if self.i + 1 < n and p[self.i] == 0x2D and p[self.i + 1] != 0x5D:
                    raise EREError("Invalid range end")
                members |= cls
                continue
            assert single is not None
            if self.i + 1 < n and p[self.i] == 0x2D and p[self.i + 1] != 0x5D:
                self.i += 1
                hi, hcls = element(accept_hyphen=True)
                if hcls is not None or hi is None:
                    raise EREError("Invalid range end")
                if single > hi or (self.ic and _upper(single) > _upper(hi)):
                    # glibc upper-cases a case-insensitive pattern before it orders a range, so [Z-a] is an error
                    # under -i although it is fine without
                    raise EREError("Invalid range end")
                complex_element = True
                members.update(range(single, hi + 1))
            else:
                members.add(single)
        content = p[content_start:self.i - 1]
        if (not complex_element and len(content) >= 2 and content[:1] == b":" and content[-1:] == b":"
                and content.strip(b":")):
            raise EREError("character class syntax is [[:space:]], not [:space:]")
        bits = frozenset(members - {NL})
        if self.ic:
            bits = _fold(bits)
        if negate:
            bits = _ALL - bits
        return Set(frozenset(bits))


def _nullable(node: Node) -> bool:
    if isinstance(node, (Empty, Assert, Backref)):
        return True
    if isinstance(node, Set):
        return False
    if isinstance(node, Cat):
        return all(_nullable(x) for x in node.items)
    if isinstance(node, Alt):
        return any(_nullable(x) for x in node.items)
    if isinstance(node, Rep):
        return node.lo == 0 or _nullable(node.node)
    if isinstance(node, Group):
        return _nullable(node.node)
    return True


def _matches_empty(node: Node) -> bool:
    """Can the node match the empty string with no assertion to satisfy? Then it matches every line."""
    if isinstance(node, Empty):
        return True
    if isinstance(node, (Assert, Set)):
        return False
    if isinstance(node, Backref):
        return False
    if isinstance(node, Cat):
        return all(_matches_empty(x) for x in node.items)
    if isinstance(node, Alt):
        return any(_matches_empty(x) for x in node.items)
    if isinstance(node, Rep):
        return node.lo == 0 or _matches_empty(node.node)
    if isinstance(node, Group):
        return _matches_empty(node.node)
    return False


def _firsts(node: Node) -> tuple[list, bool]:
    """(byte sets a match of node can start with, can node match the empty string)."""
    if isinstance(node, Set):
        return [node.bits], False
    if isinstance(node, (Empty, Assert)):
        return [], True
    if isinstance(node, Backref):
        return [], True
    if isinstance(node, Group):
        return _firsts(node.node)
    if isinstance(node, Rep):
        f, nl = _firsts(node.node)
        return f, nl or node.lo == 0
    if isinstance(node, Alt):
        out, nl = [], False
        for x in node.items:
            f, n = _firsts(x)
            out += f
            nl = nl or n
        return out, nl
    out, nl = [], True  # Cat
    for x in node.items:
        f, n = _firsts(x)
        out += f
        if not n:
            nl = False
            break
    return out, nl


def _lasts(node: Node) -> tuple[list, bool]:
    if isinstance(node, Cat):
        out, nl = [], True
        for x in reversed(node.items):
            f, n = _lasts(x)
            out += f
            if not n:
                nl = False
                break
        return out, nl
    if isinstance(node, Group):
        return _lasts(node.node)
    if isinstance(node, Rep):
        f, nl = _lasts(node.node)
        return f, nl or node.lo == 0
    if isinstance(node, Alt):
        out, nl = [], False
        for x in node.items:
            f, n = _lasts(x)
            out += f
            nl = nl or n
        return out, nl
    return _firsts(node)


def _boundary_hazards(node: Node, out: list[str]) -> None:
    """\\b \\< \\> between two things that cannot be on opposite sides of a word edge.

    ``\\b`` holds only where exactly one neighbour is a word byte. ``\\b(a|%x)`` therefore finds ``%x`` only after a word
    byte (``p%x``, never `` %x``), and ``\\bfoo\\(\\)\\b`` finds ``foo()`` only before a word byte (never ``foo();``)."""
    if isinstance(node, Cat):
        items = node.items
        for k, it in enumerate(items):
            if isinstance(it, Assert) and it.kind in ("wordb", "wstart", "wend"):
                def side(seq, fn):
                    sets = []
                    reached_edge = True
                    for x in seq:
                        fs, nl = fn(x)
                        sets += fs
                        if not nl:
                            reached_edge = False
                            break
                    return sets, reached_edge

                before, before_edge = side(reversed(items[:k]), _lasts)
                after, after_edge = side(items[k + 1:], _firsts)
                nonword_before = any(not (b & _WORD) for b in before)
                nonword_after = any(not (b & _WORD) for b in after)
                if it.kind in ("wordb", "wstart") and nonword_after and (before_edge or nonword_before or True):
                    ex = next(b for b in after if not (b & _WORD))
                    out.append("a word boundary (\\b or \\<) in front of %s: it only holds after a word character, so that "
                               "alternative is not found at the start of a line or after a space" %
                               ("'" + chr(next(iter(ex))) + "'" if len(ex) == 1 else "a set with no word character"))
                if it.kind in ("wordb", "wend") and nonword_before and (nonword_after or after_edge):
                    out.append("a word boundary (\\b or \\>) after a character that cannot be a word character, followed by "
                               "%s: it only holds in front of a word character, so a match that ends there is not found "
                               "before a space, punctuation or the end of the line" %
                               ("the end of the pattern" if after_edge and not nonword_after else "a non-word character"))
            _boundary_hazards(it, out)
    elif isinstance(node, Alt):
        for it in node.items:
            _boundary_hazards(it, out)
    elif isinstance(node, (Rep, Group)):
        _boundary_hazards(node.node, out)


def _check_backrefs(ast: Node) -> None:
    """A pattern with a back-reference is matched by glibc, not by grep's DFA, and glibc's handling of a group that may
    be empty, or that sits inside a repetition, is not what Python does ((|a){2,}\\1 matches nothing in grep, almost
    everything in re). Only the plain shape is translated: the referenced group must match at least one byte and
    must not be repeated."""
    refs = _referenced(ast, set())

    def walk(n: Node, in_rep: bool) -> None:
        if isinstance(n, Group):
            if n.index in refs:
                if _nullable(n.node):
                    raise UnsupportedERE(f"back-reference to group {n.index}, which can match the empty string")
                if in_rep:
                    raise UnsupportedERE(f"back-reference to group {n.index}, which is inside a repetition")
            walk(n.node, in_rep)
        elif isinstance(n, (Cat, Alt)):
            for x in n.items:
                walk(x, in_rep)
        elif isinstance(n, Rep):
            walk(n.node, True)

    walk(ast, False)


def parse_ere(pattern: str | bytes, ignore_case: bool = False) -> Parsed:
    """Parse a GNU ERE into the module's AST. A newline separates alternative patterns, as it does in grep."""
    pat = pattern.encode("utf-8", "surrogateescape") if isinstance(pattern, str) else bytes(pattern)
    branches: list[Node] = []
    ngroups = 0
    has_backref = False
    warnings: list[str] = []
    for piece in pat.split(b"\n"):
        ps = _Parser(piece, ignore_case)
        ps.ngroups = ngroups
        try:
            node = ps.parse_alt()
            if ps.i < ps.n:  # parse_alt stops only at '|' consumed or ')' at depth 0 (handled as literal)
                raise EREError("Unmatched ) or \\)")
        except RecursionError as exc:
            raise EREError("pattern nests too deeply") from exc
        ngroups = ps.ngroups
        has_backref = has_backref or ps.has_backref
        warnings += ps.warnings
        if ps.has_backref and ps.anchor_repeated:
            # a pattern with a back-reference is matched by glibc, whose reading of a repeated anchor differs from
            # the DFA's, which is the reading translated here
            raise UnsupportedERE("a repeated anchor in a pattern with a back-reference")
        branches.append(node)
    if len(branches) > 1 and has_backref:
        raise UnsupportedERE("a back-reference in a pattern list separated by newlines")
    ast = branches[0] if len(branches) == 1 else Alt(tuple(branches))
    if has_backref:
        _check_backrefs(ast)
    _boundary_hazards(ast, warnings)
    if _matches_empty(ast):
        warnings.append("the pattern can match the empty string, so it matches every line (an empty alternative such as "
                        "'a|' or '(|a)', or a pattern made only of optional parts)")
    return Parsed(ast, ngroups, has_backref, warnings)


# --------------------------------------------------------------------------------------------------------
# simplification (exactly equivalent rewrites only)
# --------------------------------------------------------------------------------------------------------
_ZERO_WIDTH = (Assert, Empty)


def _referenced(node: Node, acc: set[int]) -> set[int]:
    if isinstance(node, Backref):
        acc.add(node.index)
    elif isinstance(node, (Cat, Alt)):
        for x in node.items:
            _referenced(x, acc)
    elif isinstance(node, (Rep, Group)):
        _referenced(node.node, acc)
    return acc


def _simplify(node: Node, keep: frozenset) -> Node:
    """Exactly-equivalent rewrites. ``keep`` holds the group numbers a back-reference needs; every other group is
    only a bracket and is removed, which is what lets ``(a+)+`` be seen as a repetition of a repetition."""
    if isinstance(node, Cat):
        items = []
        for it in node.items:
            it = _simplify(it, keep)
            if isinstance(it, Empty):
                continue
            if isinstance(it, Cat):
                items.extend(it.items)
            else:
                items.append(it)
        if not items:
            return Empty()
        return items[0] if len(items) == 1 else Cat(tuple(items))
    if isinstance(node, Alt):
        items = []
        for it in node.items:
            it = _simplify(it, keep)
            if isinstance(it, Alt):
                items.extend(it.items)  # a|(b|c) is a|b|c
            else:
                items.append(it)
        return Alt(tuple(items))
    if isinstance(node, Group):
        inner = _simplify(node.node, keep)
        return Group(inner, node.index) if node.index in keep else inner
    if isinstance(node, Rep):
        inner = _simplify(node.node, keep)
        lo, hi = node.lo, node.hi
        if hi == 0:  # x{0} and x{0,0} match only the empty string
            return Empty()
        if isinstance(inner, _ZERO_WIDTH):
            # (^)* matches the empty string anywhere; (^)+ is just ^
            return Empty() if lo == 0 else inner
        if isinstance(inner, Rep):
            a, b = inner.lo, inner.hi
            # (x{a,b}){lo,hi} is x{a*lo, b*hi} when a <= 1: the set of counts is contiguous
            if a <= 1:
                nlo = a * lo
                if hi is None:
                    nhi = None if b is None or b > 0 else 0
                elif b is None:
                    nhi = None
                else:
                    nhi = b * hi
                return Rep(inner.node, nlo, nhi)
        if lo == 1 and hi == 1:
            return inner
        return Rep(inner, lo, hi)
    return node


# --------------------------------------------------------------------------------------------------------
# emission
# --------------------------------------------------------------------------------------------------------
def _esc(b: int) -> bytes:
    if 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122:
        return bytes([b])
    return b"\\x%02x" % b


def _emit_set(bits: frozenset) -> bytes:
    """A bytes character class for ``bits`` (which never holds the newline). The negated form lists the newline,
    so it stays excluded."""
    if not bits:
        return b"(?!)"  # an empty class: matches nothing
    if len(bits) == 255:  # every byte but the newline
        return b"[^\\n]"
    pos = sorted(bits)
    neg = sorted(set(range(256)) - bits)
    members, out = (pos, bytearray(b"[")) if len(pos) <= len(neg) else (neg, bytearray(b"[^"))
    i = 0
    while i < len(members):
        j = i
        while j + 1 < len(members) and members[j + 1] == members[j] + 1:
            j += 1
        if j - i >= 2:
            out += _esc(members[i]) + b"-" + _esc(members[j])
        else:
            for k in range(i, j + 1):
                out += _esc(members[k])
        i = j + 1
    out += b"]"
    return bytes(out)


_WB = b"[A-Za-z0-9_]"


class _Emitter:
    """Writes the Python pattern. Groups are numbered as they are written, so a back-reference follows its group even
    when the simplifier has removed the groups in between."""

    def __init__(self, capturing: bool) -> None:
        self.capturing = capturing
        self.count = 0
        self.number: dict[int, int] = {}

    def emit(self, node: Node) -> bytes:
        if isinstance(node, Empty):
            return b""
        if isinstance(node, Set):
            if len(node.bits) == 1:
                return _esc(next(iter(node.bits)))
            return _emit_set(node.bits)
        if isinstance(node, Cat):
            return b"".join(b"(?:" + self.emit(x) + b")" if isinstance(x, Alt) else self.emit(x) for x in node.items)
        if isinstance(node, Alt):
            return b"|".join(self.emit(x) for x in node.items)
        if isinstance(node, Group):
            if self.capturing:
                self.count += 1
                self.number[node.index] = self.count
                return b"(" + self.emit(node.node) + b")"
            return b"(?:" + self.emit(node.node) + b")"
        if isinstance(node, Backref):
            return b"(?:\\%d)" % self.number[node.index]
        if isinstance(node, Assert):
            k = node.kind
            if k == "bol":
                return b"^"
            if k == "eol":
                return b"$"
            if k == "wordb":
                return b"\\b"
            if k == "nwordb":
                return b"(?:(?<!" + _WB + b")(?!" + _WB + b")|(?<=" + _WB + b")(?=" + _WB + b"))"
            if k == "wstart":
                return b"\\b(?=" + _WB + b")"
            if k == "wend":
                return b"\\b(?<=" + _WB + b")"
            raise AssertionError(k)
        if isinstance(node, Rep):
            inner = node.node
            body = self.emit(inner)
            # anything that is not a single atom is bracketed, so the quantifier cannot bind to part of it or be read as
            # lazy / possessive when the body is itself a quantified item
            if not (isinstance(inner, (Set, Backref)) or (isinstance(inner, Group) and self.capturing)):
                body = b"(?:" + body + b")"
            lo, hi = node.lo, node.hi
            if lo == 0 and hi is None:
                q = b"*"
            elif lo == 1 and hi is None:
                q = b"+"
            elif lo == 0 and hi == 1:
                q = b"?"
            elif hi is None:
                q = b"{%d,}" % lo
            elif lo == hi:
                q = b"{%d}" % lo
            else:
                q = b"{%d,%d}" % (lo, hi)
            return body + q
        raise AssertionError(type(node))


def _build(parsed: Parsed, simplify: bool) -> bytes:
    ast = parsed.ast
    if simplify:
        ast = _simplify(ast, frozenset(_referenced(ast, set())))
    return _Emitter(parsed.has_backref).emit(ast)


def ere_to_py_source(pattern: str | bytes, ignore_case: bool = False, *, simplify: bool = True) -> bytes:
    """The Python (bytes) pattern text for a GNU ERE. Compile it with re.MULTILINE."""
    return _build(parse_ere(pattern, ignore_case), simplify)


# --------------------------------------------------------------------------------------------------------
# compiled patterns and the registry
# --------------------------------------------------------------------------------------------------------
_CACHE: dict[tuple[bytes, bool, bool], re.Pattern] = {}
_AST: dict[re.Pattern, tuple[Node, bool]] = {}  # compiled pattern -> (tree, has back-reference), for the linear matcher
_DFAS: dict[re.Pattern, "_DFA | None"] = {}
_LOCK = threading.Lock()


def ere_to_py(pattern: str | bytes, ignore_case: bool = False, *, simplify: bool = True) -> re.Pattern:
    """Compile a GNU ERE to a bytes ``re.Pattern`` with grep's per-line semantics.

    Use it with ``search_lines`` / ``matching_lines`` (whole buffers) or ``.search(line)`` (one line). The pattern is
    compiled with re.MULTILINE, so ``^`` and ``$`` are line anchors, and it cannot match across a newline.
    Raises EREError for a pattern grep would reject."""
    key = (pattern.encode("utf-8", "surrogateescape") if isinstance(pattern, str) else bytes(pattern),
           bool(ignore_case), bool(simplify))
    with _LOCK:
        hit = _CACHE.get(key)
    if hit is not None:
        return hit
    parsed = parse_ere(key[0], ignore_case)
    src = _build(parsed, simplify)
    flags = re.MULTILINE | (re.IGNORECASE if ignore_case and parsed.has_backref else 0)
    try:
        comp = re.compile(src, flags)
    except (re.error, RecursionError, OverflowError) as exc:
        raise EREError(f"Python could not compile {src!r}: {exc}") from exc
    with _LOCK:
        _CACHE[key] = comp
        _AST[comp] = (parsed.ast if parsed.has_backref else _simplify(parsed.ast, frozenset()), parsed.has_backref)
    return comp


def compiled_patterns() -> list[tuple[bytes, bool, re.Pattern]]:
    """Every pattern compiled so far in this process: (ERE text, ignore_case, compiled)."""
    with _LOCK:
        return [(k[0], k[1], v) for k, v in _CACHE.items() if k[2]]


@dataclass(frozen=True)
class Rule:
    """A named rule as the engine registers it, so a CI gate can enumerate and fuzz every one."""
    id: str
    pattern: str
    mode: str  # line | line_i | excl | flat | line_a
    excl: str | None
    compiled: re.Pattern
    compiled_excl: re.Pattern | None


_RULES: dict[str, Rule] = {}


def rule(rule_id: str, pattern: str, *, mode: str = "line", excl: str | None = None) -> Rule:
    """Compile and register a rule. mode: line (grep_check), line_i (grep_check_i), excl (grep_check_excl),
    flat (grep_flat), line_a (the pdf helper, grep -a)."""
    if mode not in ("line", "line_i", "excl", "flat", "line_a"):
        raise ValueError(f"unknown mode {mode!r}")
    if mode == "excl" and excl is None:
        raise ValueError("mode 'excl' needs an exclusion pattern")
    ci = mode in ("line_i", "excl", "flat")
    r = Rule(rule_id, pattern, mode, excl, ere_to_py(pattern, ci), ere_to_py(excl, True) if excl is not None else None)
    prev = _RULES.get(rule_id)
    if prev is not None and (prev.pattern, prev.mode, prev.excl) != (pattern, mode, excl):
        raise ValueError(f"rule id {rule_id!r} registered twice with different content")
    _RULES[rule_id] = r
    return r


def registered() -> list[Rule]:
    return list(_RULES.values())


# --------------------------------------------------------------------------------------------------------
# a linear-time matcher for the same patterns
# --------------------------------------------------------------------------------------------------------
# grep is automaton-based and linear; Python's re backtracks. A rule such as ``curl[^|]*http://`` is fast on every real
# file and quadratic on a long line that repeats ``curl x`` without ever reaching ``http://`` (64 KB: 2 s in re, 3 ms in
# grep). The fuzz in tests/conformance measures this. So every pattern without a back-reference can also be run as a lazy
# DFA built from the same parse tree: slower per byte than re on a normal line, but linear on any line. ``budget=``
# on the search functions below runs re first and switches to the DFA for the rest of the buffer when re runs out of time.
_WORD_BYTES = bytes(1 if (48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122 or b == 95) else 0 for b in range(256))
_BOL, _WORDCTX, _OTHER = 0, 1, 2  # context of the previous byte; for the next byte 0 means end of line
MAX_NFA_STATES = 60_000
MAX_DFA_STATES = 4_000


class _TooBig(Exception):
    pass


class _DFA:
    """Lazy DFA for "does this line contain a match", built from the parse tree (counted repetitions are unrolled).

    A DFA state is (set of NFA states not yet closed over epsilons and assertions, class of the previous byte). The closure
    is taken when the next byte is known, because ^ $ \b \B \< \> depend on the byte before and the byte after."""

    def __init__(self, ast: Node) -> None:
        self.kind: list[int] = []     # 0 consume a byte of a set, 1 split, 2 assertion, 3 match
        self.out: list[int] = []
        self.alt: list[int] = []
        self.arg: list = []           # bytes(256) membership for a set, the assertion name for an assertion
        match = self._new(3, -1, -1, None)
        self.start = self._build(ast, match)
        self.ids: dict = {}
        self.keys: list = []
        self.trans: list[list] = []
        self.eol: list = []
        self._reset()

    # -- NFA ---------------------------------------------------------------------------------------------
    def _new(self, kind: int, out: int, alt: int, arg) -> int:
        if len(self.kind) >= MAX_NFA_STATES:
            raise _TooBig
        self.kind.append(kind)
        self.out.append(out)
        self.alt.append(alt)
        self.arg.append(arg)
        return len(self.kind) - 1

    def _build(self, node: Node, nxt: int) -> int:
        if isinstance(node, Empty):
            return nxt
        if isinstance(node, Set):
            member = bytearray(256)
            for b in node.bits:
                member[b] = 1
            return self._new(0, nxt, -1, bytes(member))
        if isinstance(node, Cat):
            for it in reversed(node.items):
                nxt = self._build(it, nxt)
            return nxt
        if isinstance(node, Alt):
            starts = [self._build(it, nxt) for it in node.items]
            cur = starts[-1]
            for st in reversed(starts[:-1]):
                cur = self._new(1, st, cur, None)
            return cur
        if isinstance(node, Group):
            return self._build(node.node, nxt)
        if isinstance(node, Assert):
            return self._new(2, nxt, -1, node.kind)
        if isinstance(node, Rep):
            lo, hi = node.lo, node.hi
            if hi is None:
                loop = self._new(1, -1, nxt, None)
                self.out[loop] = self._build(node.node, loop)
                cur = loop
            else:
                cur = nxt
                for _ in range(hi - lo):
                    cur = self._new(1, self._build(node.node, cur), nxt, None)
            for _ in range(lo):
                cur = self._build(node.node, cur)
            return cur
        raise _TooBig  # a back-reference has no DFA

    # -- DFA ---------------------------------------------------------------------------------------------
    def _reset(self) -> None:
        self.ids.clear()
        del self.keys[:]
        del self.trans[:]
        del self.eol[:]
        self._intern(frozenset((self.start,)), _BOL)  # state 0: the start of a line

    def _intern(self, kernel: frozenset, prev: int) -> int:
        key = (kernel, prev)
        i = self.ids.get(key)
        if i is None:
            i = len(self.keys)
            self.ids[key] = i
            self.keys.append(key)
            self.trans.append([None] * 256)
            self.eol.append(None)
        return i

    @staticmethod
    def _holds(name: str, prev: int, nxt: int) -> bool:
        if name == "bol":
            return prev == _BOL
        if name == "eol":
            return nxt == 0
        pw, nw = prev == _WORDCTX, nxt == _WORDCTX
        if name == "wordb":
            return pw != nw
        if name == "nwordb":
            return pw == nw
        if name == "wstart":
            return (not pw) and nw
        return pw and not nw  # wend

    def _close(self, kernel: frozenset, prev: int, nxt: int) -> tuple[list[int], bool]:
        kind, out, alt, arg = self.kind, self.out, self.alt, self.arg
        seen: set[int] = set()
        stack = list(kernel)
        consumers: list[int] = []
        while stack:
            s = stack.pop()
            if s in seen:
                continue
            seen.add(s)
            k = kind[s]
            if k == 0:
                consumers.append(s)
            elif k == 1:
                stack.append(out[s])
                stack.append(alt[s])
            elif k == 2:
                if self._holds(arg[s], prev, nxt):
                    stack.append(out[s])
            else:
                return consumers, True
        return consumers, False

    def _step(self, sid: int, c: int) -> int:
        kernel, prev = self.keys[sid]
        wordc = _WORD_BYTES[c]
        consumers, matched = self._close(kernel, prev, _WORDCTX if wordc else _OTHER)
        if matched:
            self.trans[sid][c] = -1  # a match ends here, whatever follows
            return -1
        nk = {self.out[s] for s in consumers if self.arg[s][c]}
        nk.add(self.start)
        newprev = _WORDCTX if wordc else _OTHER
        if len(self.keys) >= MAX_DFA_STATES:
            self._reset()  # forget the cache and carry on: still linear, only slower (RE2 does the same)
            return self._intern(frozenset(nk), newprev)
        res = self._intern(frozenset(nk), newprev)
        self.trans[sid][c] = res
        return res

    def _at_eol(self, sid: int) -> bool:
        e = self.eol[sid]
        if e is None:
            kernel, prev = self.keys[sid]
            e = self._close(kernel, prev, 0)[1]
            self.eol[sid] = e
        return e

    def any_line(self, data: bytes, start: int, end: int) -> bool:
        """Does any line of data[start:end] contain a match?"""
        trans = self.trans
        st = 0
        step = self._step
        at_eol = self._at_eol
        for c in memoryview(data)[start:end]:
            if c == 10:
                if at_eol(st):
                    return True
                st = 0
                continue
            nxt = trans[st][c]
            if nxt is None:
                nxt = step(st, c)
            if nxt < 0:
                return True
            st = nxt
        return at_eol(st)

    def lines(self, data: bytes, start: int, end: int) -> Iterator[tuple[int, int]]:
        """(line start, line end) of every line of data[start:end] that contains a match."""
        mv = memoryview(data)
        trans, step, at_eol = self.trans, self._step, self._at_eol
        pos = start
        while pos <= end:
            st = 0
            ls = i = pos
            hit = None
            for c in mv[pos:end]:
                if c == 10:
                    if at_eol(st):
                        hit = i
                        break
                    st = 0
                    ls = i + 1
                else:
                    nxt = trans[st][c]
                    if nxt is None:
                        nxt = step(st, c)
                    if nxt < 0:
                        hit = i
                        break
                    st = nxt
                i += 1
            else:
                if at_eol(st):
                    hit = end
            if hit is None:
                return
            le = data.find(b"\n", hit, end) if hit < end else end
            if le < 0:
                le = end
            yield ls, le
            pos = le + 1


def _dfa_for(compiled: re.Pattern) -> "_DFA | None":
    with _LOCK:
        if compiled in _DFAS:
            return _DFAS[compiled]
        entry = _AST.get(compiled)
    dfa = None
    if entry is not None and not entry[1]:
        try:
            dfa = _DFA(entry[0])
        except (_TooBig, RecursionError):
            dfa = None
    with _LOCK:
        _DFAS[compiled] = dfa
    return dfa


def dfa_available(compiled: re.Pattern) -> bool:
    """True if the linear matcher can run this pattern (it cannot run a back-reference)."""
    return _dfa_for(compiled) is not None


def dfa_matching_lines(compiled: re.Pattern, data: bytes, *, binary: str = "text") -> Iterator[tuple[int, int]]:
    """Like ``matching_lines`` but with the linear matcher; raises ValueError if the pattern has no DFA."""
    dfa = _dfa_for(compiled)
    if dfa is None:
        raise ValueError("this pattern has no linear matcher")
    if not data:
        return
    d, end = _prepare(data, binary)
    if not d:
        return
    yield from dfa.lines(d, 0, end)


def dfa_search(compiled: re.Pattern, data: bytes, *, binary: str = "text") -> bool:
    """Like ``search_lines`` but with the linear matcher."""
    dfa = _dfa_for(compiled)
    if dfa is None:
        raise ValueError("this pattern has no linear matcher")
    if not data:
        return False
    d, end = _prepare(data, binary)
    if not d:
        return False
    return dfa.any_line(d, 0, end)


# --------------------------------------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------------------------------------
def _prepare(data: bytes, binary: str) -> tuple[bytes, int]:
    """Apply grep's binary-file handling and drop the final newline. Returns (data, end offset)."""
    if binary == "grep":
        if b"\0" in data:
            data = data.replace(b"\0", b"\n")
    elif binary == "skip":
        if b"\0" in data[:32768]:
            return b"", 0
    elif binary != "text":
        raise ValueError(f"binary must be 'text', 'grep' or 'skip', not {binary!r}")
    end = len(data)
    if end and data[end - 1] == NL:
        end -= 1  # a trailing newline ends the last line; it does not start another one
    return data, end


def _guarded_search(compiled: re.Pattern, d: bytes, pos: int, end: int, budget: float | None):
    """compiled.search(d, pos, end) -> match or None, or RegexTimeout if it took longer than ``budget`` seconds."""
    if budget is None:
        return compiled.search(d, pos, end)
    with time_limit(budget):
        return compiled.search(d, pos, end)


def _lines_of(compiled: re.Pattern, d: bytes, end: int, budget: float | None = None) -> Iterator[tuple[int, int]]:
    """(start, end) of each line of d[:end] that has a match; the search resumes after the line.

    With ``budget`` a single search that outlasts it is abandoned and the rest of the buffer is scanned by the linear
    matcher (RegexTimeout if the pattern has none)."""
    pos = 0
    while pos <= end:
        try:
            m = _guarded_search(compiled, d, pos, end, budget)
        except RegexTimeout:
            dfa = _dfa_for(compiled)
            if dfa is None:
                raise
            yield from dfa.lines(d, pos, end)
            return
        if m is None:
            return
        ls = d.rfind(b"\n", 0, m.start()) + 1
        le = d.find(b"\n", m.end(), end)
        if le < 0:
            le = end
        yield ls, le
        pos = le + 1


def search_lines(compiled: re.Pattern, data: bytes, *, binary: str = "text", budget: float | None = None) -> bool:
    """grep -q: does any line of ``data`` match? Lines end at b"\\n"; an empty buffer has no lines.

    ``budget`` (seconds, main thread only): re may spend that long, then the linear matcher takes over for the rest of the
    buffer. Without it a hostile long line can make a backtracking pattern quadratic."""
    if not data:
        return False
    data, end = _prepare(data, binary)
    if end == 0 and not data:
        return False
    try:
        return _guarded_search(compiled, data, 0, end, budget) is not None
    except RegexTimeout:
        dfa = _dfa_for(compiled)
        if dfa is None:
            raise
        return dfa.any_line(data, 0, end)


def matching_lines(compiled: re.Pattern, data: bytes, *, binary: str = "text",
                   budget: float | None = None) -> Iterator[tuple[int, int]]:
    """Yield (start, end) offsets of every line that has a match (end excludes the newline)."""
    if not data:
        return
    d, end = _prepare(data, binary)
    if not d:
        return
    yield from _lines_of(compiled, d, end, budget)


def _line_has(compiled: re.Pattern, d: bytes, ls: int, le: int, budget: float | None) -> bool:
    try:
        return _guarded_search(compiled, d, ls, le, budget) is not None
    except RegexTimeout:
        dfa = _dfa_for(compiled)
        if dfa is None:
            raise
        return dfa.any_line(d, ls, le)


def excl_lines(pat: re.Pattern, excl: re.Pattern, data: bytes, *, binary: str = "text",
               budget: float | None = None) -> Iterator[tuple[int, int]]:
    """Lines that match ``pat`` and do not match ``excl`` (grep -hiE pat | grep -viE excl).

    ``binary="grep"`` reproduces bash exactly, including its blind spot: on a file that holds a NUL byte the first
    grep prints only a "binary file matches" notice (to stderr since grep 3.5, to stdout before that, which flips
    the answer), so the second grep sees nothing and the helper reports no match."""
    if not data:
        return
    if binary == "grep" and b"\0" in data:
        return
    d, end = _prepare(data, binary)
    if not d:
        return
    for ls, le in _lines_of(pat, d, end, budget):
        if not _line_has(excl, d, ls, le, budget):
            yield ls, le


def _as_compiled(x: str | bytes | re.Pattern, ignore_case: bool) -> re.Pattern:
    return x if isinstance(x, re.Pattern) else ere_to_py(x, ignore_case)


def search_excl(pat: str | bytes | re.Pattern, excl: str | bytes | re.Pattern, data: bytes, *,
                binary: str = "text", budget: float | None = None) -> bool:
    """grep_check_excl: some line matches ``pat`` and does not match ``excl``, both case-insensitively.

    Strings are compiled with ignore_case=True. Bash runs ``grep -hiE pat FILE | grep -viE excl``: on a file that
    holds a NUL byte the first grep prints nothing, so bash answers False whatever the content. ``binary="text"``
    (the default) does not copy that; ``binary="grep"`` does. See the divergence register."""
    p = _as_compiled(pat, True)
    x = _as_compiled(excl, True)
    for _ in excl_lines(p, x, data, binary=binary, budget=budget):
        return True
    return False


def flat_view(data: bytes, cap: int = FLAT_CAP) -> bytes:
    """grep_flat's view: CR, LF and TAB become spaces so one pattern can see across a line break.

    Bash tests ``wc -c <= 5242880`` first and otherwise ``return 1`` (no match): a larger file is not cut, it is not
    searched. This returns b"" for it, which no pattern matches."""
    if len(data) > cap:
        return b""
    return data.translate(_FLAT_TABLE)


_FLAT_TABLE = bytes(32 if b in (9, 10, 13) else b for b in range(256))


def search_flat(compiled: re.Pattern, data: bytes, cap: int = FLAT_CAP, *, budget: float | None = None) -> bool:
    """grep_flat: match against the folded view, which is a single line (the view has no newline left).

    This is the case ``budget`` matters most for: the view can be 5 MB long, all one line."""
    view = flat_view(data, cap)
    if not view:
        return False
    try:
        return _guarded_search(compiled, view, 0, len(view), budget) is not None
    except RegexTimeout:
        dfa = _dfa_for(compiled)
        if dfa is None:
            raise
        return dfa.any_line(view, 0, len(view))


def only_matching(compiled: re.Pattern, data: bytes, *, binary: str = "text") -> list[bytes]:
    """grep -o: the text of every non-empty match, line by line, left to right, not overlapping.

    Leftmost-FIRST (Python), where grep is leftmost-LONGEST: the two differ only for an ambiguous alternation."""
    out: list[bytes] = []
    if not data:
        return out
    d, end = _prepare(data, binary)
    for ls, le in _lines_of(compiled, d, end):
        pos = ls
        while pos <= le:
            m = compiled.search(d, pos, le)
            if m is None or m.start() > le:
                break
            if m.end() == m.start():
                pos = m.end() + 1
                continue
            out.append(m.group(0))
            pos = m.end()
    return out


def after_context(compiled: re.Pattern, data: bytes, after: int, *, binary: str = "text") -> bytes:
    """What ``grep -E -A<after> -e PATTERN FILE`` writes (no -n, no file name): every matching line and the ``after``
    lines that follow it, a line that is not adjacent to the last one printed preceded by a ``--`` line.

    The private-key rule pipes this through ``tr '\\r\\n\\t' '   '`` and a second grep, so the header and the body may be
    a few lines apart. Returns b"" when nothing matches."""
    if not data:
        return b""
    d, end = _prepare(data, binary)
    if not d or compiled.search(d, 0, end) is None:
        return b""
    out: list[bytes] = []
    last = -2
    pending = 0

    def emit(i: int, line: bytes) -> None:
        nonlocal last
        if last >= 0 and i > last + 1:
            out.append(b"--")
        out.append(line)
        last = i

    for i, line in enumerate(d[:end].split(b"\n")):
        if compiled.search(line) is not None:
            emit(i, line)
            pending = after
        elif pending > 0:
            emit(i, line)
            pending -= 1
    return b"\n".join(out) + b"\n"


def lines_over(data: bytes, limit: int) -> int:
    """How many lines are longer than ``limit`` bytes (for a reported, never silent, line-length cap)."""
    if len(data) <= limit:
        return 0
    return sum(1 for ln in data.split(b"\n") if len(ln) > limit)


@contextmanager
def time_limit(seconds: float) -> Iterator[None]:
    """Raise RegexTimeout if the body runs longer than ``seconds`` (SIGALRM; main thread, POSIX only).

    The regex engine polls for signals, so this interrupts a match that has run away. It is the backstop for a
    pattern that backtracks, not a substitute for a pattern that does not."""
    if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
        yield
        return

    def handler(signum, frame):  # noqa: ARG001
        raise RegexTimeout(f"regex exceeded {seconds}s")

    old = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
