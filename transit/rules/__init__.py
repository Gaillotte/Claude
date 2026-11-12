"""Declarative rule tables and the only way a rule is evaluated.

A scanner's pattern rules are DATA: a ``RuleSet`` built from ``RuleSpec`` rows, each row one ``record_fail`` or
``record_warn`` of the bash scanner (id, message, pattern, mode, case-insensitivity, exclusion, applies-to). The table
lives at the top of the scanner module that owns it (``transit/scanners/python_lang.py`` has ``RULES``); this package holds
only the machinery, so two scanner packages never edit the same file.

Owner of: S12 (hostile input costs bounded time) for pattern rules, the regex rule of PYTHON_PORT_PLAN 5.1/5.2
("compiled ONLY through transit/rx.py"), contract 8.7 (which grep flags a rule corresponds to).

Layering: depends on ``transit.rx`` (and the standard library) only. It never records anything: ``run_ruleset`` returns
which rules matched, and ``ScanContext.run_rules`` (transit.scanners) turns hits into ``record_fail`` / ``record_warn``.
No ``re`` here: ``rx.ere_to_py`` is the only compiler, and every rule is registered with ``rx.rule`` so the CI fuzz gate
(``rx.registered()``) sees it.

Search policy (measured, see design section 9.2). ``rx``'s ``budget=`` is an alarm that is only polled between
steps of the regex engine: on one line of 70 KB it let a 0.25 s budget run 0.78 s, on 600 KB 8.9 s, on 5 MB 74 s,
while the linear matcher needs 0.02 s for the 600 KB. So a buffer that holds a line longer than
``SearchPolicy.long_line_bytes`` goes STRAIGHT to the linear matcher (``rx.dfa_search``); shorter buffers use ``re`` with
``budget=rule_budget_s``. A per-line length CAP is never used: padding would hide a payload (PYTHON_PORT_PLAN status block).
``rx.time_limit`` cannot be nested (the inner exit cancels the outer timer, measured), so nothing in the engine wraps a
search in a second ``time_limit``; the per-file budget is a deadline checked BETWEEN rules.
"""
from __future__ import annotations

import dataclasses
from typing import Callable, Sequence, Union

from transit import rx

MODES = ("line", "flat")
BINARY_MODES = ("text", "grep", "skip")


class ScanBudgetExceeded(Exception):
    """The per-file deadline passed between two rules. The context records a WARN and a ``partial`` coverage note."""


@dataclasses.dataclass(frozen=True)
class SearchPolicy:
    """How a search is run. Built once from ``Config.limits`` and ``Config.fix('D-029')``."""
    rule_budget_s: float = 0.25
    long_line_bytes: int = 8192
    #: Bash behaviour for ``excl`` matches on a file with a NUL byte (``grep_check_excl`` reads nothing, so the rule never
    #: fires, A15-like blind spot). True copies bash; False (switch D-029) searches the file as text.
    excl_nul_blind: bool = True


@dataclasses.dataclass(frozen=True)
class Target:
    """What a rule is evaluated against: bytes plus the facts a rule can depend on. Built by ``FileView.target``.
    ``flat`` is a callable so the folded copy (up to 5 MB) is made only if a ``flat`` rule needs it, once."""
    data: bytes
    basename: str
    ext: str
    has_long_line: bool
    flat: Callable[[], bytes]


@dataclasses.dataclass(frozen=True)
class Match:
    """One grep call. ``mode='line'``: some single line matches (``grep -qE``; ``ci`` adds ``-i``). ``mode='flat'``: the
    file with CR, LF and TAB folded to spaces matches (``grep_flat``; always case-insensitive, over 5 MB it matches
    nothing). ``excl`` (a pattern): some line matches ``pattern`` and does not match ``excl`` (``grep_check_excl``; always
    case-insensitive; ``mode`` must be ``line``). ``binary``: ``text`` = like ``grep -a`` (a NUL byte changes nothing; this is
    ``grep_check``, E8), ``skip`` = ``grep -I`` (a file with a NUL byte in its first 32 KiB matches nothing, the known
    credential formats), ``grep`` = bash's own handling (used only for ``excl``). Patterns are POSIX ERE exactly as bash
    hands them to grep, taken from tests/conformance/patterns.json. Invalid combinations raise ``ValueError`` at construction."""
    pattern: str
    mode: str = "line"
    ci: bool = False
    excl: "str | None" = None
    binary: str = "text"


@dataclasses.dataclass(frozen=True)
class AllOf:
    """Whole-file conjunction: true when every member is (each over the WHOLE file, not necessarily the same line).
    This is bash's ``{ grep_check_i A && grep_check_i B; }`` (PowerShell ``fetch then execute``)."""
    members: "tuple[Cond, ...]"


@dataclasses.dataclass(frozen=True)
class AnyOf:
    """True when any member is (bash ``A || B``)."""
    members: "tuple[Cond, ...]"


Cond = Union[Match, AllOf, AnyOf]


@dataclasses.dataclass(frozen=True)
class AppliesTo:
    """Restricts a rule to some files of the scanner that owns it. All given conditions must hold. ``basenames`` are
    ``fnmatch.fnmatchcase`` globs on the basename, ``exts`` lower-case extensions without the dot. ``None`` fields mean
    "any". Used where one bash function branches on the file name (Maven ``pom.xml``, Gradle ``gradle.properties``)."""
    basenames: "tuple[str, ...] | None" = None
    exts: "tuple[str, ...] | None" = None


@dataclasses.dataclass(frozen=True)
class RuleSpec:
    """One row of a rule table = one ``record_fail`` / ``record_warn`` of the bash scanner.

    ``id`` is unique across the whole engine: ``<scanner id>/<NN>-<slug>`` (``python/01-os-command-injection``); a
    duplicate raises ``ValueError``. ``outcome`` is ``fail`` or ``warn``. ``message`` is the EXACT string bash passes
    (``CWE-78:OS_command_injection_risk``): tests, the allowlist and the classifier all match on it. ``severity`` is ``None``
    (derive from the message, bash behaviour) or one of ``findings.SEVERITY_NUMBER``; a unit test asserts that a given
    severity equals ``classify_severity(message)``, so the two can never disagree (D-016 stays a decision, not an accident).
    ``source`` names the bash function the row was taken from (``scan_python``). Rules of one table are evaluated in table
    order, which is the bash order."""
    id: str
    outcome: str
    message: str
    cond: Cond
    severity: "str | None" = None
    applies_to: "AppliesTo | None" = None
    source: str = ""


class RuleSet:
    """An ordered, compiled table. Construction compiles every ``Match`` through ``rx.ere_to_py`` and registers it with
    ``rx.rule`` (id ``<rule id>`` for a single match, ``<rule id>#<k>`` for the k-th leaf of a composite). Raises ``ValueError`` on a
    duplicate id or an invalid combination and ``rx.EREError`` for a pattern GNU grep would reject (in bash such a rule is
    silently inert forever; here it is an exception at import, caught by the registry as a load error)."""

    def __init__(self, name: str, rules: Sequence[RuleSpec]) -> None:
        raise NotImplementedError

    @property
    def name(self) -> str:
        raise NotImplementedError

    @property
    def rules(self) -> tuple[RuleSpec, ...]:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class RuleRun:
    """Result of ``run_ruleset``. ``hits``: the rules whose condition held, in table order. ``skipped``: ids not evaluated
    because the deadline passed (the context reports them). ``timed_out``: ids whose search ran out of time and have no
    linear matcher (a back-reference; none exists in the current inventory) - the context turns each into a FAIL."""
    hits: tuple[RuleSpec, ...]
    skipped: tuple[str, ...]
    timed_out: tuple[str, ...]


def evaluate(cond: Cond, target: Target, policy: SearchPolicy) -> bool:
    """Evaluate one condition tree. ``AllOf``/``AnyOf`` short-circuit. A ``Match`` is run as described in the module docstring.
    Raises ``rx.RegexTimeout`` only for a pattern with no linear matcher. Main thread only (``rx.time_limit``); raises
    ``RuntimeError`` elsewhere. Scanners with control flow that is not a table row call this directly."""
    raise NotImplementedError


def run_ruleset(ruleset: RuleSet, target: Target, policy: SearchPolicy,
                deadline: "float | None" = None) -> RuleRun:
    """Evaluate every applicable rule (``AppliesTo`` checked against ``target.basename`` / ``target.ext``) in table order.
    ``deadline`` is a ``time.monotonic()`` value; when it has passed before a rule starts, that rule and all later ones are
    returned in ``skipped`` and no exception is raised. Pure with respect to the engine state."""
    raise NotImplementedError
