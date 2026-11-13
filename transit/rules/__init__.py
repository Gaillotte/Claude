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

An implementation may send ONLY the over-long lines of a buffer to the linear matcher and the rest to ``re`` (the linear matcher costs
about 38 ns per byte against about 5 for ``re`` on ordinary text), as long as the answer is identical to running the linear matcher on the
whole buffer; the unit test compares the two on random buffers. Nothing in this package may split a whole buffer into a list of lines
(memory: about 19 times the buffer, measured; review log R-04) or call ``rx.after_context`` / ``rx.lines_over``.

EVERY pattern the engine evaluates is registered. A ``Match`` becomes evaluable only by being part of a ``RuleSet`` row or of a
``Matcher``, both of which compile it through ``rx.ere_to_py`` and register it with ``rx.rule`` at import time; ``evaluate`` raises
``ValueError`` for a ``Match`` that was never registered. So ``rx.registered()``, the hostile-line test and the fuzz gate see every
pattern the engine can run, including the ones that are not report rows (the private-key test, the credential formats) and the ones
a scanner combines with ``AllOf``, ``AnyOf`` or ``Not`` (review log R-18, R-21). A scanner never builds a ``Match`` inside a function.
"""
from __future__ import annotations

import contextlib
import dataclasses
import fnmatch
import threading
import time
from typing import Callable, Iterator, Sequence, Union

from transit import rx

MODES = ("line", "flat")
#: ``text``: like ``grep -a`` (a NUL byte changes nothing; ``grep_check``, E8). ``skip``: like ``grep -I`` (a buffer with a NUL byte in its
#: first 32 KiB matches nothing; the known credential formats). There is no third mode in a table: bash's own handling of an ``excl``
#: rule on a file with a NUL byte (``rx`` ``binary="grep"``) is chosen by ``SearchPolicy.excl_nul_blind``, not by the row (review log R-25).
BINARY_MODES = ("text", "skip")


class ScanBudgetExceeded(Exception):
    """The per-file deadline passed between two rules. The context records a WARN and a ``partial`` coverage note."""


@dataclasses.dataclass(frozen=True)
class SearchPolicy:
    """How a search is run. Built once per run by ``layers.run_file_layers`` (``layers.search_policy(cfg)``) from ``Config.limits``
    (``rule_budget_s``, ``long_line_bytes``) and ``Config.fix('D-029')`` (``excl_nul_blind = not fix``); nothing else builds one, and
    the two numbers have a single source (``Limits``)."""
    rule_budget_s: float = 0.25
    long_line_bytes: int = 8192
    #: Bash behaviour for ``excl`` matches on a file with a NUL byte (``grep_check_excl`` reads nothing, so the rule never
    #: fires, A15-like blind spot). True copies bash; False (switch D-029) searches the file as text.
    excl_nul_blind: bool = True


@dataclasses.dataclass(frozen=True)
class Target:
    """What a rule is evaluated against: bytes plus the facts a rule can depend on. Built by ``FileView.target``.
    ``flat`` is a callable so the folded copy (the size of the file; there is no cap, D-039) is made only if a ``flat`` rule needs it, once."""
    data: bytes
    basename: str
    ext: str
    has_long_line: bool
    flat: Callable[[], bytes]


@dataclasses.dataclass(frozen=True)
class Match:
    """One grep call. ``mode='line'``: some single line matches (``grep -qE``; ``ci`` adds ``-i``). ``mode='flat'``: the
    file with CR, LF and TAB folded to spaces matches (``grep_flat``; always case-insensitive; NO size cap: bash returned "no match"
    over 5 MiB and a hostile XML could pad itself past it, D-039). ``excl`` (a pattern): some line matches ``pattern`` and does not match
    ``excl`` (``grep_check_excl``; always case-insensitive; ``mode`` must be ``line``; ``binary`` must be ``text``: whether a NUL byte
    blinds the rule as in bash is decided by ``SearchPolicy.excl_nul_blind``, D-029, so there is one control point and not two).
    ``binary``: ``text`` = like ``grep -a`` (a NUL byte changes nothing; this is ``grep_check``, E8), ``skip`` = ``grep -I`` (a file
    with a NUL byte in its first 32 KiB matches nothing, the known credential formats). Patterns are POSIX ERE exactly as bash
    hands them to grep, taken from tests/conformance/patterns.json. Invalid combinations (``flat`` with ``excl``, ``excl`` with
    ``skip``, an unknown mode) raise ``ValueError`` at construction."""
    pattern: str
    mode: str = "line"
    ci: bool = False
    excl: "str | None" = None
    binary: str = "text"

    def __post_init__(self) -> None:
        if not isinstance(self.pattern, str):
            raise ValueError("Match.pattern must be a str, not %s" % type(self.pattern).__name__)
        if self.excl is not None and not isinstance(self.excl, str):
            raise ValueError("Match.excl must be a str or None, not %s" % type(self.excl).__name__)
        if not isinstance(self.ci, bool):
            raise ValueError("Match.ci must be a bool, not %s" % type(self.ci).__name__)
        if self.mode not in MODES:
            raise ValueError("Match.mode must be one of %r, not %r" % (MODES, self.mode))
        if self.binary not in BINARY_MODES:
            raise ValueError("Match.binary must be one of %r, not %r" % (BINARY_MODES, self.binary))
        if self.excl is not None:
            if self.mode != "line":
                raise ValueError("an excl Match needs mode 'line', not %r" % (self.mode,))
            if self.binary != "text":
                raise ValueError("an excl Match needs binary 'text' (SearchPolicy.excl_nul_blind decides), not %r" % (self.binary,))


@dataclasses.dataclass(frozen=True)
class AllOf:
    """Whole-file conjunction: true when every member is (each over the WHOLE file, not necessarily the same line).
    This is bash's ``{ grep_check_i A && grep_check_i B; }`` (PowerShell ``fetch then execute``)."""
    members: "tuple[Cond, ...]"

    def __post_init__(self) -> None:
        _check_members(self)


@dataclasses.dataclass(frozen=True)
class AnyOf:
    """True when any member is (bash ``A || B``)."""
    members: "tuple[Cond, ...]"

    def __post_init__(self) -> None:
        _check_members(self)


@dataclasses.dataclass(frozen=True)
class Not:
    """Negation of one condition (bash ``! grep_check ...``). The reference script has exactly one: ``scan_go`` warns on
    ``tls\\.Config\\s*\\{`` when ``MinVersion`` does not occur anywhere in the file, i.e.
    ``AllOf((Match(r"tls\\.Config\\s*\\{"), Not(Match("MinVersion"))))``. Its member is evaluated over the WHOLE file, like every member of an
    ``AllOf`` (review log R-21)."""
    member: "Cond"

    def __post_init__(self) -> None:
        if not isinstance(self.member, (Match, AllOf, AnyOf, Not)):
            raise ValueError("Not.member must be a Match, AllOf, AnyOf or Not, not %s" % type(self.member).__name__)


Cond = Union[Match, AllOf, AnyOf, Not]


def _check_members(cond: "AllOf | AnyOf") -> None:
    name = type(cond).__name__
    if not isinstance(cond.members, tuple):
        raise ValueError("%s.members must be a tuple (a list is not hashable, so it could never be registered), not %s"
                         % (name, type(cond.members).__name__))
    if not cond.members:
        raise ValueError("%s needs at least one member (an empty conjunction is always true, an empty alternative never)" % name)
    for member in cond.members:
        if not isinstance(member, (Match, AllOf, AnyOf, Not)):
            raise ValueError("%s members must be Match, AllOf, AnyOf or Not, not %s" % (name, type(member).__name__))


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
    ``rx.rule`` (id ``<rule id>`` for a single match, ``<rule id>#<k>`` for the k-th leaf of a composite, leaves numbered left to right
    through ``AllOf``, ``AnyOf`` and ``Not``) and records it as evaluable (see the module docstring). Raises ``ValueError`` on a
    duplicate id or an invalid combination and ``rx.EREError`` for a pattern GNU grep would reject (in bash such a rule is
    silently inert forever; here it is an exception at import, caught by the registry as a load error)."""

    def __init__(self, name: str, rules: Sequence[RuleSpec]) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("a RuleSet needs a non-empty name")
        try:
            specs = tuple(rules)
        except TypeError:
            raise ValueError("RuleSet %r: rules must be a sequence of RuleSpec" % (name,)) from None
        # Phase 1, no side effect: every row is checked and every id is claimed only on paper.
        seen: "set[str]" = set()
        for spec in specs:
            _check_spec(name, spec)
            if spec.id in seen:
                raise ValueError("RuleSet %r: rule id %r appears twice in the table" % (name, spec.id))
            seen.add(spec.id)
            owner = _RULE_OWNERS.get(spec.id)
            if owner is not None and owner != (name, spec):
                raise ValueError("RuleSet %r: rule id %r is already used by RuleSet %r (ids are unique across the engine)"
                                 % (name, spec.id, owner[0]))
            if spec.id in _MATCHER_IDS:
                raise ValueError("RuleSet %r: rule id %r is already used by a Matcher" % (name, spec.id))
        # Phase 2: compile every leaf (an invalid pattern raises rx.EREError here) and register all of them, or none.
        plan: "list[tuple[str, Match]]" = []
        for spec in specs:
            if isinstance(spec.cond, Match):
                plan.append((spec.id, spec.cond))
            else:
                plan.extend(("%s#%d" % (spec.id, k), leaf) for k, leaf in enumerate(_leaves(spec.cond), 1))
        _register_leaves(plan)
        for spec in specs:
            _RULE_OWNERS[spec.id] = (name, spec)
        self._name = name
        self._rules = specs

    @property
    def name(self) -> str:
        return self._name

    @property
    def rules(self) -> tuple[RuleSpec, ...]:
        return self._rules


class Matcher:
    """A ``Match`` that is not a report row: the private-key header and body tests, the credential-format alternation, a helper pattern of
    a container scanner. Construction compiles it through ``rx.ere_to_py``, registers it with ``rx.rule(id, ...)`` (``id`` is unique across the
    engine, ``<scanner id>/<name>``, e.g. ``universal/key-header``; a duplicate with different content raises ``ValueError``) and records it
    as evaluable, exactly as ``RuleSet`` does for its rows. It is a module-level constant of the scanner module that uses it
    (review log R-18, R-21)."""

    def __init__(self, id: str, match: Match) -> None:
        if not isinstance(id, str) or not id:
            raise ValueError("a Matcher needs a non-empty id")
        if "#" in id:
            raise ValueError("Matcher id %r: '#' is reserved for the leaves of a composite rule" % (id,))
        if not isinstance(match, Match):
            raise ValueError("Matcher %r needs a Match, not %s" % (id, type(match).__name__))
        if id in _RULE_OWNERS:
            raise ValueError("Matcher id %r is already used by a rule row of RuleSet %r" % (id, _RULE_OWNERS[id][0]))
        previous = _MATCHER_IDS.get(id)
        if previous is not None and previous != match:
            raise ValueError("Matcher id %r is already registered with a different Match" % (id,))
        _register_leaves([(id, match)])
        _MATCHER_IDS[id] = match
        self._id = id
        self._match = match
        self._rule = _EVALUABLE[match]

    @property
    def id(self) -> str:
        return self._id

    @property
    def match(self) -> Match:
        return self._match

    def search(self, target: Target, policy: SearchPolicy) -> bool:
        """``evaluate(self.match, target, policy)``."""
        return evaluate(self._match, target, policy)

    def spans(self, target: Target, policy: SearchPolicy) -> Iterator[tuple[int, int]]:
        """``(start, end)`` offsets in ``target.data`` of every LINE that matches, in order (end excludes the LF); ``mode`` must be ``line``
        (else ``ValueError``). Same policy as ``evaluate``: a buffer with an over-long line is walked by ``rx.dfa_matching_lines``, any
        other by ``rx.matching_lines(budget=policy.rule_budget_s)``. A generator: it never materialises the lines. This is what the
        private-key test uses instead of ``rx.after_context``, which is unbudgeted (0.2 s on 46 KB, 6.7 s on 281 KB, quadratic) and splits
        the whole buffer."""
        _require_main_thread()
        if self._match.mode != "line":
            raise ValueError("Matcher %r: spans needs a line Match, this one is %r" % (self._id, self._match.mode))
        # Validated here and not inside the generator, so that the error is raised by the call and not by the first next().
        return self._walk(target, policy)

    def _walk(self, target: Target, policy: SearchPolicy) -> Iterator[tuple[int, int]]:
        match, rule, data = self._match, self._rule, target.data
        budget = _budget(policy)
        if match.excl is None:
            if target.has_long_line and rx.dfa_available(rule.compiled):
                yield from rx.dfa_matching_lines(rule.compiled, data, binary=match.binary)
            else:
                yield from rx.matching_lines(rule.compiled, data, binary=match.binary, budget=budget)
            return
        pat, excl = rule.compiled, rule.compiled_excl
        if policy.excl_nul_blind and b"\0" in data:
            return                                   # bash: the first grep prints a notice and the second reads nothing
        if target.has_long_line and rx.dfa_available(pat) and rx.dfa_available(excl):
            for start, stop in rx.dfa_matching_lines(pat, data):
                if not rx.dfa_search(excl, data[start:stop + 1]):
                    yield start, stop
        else:
            yield from rx.excl_lines(pat, excl, data, binary="text", budget=budget)


@dataclasses.dataclass(frozen=True)
class RuleRun:
    """Result of ``run_ruleset``. ``hits``: the rules whose condition held, in table order. ``skipped``: ids not evaluated
    because the deadline passed (the context reports them). ``timed_out``: ids whose search ran out of time and have no
    linear matcher (a back-reference; none exists in the current inventory) - the context turns each into a FAIL."""
    hits: tuple[RuleSpec, ...]
    skipped: tuple[str, ...]
    timed_out: tuple[str, ...]


def evaluate(cond: Cond, target: Target, policy: SearchPolicy) -> bool:
    """Evaluate one condition tree. ``AllOf``/``AnyOf`` short-circuit; ``Not`` inverts its member. A ``Match`` is run as described in the module
    docstring and must have been registered by a ``RuleSet`` or a ``Matcher`` (``ValueError`` otherwise). Raises ``rx.RegexTimeout`` only for a
    pattern with no linear matcher. Main thread only (``rx.time_limit``); raises ``RuntimeError`` elsewhere. Scanners with control flow that is
    not a table row call this through ``ScanContext.search`` with a condition built at module level.

    The search per mode (design section 9.2): ``line``: linear matcher if the buffer has an over-long line, else ``re`` with the rule budget;
    ``flat``: ``target.flat()`` WITHOUT a size cap, linear matcher if it is longer than ``long_line_bytes``; ``excl``: candidates by the
    pattern, then the exclusion on each candidate line, ``binary="grep"`` when ``policy.excl_nul_blind``."""
    _require_main_thread()
    _require_registered(cond)      # the whole tree first: a short-circuit must not hide an unregistered pattern
    return _eval(cond, target, policy)


def run_ruleset(ruleset: RuleSet, target: Target, policy: SearchPolicy,
                deadline: "float | None" = None) -> RuleRun:
    """Evaluate every applicable rule (``AppliesTo`` checked against ``target.basename`` / ``target.ext``) in table order.
    ``deadline`` is a ``time.monotonic()`` value; when it has passed before a rule starts, that rule and all later ones are
    returned in ``skipped`` and no exception is raised. Pure with respect to the engine state."""
    _require_main_thread()
    hits: "list[RuleSpec]" = []
    skipped: "list[str]" = []
    timed_out: "list[str]" = []
    expired = False
    for spec in ruleset.rules:
        if not _applies(spec.applies_to, target):
            continue                                 # a rule that does not apply to this file was never due: not "skipped"
        if not expired and deadline is not None and time.monotonic() >= deadline:
            expired = True                           # checked between rules, never by an alarm (design 9.3)
        if expired:
            skipped.append(spec.id)
            continue
        try:
            if _eval(spec.cond, target, policy):
                hits.append(spec)
        except rx.RegexTimeout:
            timed_out.append(spec.id)                # no linear matcher for this pattern and `re` ran out of time
    return RuleRun(hits=tuple(hits), skipped=tuple(skipped), timed_out=tuple(timed_out))


# ---------------------------------------------------------------------------------------------------------------------
# Private machinery (not part of the frozen interface). Everything below runs on engine data or on the bytes of one file;
# no repository text is ever formatted into a message here (only ids and patterns, which are engine data).
# ---------------------------------------------------------------------------------------------------------------------
#: The severities a row may carry: ``findings.SEVERITY_NUMBER``. ``rules`` may import only ``rx``, so the words are repeated here
#: and a unit test keeps the two sets equal.
_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
#: ``grep -I`` decides "binary" from the first buffer it reads: ``rx`` looks at this many bytes (``rx._prepare``).
_SKIP_PREFIX = 32768

#: Every ``Match`` that went through a ``RuleSet`` or a ``Matcher``, with the ``rx.Rule`` it was registered as (the compiled pattern and
#: exclusion). Keyed by VALUE: an equal ``Match`` is the same rule, so the registered pattern is the one that runs.
_EVALUABLE: "dict[Match, rx.Rule]" = {}
#: Row id -> (table name, row), for the engine-wide uniqueness of ids. Building the same table again (a reloaded module) is allowed.
_RULE_OWNERS: "dict[str, tuple[str, RuleSpec]]" = {}
_MATCHER_IDS: "dict[str, Match]" = {}


def _label(match: Match) -> str:
    """The ``rx.rule`` mode of a ``Match`` (design 9.1): the case-insensitivity of ``flat`` and ``excl`` is part of the label."""
    if match.excl is not None:
        return "excl"
    if match.mode == "flat":
        return "flat"
    return "line_i" if match.ci else "line"


def _leaves(cond: Cond) -> Iterator[Match]:
    """The ``Match`` leaves of a condition tree, left to right through ``AllOf``, ``AnyOf`` and ``Not``."""
    if isinstance(cond, Match):
        yield cond
    elif isinstance(cond, (AllOf, AnyOf)):
        for member in cond.members:
            yield from _leaves(member)
    elif isinstance(cond, Not):
        yield from _leaves(cond.member)
    else:
        raise ValueError("not a condition: %s" % type(cond).__name__)


def _register_leaves(plan: "Sequence[tuple[str, Match]]") -> None:
    """Compile and register ``(rx rule id, Match)`` pairs: all of them or none. An invalid pattern (``rx.EREError``) and a clash with a
    rule already in the ``rx`` registry (``ValueError``) are found before anything is registered."""
    for _, match in plan:
        rx.ere_to_py(match.pattern, _label(match) != "line")
        if match.excl is not None:
            rx.ere_to_py(match.excl, True)
    known = {r.id: r for r in rx.registered()}
    for leaf_id, match in plan:
        previous = known.get(leaf_id)
        if previous is not None and (previous.pattern, previous.mode, previous.excl) != (match.pattern, _label(match), match.excl):
            raise ValueError("rule id %r is already registered with rx with a different pattern, mode or exclusion" % (leaf_id,))
    for leaf_id, match in plan:
        _EVALUABLE.setdefault(match, rx.rule(leaf_id, match.pattern, mode=_label(match), excl=match.excl))


def _check_spec(table: str, spec: RuleSpec) -> None:
    if not isinstance(spec, RuleSpec):
        raise ValueError("RuleSet %r: every row must be a RuleSpec, not %s" % (table, type(spec).__name__))
    if not isinstance(spec.id, str) or not spec.id:
        raise ValueError("RuleSet %r: a row needs a non-empty str id" % (table,))
    if "#" in spec.id:
        raise ValueError("RuleSet %r: rule id %r: '#' is reserved for the leaves of a composite rule" % (table, spec.id))
    if spec.outcome not in ("fail", "warn"):
        raise ValueError("rule %r: outcome must be 'fail' or 'warn', not %r" % (spec.id, spec.outcome))
    if not isinstance(spec.message, str) or not spec.message:
        raise ValueError("rule %r: message must be a non-empty str" % (spec.id,))
    if spec.severity is not None and spec.severity not in _SEVERITIES:
        raise ValueError("rule %r: severity must be None or one of %r, not %r" % (spec.id, _SEVERITIES, spec.severity))
    if not isinstance(spec.source, str):
        raise ValueError("rule %r: source must be a str" % (spec.id,))
    for _ in _leaves(spec.cond):                     # every node must be a condition; a Match checked itself when it was built
        pass
    _check_applies(spec.id, spec.applies_to)


def _check_applies(rule_id: str, applies: "AppliesTo | None") -> None:
    if applies is None:
        return
    if not isinstance(applies, AppliesTo):
        raise ValueError("rule %r: applies_to must be an AppliesTo or None" % (rule_id,))
    for field, values in (("basenames", applies.basenames), ("exts", applies.exts)):
        if values is None:
            continue
        if not isinstance(values, tuple) or not values:
            raise ValueError("rule %r: applies_to.%s must be None or a non-empty tuple (an empty one would never apply)" % (rule_id, field))
        for value in values:
            if not isinstance(value, str) or not value:
                raise ValueError("rule %r: applies_to.%s holds a non-str or empty entry" % (rule_id, field))
            if field == "exts" and (value != value.lower() or value.startswith(".")):
                # Target.ext is lower case and has no dot, so such an entry could never match: a rule silently inert forever.
                raise ValueError("rule %r: applies_to.exts entry %r must be lower case, without the dot" % (rule_id, value))


def _applies(applies: "AppliesTo | None", target: Target) -> bool:
    if applies is None:
        return True
    if applies.basenames is not None and not any(fnmatch.fnmatchcase(target.basename, glob) for glob in applies.basenames):
        return False
    if applies.exts is not None and target.ext not in applies.exts:
        return False
    return True


def _require_main_thread() -> None:
    # rx.time_limit needs SIGALRM (main thread only) and the DFA caches of rx are not thread-safe.
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("transit.rules runs on the main thread only (SIGALRM budget, non-thread-safe linear matcher)")


def _require_registered(cond: Cond) -> None:
    for leaf in _leaves(cond):
        if leaf not in _EVALUABLE:
            raise ValueError("Match %r was never registered by a RuleSet or a Matcher: an unregistered pattern would be invisible to "
                             "rx.registered(), the hostile-line test and the fuzz gate" % (leaf,))


def _budget(policy: SearchPolicy) -> float:
    # A budget of 0 would DISARM the timer (setitimer(0) cancels it) and leave re unbounded; a tiny one hands over to the linear matcher.
    return policy.rule_budget_s if policy.rule_budget_s > 0 else 0.001


# -- evaluation ---------------------------------------------------------------------------------------------------------------
def _eval(cond: Cond, target: Target, policy: SearchPolicy) -> bool:
    if isinstance(cond, Match):
        rule = _EVALUABLE.get(cond)
        if rule is None:
            raise ValueError("Match %r was never registered by a RuleSet or a Matcher" % (cond,))
        if cond.excl is not None:
            return _search_excl(rule, target, policy)
        if cond.mode == "flat":
            return _search_flat(rule, target, policy, cond.binary)
        return _search_line(rule, target, policy, cond.binary)
    if isinstance(cond, AllOf):
        for member in cond.members:
            if not _eval(member, target, policy):
                return False
        return True
    if isinstance(cond, AnyOf):
        for member in cond.members:
            if _eval(member, target, policy):
                return True
        return False
    if isinstance(cond, Not):
        return not _eval(cond.member, target, policy)
    raise ValueError("not a condition: %s" % type(cond).__name__)


def _search_line(rule: "rx.Rule", target: Target, policy: SearchPolicy, binary: str) -> bool:
    compiled, data = rule.compiled, target.data
    if not target.has_long_line or not rx.dfa_available(compiled):
        # Every line is short, so `re` with a budget is safe (a late alarm costs one short line). A pattern with no linear matcher
        # (a back-reference) has nowhere else to go: it may raise rx.RegexTimeout.
        return rx.search_lines(compiled, data, binary=binary, budget=_budget(policy))
    if not data:
        return False
    if binary == "skip" and b"\0" in data[:_SKIP_PREFIX]:
        return False                                  # grep -I: from here on the buffer is searched as text
    limit = max(1, policy.long_line_bytes)
    if len(data) <= 4 * limit:
        return rx.dfa_search(compiled, data)
    budget = _Budget(_budget(policy))

    def short_lines(start: int, stop: int) -> bool:
        if budget.spent():
            return rx.dfa_search(compiled, data[start:stop + 1])
        with budget.charge():
            return _re_range(compiled, data, start, stop, budget.left)

    return _routed(data, limit, short_lines, lambda start, stop: rx.dfa_search(compiled, data[start:stop + 1]))


def _search_excl(rule: "rx.Rule", target: Target, policy: SearchPolicy) -> bool:
    pat, excl, data = rule.compiled, rule.compiled_excl, target.data
    blind, budget = policy.excl_nul_blind, _budget(policy)
    if not (target.has_long_line and rx.dfa_available(pat) and rx.dfa_available(excl)):
        return rx.search_excl(pat, excl, data, binary="grep" if blind else "text", budget=budget)
    if not data:
        return False
    if blind and b"\0" in data:
        return False                                  # bash: grep prints a notice for a binary file, the second grep reads nothing
    limit = max(1, policy.long_line_bytes)
    if len(data) <= 4 * limit:
        return _excl_linear(pat, excl, data)
    left = _Budget(budget)

    def short_lines(start: int, stop: int) -> bool:
        if left.spent():
            return _excl_linear(pat, excl, data[start:stop + 1])
        with left.charge():
            return rx.search_excl(pat, excl, data[start:stop + 1], binary="text", budget=left.left)

    return _routed(data, limit, short_lines, lambda start, stop: _excl_linear(pat, excl, data[start:stop + 1]))


def _search_flat(rule: "rx.Rule", target: Target, policy: SearchPolicy, binary: str) -> bool:
    compiled = rule.compiled
    if binary == "skip" and b"\0" in target.data[:_SKIP_PREFIX]:
        return False
    view = target.flat()                              # the whole file folded to one line; no size cap (R-08, D-039)
    if not view:
        return False
    if len(view) > policy.long_line_bytes and rx.dfa_available(compiled):
        return rx.dfa_search(compiled, view)
    return rx.search_lines(compiled, view, budget=_budget(policy))


class _Budget:
    """The `re` time one rule may spend on ONE buffer, shared by all the runs of ordinary lines of a buffer that is routed around its
    over-long lines. Without it each run would get the whole budget again, and a buffer that alternates a long line with a run of
    8 KiB lines of ``curl x `` would cost the budget once per long line (measured: 6.2 s for 300 pairs, where the linear matcher needs 0.4 s).
    Only `re` time is charged; the clock is ``perf_counter`` so that a test which fakes ``time.monotonic`` (the deadline) is not disturbed."""

    def __init__(self, seconds: float) -> None:
        self.left = seconds

    def spent(self) -> bool:
        return self.left <= 0.0

    @contextlib.contextmanager
    def charge(self) -> Iterator[None]:
        began = time.perf_counter()
        try:
            yield
        finally:
            self.left -= time.perf_counter() - began


def _excl_linear(pat, excl, data: bytes) -> bool:
    """grep_check_excl over ``data`` with the linear matcher only: some line matches ``pat`` and not ``excl``."""
    for start, stop in rx.dfa_matching_lines(pat, data):
        if not rx.dfa_search(excl, data[start:stop + 1]):    # +1: an empty line is still the line (b"" has none)
            return True
    return False


def _re_range(compiled, data: bytes, start: int, stop: int, budget: float) -> bool:
    """Does any line of ``data[start:stop]`` match? ``start`` is the start of a line and ``stop`` the end of one (an LF or the end of the
    data), so ``^``, ``$`` and the word-boundary look-arounds see exactly what a whole-buffer search sees. All its lines are short."""
    try:
        with rx.time_limit(budget):
            return compiled.search(data, start, stop) is not None
    except rx.RegexTimeout:
        if not rx.dfa_available(compiled):
            raise
        return rx.dfa_search(compiled, data[start:stop + 1])


def _routed(data: bytes, limit: int, short_lines, long_line) -> bool:
    """Send the over-long lines of ``data`` to ``long_line(start, stop)`` (the linear matcher) and every run of ordinary lines between them
    to ``short_lines(start, stop)`` (``re``): True at the first call that says True. ``[start, stop]`` is a run of whole lines, ``stop`` the
    position of the LF that ends the last one (or the end of the data); a run of zero lines is never passed. The answer equals the one of
    the linear matcher over the whole buffer (the unit test compares them on random buffers); only the cost differs."""
    end = len(data) - 1 if data.endswith(b"\n") else len(data)     # one trailing LF ends a line, it does not start another
    pos = 0
    for start, stop in _long_lines(data, end, limit):
        if pos < start and short_lines(pos, start - 1):
            return True
        if long_line(start, stop):
            return True
        pos = stop + 1
    return pos <= end and short_lines(pos, end)


def _long_lines(data: bytes, end: int, limit: int) -> Iterator[tuple[int, int]]:
    """``(start, stop)`` of every line of ``data[:end]`` longer than ``limit`` bytes (``stop`` is the LF that ends it, or ``end``), in order.
    The aligned-block idea of ``FileView.has_long_line``: with ``h = (limit + 1) // 2`` a run of ``limit + 1`` bytes without an LF contains one
    whole block ``[k*h, (k+1)*h)``, so only a block with no LF can be inside a long line; ``count`` and ``find`` run at C speed and no list of
    lines is ever built."""
    h = max(1, (limit + 1) // 2)
    block = 0
    while block + h <= end:
        if data.count(b"\n", block, block + h):
            block += h
            continue
        start = data.rfind(b"\n", 0, block) + 1
        stop = data.find(b"\n", block + h, end)
        if stop < 0:
            stop = end
        if stop - start > limit:
            yield start, stop
        block = -(-(stop + 1) // h) * h                # the first block at or after the start of the next line
