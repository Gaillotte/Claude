"""Scanner registry, the ``ScanContext`` every scanner receives, and the guard that turns a scanner's failure into a recorded one.

Owner of: contract 8.8 rule 5 (every scanner records an outcome), S9 for scanners (a scanner that could not run is visible),
contract 11 / D-028 for scanners (an error inside a scanner is a FAIL for that file, not an abort), the policy for a scanner
that is not written yet.

Layering: depends on ``transit.config``, ``console``, ``files``, ``findings``, ``rules``, ``tools`` and ``verdict``. It does NOT
import ``transit.layers``, ``transit.dispatch`` or any scanner module at import time (``load_registry`` imports the scanner
modules on request), so importing this package has no side effects and no cycle. This file is the ONE module under
``transit/scanners/`` and ``transit/rules/`` that may import ``verdict`` and ``console`` (it defines ``ScanContext``, whose constructor
names both types); every other module there is linted against them (review log R-11).

WHAT ``invoke`` AND ``guard`` CATCH. ``Exception`` and ``SystemExit``. A ``SystemExit`` raised inside a scanner (a library that calls
``sys.exit``, an ``argparse`` error, the import of a helper program that exits) is a failure of THAT FILE's scan: it becomes the
non-downgradable FAIL ``engine:scanner_error:<id>:SystemExit`` and the run goes on; it must never travel up to ``pipeline.main`` and
end the process with status 0, which every status-only caller reads as PASS (review log R-06). Nothing else is caught: the signal
exception of ``pipeline`` (a private ``BaseException``), ``KeyboardInterrupt`` and ``GeneratorExit`` propagate.

THE REGISTRY. There are 34 scanner FAMILIES (``build_pdf_filetypes.FAMILIES``) and 37 scanner IDS: a family has one id (its
key) except ``manifest`` (``manifest.package_json``, ``manifest.requirements``) and ``powershell`` (``powershell.text``,
``powershell.xml``), plus the pseudo id ``unknown`` (``scan_unknown``). ``KNOWN_SCANNERS`` below is FIXED: a package may not
add an id. A scanner module declares ``SCANNERS: tuple[ScannerSpec, ...]`` at module level and the registry finds it; no
shared file lists the modules. ``load_registry`` skips ``manifests`` (a bash-engine helper PROGRAM that cannot be imported)
and every name starting with ``_``; a module without ``SCANNERS`` is ignored (a shared helper); a module that fails to import
or declares an unknown id, a duplicate id or a family that does not match ``KNOWN_SCANNERS`` becomes a LOAD ERROR (never
fatal: the ids it would have served are reported as not ported).

WHAT A SCANNER RECEIVES AND RETURNS. ``fn(ctx: ScanContext) -> bool``. It reads the file through ``ctx``, records through
``ctx.record_*`` and returns True ("handled: I recorded this file's outcome, PASS included"). It returns False ("not mine")
only when ``ctx.sniffed`` is True - the office scanner answering a ``.md``/``.txt``/``.rst``/extensionless file that is not
really an RTF, or the Flat-OPC probe of a ``.xml`` (contract 8.8). Every scanner records AT LEAST ONE event
(``record_pass`` unless a rule fired, or a WARN, as ``scan_jar`` does). It must not catch ``Exception`` to hide a problem: let
it propagate and ``invoke`` records the FAIL.
"""
from __future__ import annotations

import dataclasses
import importlib
import pkgutil
import time
import types
from typing import Callable, Iterator, Mapping, Sequence

from transit import rules as _rules
from transit import rx
from transit.config import Config
from transit.console import Console
from transit.files import FileReadError, FileView, TempArea
from transit.rules import Cond, Matcher, RuleSet, ScanBudgetExceeded, SearchPolicy, Target
from transit.tools import FILE_TOOLS, Record, ToolLocator, ToolRequest, WrapperSet
from transit.verdict import GLOBAL_FILE, Outcome, Verdict

#: scanner id -> family key (``build_pdf_filetypes.FAMILIES[*]['key']``). Fixed.
KNOWN_SCANNERS: Mapping[str, str] = {
    "python": "python", "setuppy": "setuppy", "js": "js", "java": "java", "php": "php", "ruby": "ruby", "go": "go",
    "c": "c", "rust": "rust", "kotlin": "kotlin", "csharp": "csharp", "shell": "shell",
    "powershell.text": "powershell", "powershell.xml": "powershell", "batch": "batch", "makefile": "makefile",
    "cmake": "cmake", "gradle": "gradle", "manifest.package_json": "manifest", "manifest.requirements": "manifest",
    "xml": "xml", "yaml": "yaml", "terraform": "terraform", "docker": "docker", "html": "html", "pdf": "pdf",
    "ooxml": "ooxml", "legacy_office": "legacy_office", "odf": "odf", "rtf": "rtf", "sql": "sql", "json": "json",
    "docs": "docs", "binary": "binary", "archive": "archive", "jar": "jar",
    "unknown": "unknown",
}
#: The pseudo family of ``unknown``; it is not one of the 34.
PSEUDO_FAMILIES = frozenset({"unknown"})
#: Bash-engine helper programs that live in this package and must never be imported.
SCRIPT_MODULES = frozenset({"manifests"})

ScannerFn = Callable[["ScanContext"], bool]

#: ``ScanContext.delegate`` may be nested this deep (``scan_unknown`` -> a language scanner; ``docs`` -> ``rtf``): a deeper call is a bug.
_MAX_DELEGATION_DEPTH = 3
#: The coverage reason of a file whose rules were not all evaluated before its deadline (``partial:per-file time budget reached``).
_BUDGET_NOTE = "per-file time budget reached"
_PER_FILE_LAYER = "L5_per_language_sast"
#: The words a message of the engine may be built from: an engine-generated word, never repository text (a class name, a reason word, a label).
_CLASS_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_LABEL_CHARS = _CLASS_CHARS | frozenset(".-")


def _word(text: object, allowed: "frozenset[str]" = _CLASS_CHARS, limit: int = 60) -> str:
    """``text`` cut to ``limit`` characters with every character outside ``allowed`` replaced by ``_``: for the class name of an exception
    (which a library, not the repository, chooses, but which is still printed into a report) and for a scanner label."""
    cleaned = "".join(ch if ch in allowed else "_" for ch in str(text)[:limit])
    return cleaned or "unknown"


def _reason_word(reason: object) -> str:
    """``FileReadError.reason`` (``permission``, ``too_large``, ``io``, ``vanished``): kept only if it looks like one of those, else ``unknown``."""
    text = reason if isinstance(reason, str) else ""
    if 0 < len(text) <= 24 and text.isascii() and text.islower() and text.replace("_", "").isalpha():
        return text
    return "unknown"


@dataclasses.dataclass(frozen=True)
class ScannerSpec:
    """A registered scanner. ``id``/``family`` must agree with ``KNOWN_SCANNERS``. ``bash_function`` documents the origin
    (``scan_python``). ``tools``: wrapper keys (``tools.FILE_TOOLS``) the scanner asks ``ctx.file_tool`` for (``("bandit",)``, ``("semgrep-js",)``). ``ported`` is False in
    a stub and True when the scanner is complete; a spec with ``ported=False`` is reported as not ported."""
    id: str
    family: str
    fn: ScannerFn
    bash_function: str
    tools: tuple[str, ...] = ()
    ported: bool = False


@dataclasses.dataclass(frozen=True)
class Registry:
    """All specs found, and the load errors (module name + exception class name only)."""
    specs: Mapping[str, ScannerSpec]
    load_errors: tuple[str, ...] = ()

    def get(self, scanner_id: str) -> "ScannerSpec | None":
        return self.specs.get(scanner_id)

    def unported(self) -> tuple[str, ...]:
        """Sorted ids of ``KNOWN_SCANNERS`` that have no spec or whose spec has ``ported=False``. Must be empty before the
        Python engine becomes the default (a Phase 6 gate)."""
        return tuple(sorted(i for i in KNOWN_SCANNERS if i not in self.specs or not self.specs[i].ported))


def load_registry(module_names: "Sequence[str] | None" = None) -> Registry:
    """Discover the scanner modules (``pkgutil.iter_modules`` over this package, minus ``SCRIPT_MODULES`` and ``_*``; or exactly
    ``module_names`` for tests), import each and collect ``SCANNERS``. See the module docstring for what is a load error."""
    if module_names is None:
        names = sorted(info.name for info in pkgutil.iter_modules(__path__))
    else:
        names = list(module_names)
    specs: "dict[str, ScannerSpec]" = {}
    errors: "list[str]" = []
    for name in names:
        short = name.rpartition(".")[2]
        if short in SCRIPT_MODULES or short.startswith("_"):
            continue                                       # a helper PROGRAM (importing it exits or reads sys.argv), or private
        full = name if "." in name else __name__ + "." + name
        try:
            module = importlib.import_module(full)
        except (Exception, SystemExit) as exc:             # a module that cannot be imported costs its own ids, never the run
            errors.append("%s:%s" % (_word(short, _LABEL_CHARS), _word(type(exc).__name__)))
            continue
        if not hasattr(module, "SCANNERS"):
            continue                                       # a shared helper
        problem, accepted = _check_declared(getattr(module, "SCANNERS"), specs)
        if problem:
            errors.append("%s:%s" % (_word(short, _LABEL_CHARS), problem))
            continue
        for entry in accepted:
            specs[entry.id] = entry
    return Registry(specs=types.MappingProxyType(dict(sorted(specs.items()))), load_errors=tuple(errors))


def _check_declared(declared: object, known: "Mapping[str, ScannerSpec]") -> "tuple[str, tuple[ScannerSpec, ...]]":
    """``("", specs)`` for a module whose ``SCANNERS`` is acceptable, else ``(<problem word>, ())``: the whole module is refused, so that the
    ids it would have served are reported as not ported and nothing half-registered is left behind."""
    if not isinstance(declared, tuple) or not all(isinstance(e, ScannerSpec) and isinstance(e.id, str) and callable(e.fn) for e in declared):
        return "invalid_SCANNERS", ()
    seen: "set[str]" = set()
    for entry in declared:
        if entry.id not in KNOWN_SCANNERS:
            return "unknown_scanner_id", ()
        if KNOWN_SCANNERS[entry.id] != entry.family:
            return "family_mismatch", ()
        if entry.id in seen or entry.id in known:
            return "duplicate_scanner_id", ()
        seen.add(entry.id)
    return "", declared


@dataclasses.dataclass(frozen=True)
class RuleOutcome:
    """Result of ``ScanContext.run_rules``. ``fired``: some ``fail`` rule matched, WHETHER OR NOT the allowlist or the
    threshold turned it into a WARN (bash sets ``failed=true`` after ``record_fail`` regardless; ``finish`` needs this).
    ``outcomes``: (rule id, Outcome) for every ``fail`` rule that matched. ``incomplete``: some rules were not evaluated (time)."""
    fired: bool
    outcomes: tuple[tuple[str, Outcome], ...]
    incomplete: bool


@dataclasses.dataclass(frozen=True)
class FileToolRun:
    """Answer of ``ScanContext.file_tool``. ``status``: ``missing`` (not installed: the scanner writes its own
    ``<tool> missing`` WARN, contract 5.1), ``not_ported`` (installed, no wrapper: already noted as incomplete and warned
    once), ``ok`` (``records`` hold the findings in bash order), ``failed`` (started but unusable: ``records`` hold the WARN or
    FAIL the wrapper chose, and the layer is noted incomplete)."""
    status: str
    records: tuple[Record, ...] = ()


class ScanContext:
    """Everything one scanner may touch for one file. Built by ``layers.run_file_layers`` (one per file and handler); a
    scanner never builds one and never sees a ``Verdict``, ``Console`` or ``files.TempArea`` directly."""

    def __init__(self, *, view: FileView, verdict: Verdict, cfg: Config, console: Console, tools: ToolLocator,
                 wrappers: WrapperSet, registry: Registry, policy: SearchPolicy, temp: TempArea, scan_dir: str,
                 deadline: float, sniffed: bool = False, depth: int = 0) -> None:
        self._view = view
        self._verdict = verdict
        self._cfg = cfg
        self._console = console
        self._tools = tools
        self._wrappers = wrappers
        self._registry = registry
        self._policy = policy
        self._temp = temp
        self._scan_dir = scan_dir
        self._deadline = deadline
        self._sniffed = sniffed
        self._depth = depth

    # -- identity ---------------------------------------------------------------------------------------------
    @property
    def path(self) -> str:
        """The recorded path ``scan_dir/rel``: the key in ``file_results`` and the first argument of every ``record_*``."""
        return self._view.path

    @property
    def rel(self) -> str:
        return self._view.rel

    @property
    def basename(self) -> str:
        return self._view.basename

    @property
    def ext(self) -> str:
        """Lower-cased extension without the dot (``FileView.ext``)."""
        return self._view.ext

    @property
    def sniffed(self) -> bool:
        """True when dispatch chose this scanner by looking at the content, not at the name (see the module docstring)."""
        return self._sniffed

    @property
    def view(self) -> FileView:
        return self._view

    @property
    def cfg(self) -> Config:
        return self._cfg

    @property
    def temp(self) -> TempArea:
        """The run's private temporary area (S16), for scanners that need a view file for a helper program."""
        return self._temp

    # -- recording --------------------------------------------------------------------------------------------
    def record_pass(self) -> None:
        self._verdict.record_pass(self.path)

    def record_warn(self, message: str, *, file: "str | None" = None) -> None:
        """WARN against ``file`` (default: this file). ``message`` is the exact contract-5 text."""
        self._verdict.record_warn(self.path if file is None else file, message)

    def record_fail(self, message: str, *, file: "str | None" = None, severity: "str | None" = None,
                    downgradable: bool = True) -> Outcome:
        """FAIL against ``file`` (default: this file); see ``Verdict.record_fail`` (allowlist, threshold, mirroring)."""
        return self._verdict.record_fail(self.path if file is None else file, message, severity=severity, downgradable=downgradable)

    def note_incomplete(self, reason: str, *, layer: str = "L5_per_language_sast") -> None:
        """Say part of the work was not done (``Verdict.note_incomplete``). ``reason`` is engine text, never repository text."""
        self._verdict.note_incomplete(layer, reason)

    def finish(self, fired: bool) -> None:
        """The last line of nearly every bash scanner, ``$failed || record_pass "$f"``: ``record_pass`` unless ``fired``."""
        if not fired:
            self.record_pass()

    # -- matching ---------------------------------------------------------------------------------------------
    def run_rules(self, ruleset: RuleSet, *, data: "bytes | None" = None) -> RuleOutcome:
        """Evaluate ``ruleset`` against this file (or against ``data``, a derived view such as a decoded text) with the run's
        ``SearchPolicy`` and the file deadline, then record each hit in table order: a ``fail`` rule through ``record_fail``
        (message from the row, severity from the row), a ``warn`` rule through ``record_warn``. A rule skipped for time becomes the
        non-downgradable FAIL ``engine:scan_incomplete:<ruleset name>:time_budget`` (once per call) and a ``partial`` note: a file
        whose rules were not all evaluated must not read as clean, and a hostile file must not be able to buy a WARN by burning the
        budget (review log R-02). A rule that timed out with no linear matcher becomes the non-downgradable FAIL
        ``engine:regex_timeout:<rule id>``."""
        target = self._view.target(data)
        run = _rules.run_ruleset(ruleset, target, self._policy, deadline=self._deadline)
        fired = False
        outcomes: "list[tuple[str, Outcome]]" = []
        for rule in run.hits:                              # table order, which is the bash order
            if rule.outcome == "fail":
                fired = True                               # bash ``failed=true``: whatever record_fail did with it
                outcomes.append((rule.id, self.record_fail(rule.message, severity=rule.severity)))
            else:
                self.record_warn(rule.message)
        for rule_id in run.timed_out:                      # no linear matcher and `re` ran out of time: never read as "no match"
            self.record_fail("engine:regex_timeout:" + rule_id, downgradable=False)
        if run.skipped:                                    # the deadline passed: a file whose rules were not all evaluated is not clean
            self.record_fail("engine:scan_incomplete:%s:time_budget" % ruleset.name, downgradable=False)
            self.note_incomplete(_BUDGET_NOTE)
        return RuleOutcome(fired=fired, outcomes=tuple(outcomes), incomplete=bool(run.skipped or run.timed_out))

    def search(self, cond: Cond, *, data: "bytes | None" = None) -> bool:
        """``rules.evaluate`` with the run's policy, for scanners whose logic is not one table row. ``cond`` must be built at module level
        from ``Match`` objects registered by a ``RuleSet`` or a ``Matcher`` (``ValueError`` otherwise: an unregistered pattern would be
        invisible to the fuzz gate). Raises ``ScanBudgetExceeded`` when the file deadline has passed."""
        self.check_deadline()
        return _rules.evaluate(cond, self._view.target(data), self._policy)

    def spans(self, matcher: Matcher, *, data: "bytes | None" = None) -> Iterator[tuple[int, int]]:
        """``matcher.spans`` with the run's policy over this file (or over ``data``, a derived view): the ``(start, end)`` offsets of the
        matching lines, lazily. Calls ``check_deadline`` before each item, so a file with a very large number of matching lines
        cannot outlast the per-file deadline. For code that needs positions (the private-key windows, the credential-format lines); a
        table row never needs it."""
        # The call validates (a flat Matcher is a ValueError here, not at the first next()); the generator below only walks.
        walk = matcher.spans(self._view.target(data), self._policy)
        return self._checked(walk)

    def _checked(self, walk: "Iterator[tuple[int, int]]") -> "Iterator[tuple[int, int]]":
        for item in walk:
            self.check_deadline()
            yield item

    def target(self, data: "bytes | None" = None) -> Target:
        """``FileView.target`` (for ``credentials`` and other helpers that take a ``Target``)."""
        return self._view.target(data)

    def check_deadline(self) -> None:
        """Raise ``rules.ScanBudgetExceeded`` if the per-file deadline has passed. Long loops in a scanner call it."""
        if time.monotonic() >= self._deadline:
            raise ScanBudgetExceeded()

    # -- tools and other scanners ----------------------------------------------------------------------------------
    def file_tool(self, name: str) -> FileToolRun:
        """Run the per-file external tool ``name`` (a key of ``tools.FILE_TOOLS``; ``KeyError`` otherwise) on this file. Decision, in this order: ``ToolLocator.find(FILE_TOOLS[name])`` is None ->
        ``missing``; no wrapper -> ``not_ported`` (and once per run the WARN ``engine:tool_not_ported:<name>`` on ``__global__``, recorded with
        ``Verdict.record_warn_once("tool_not_ported:<name>", ...)`` because a ``ScanContext`` lives for one file and the memory has to be in the
        run's one mutable object; and ``note_incomplete`` with ``python engine has not ported <name> yet``); otherwise ``wrapper.run`` and
        ``ok`` / ``failed``. The scanner applies the result with ``apply_tool_records``. A wrapper that raises is NOT a ``failed`` run: the
        exception propagates to ``invoke`` and becomes the FAIL ``engine:scanner_error:<id>:<class>``."""
        info = self._tools.find(FILE_TOOLS[name])          # KeyError for a name that is not a per-file tool
        if info is None:
            return FileToolRun("missing")
        wrapper = self._wrappers.get(name)
        if wrapper is None:
            # one WARN per RUN: the memory is the Verdict's, because this context lives for one file (review log R-22)
            self._verdict.record_warn_once("tool_not_ported:" + name, GLOBAL_FILE, "engine:tool_not_ported:" + name)
            self.note_incomplete("python engine has not ported %s yet" % name)
            return FileToolRun("not_ported")
        request = ToolRequest(cfg=self._cfg, scan_dir=self._scan_dir, target=self.path, temp=self._temp, exclude_dirs=(), info=info)
        outcome = wrapper.run(request)                     # an exception is not a "failed" run: it propagates to invoke
        state = outcome.layer_state
        if state in (None, "ran") and not outcome.timed_out:
            return FileToolRun("ok", tuple(outcome.records))
        # started but unusable: ``skipped:<reason>`` / ``partial:<reason>`` (or only the timeout flag); the reason is what L5 is noted with
        reason = state.partition(":")[2] if isinstance(state, str) else ""
        self.note_incomplete(reason or ("%s timed out" % name if outcome.timed_out else "%s did not complete" % name))
        return FileToolRun("failed", tuple(outcome.records))

    def apply_tool_records(self, run: FileToolRun) -> bool:
        """Record the ``records`` of a ``FileToolRun``, in order: ``warn`` through ``record_warn`` and ``fail`` through ``record_fail`` (with the
        record's ``severity``), against ``record.file`` or, when that is empty, this file. Returns True if some ``fail`` record was
        applied, WHETHER OR NOT the allowlist or the threshold turned it into a WARN (bash ``failed=true``; ``finish`` needs it). A run with
        status ``missing`` or ``not_ported`` has no records and returns False. A ``pass`` record from a per-file wrapper is a bug in the
        wrapper (``finish`` owns the file's PASS) and raises ``ValueError``. Every scanner calls this instead of looping over ``run.records``
        itself, so the WARN a ``failed`` wrapper returns to explain why the tool was unusable is never dropped (review log R-24)."""
        for record in run.records:                         # nothing is recorded for a run that has a bad record
            if record.kind not in ("warn", "fail"):
                raise ValueError("a per-file tool wrapper returned a %r record (finish() owns the file's PASS)" % (record.kind,))
        fired = False
        for record in run.records:
            target = record.file or None
            if record.kind == "warn":
                self.record_warn(record.message, file=target)
            else:
                fired = True                               # bash ``failed=true``, whether or not the allowlist or the threshold downgraded it
                self.record_fail(record.message, file=target, severity=record.severity)
        return fired

    def delegate(self, scanner_id: str, *, sniffed: bool = False) -> bool:
        """Run another scanner on the same file through ``invoke`` (``scan_unknown`` routing by shebang, ``docs`` handing an RTF
        to ``rtf``). Returns what ``invoke`` returns. Depth is limited to 3; a deeper call raises ``RuntimeError``."""
        if self._depth >= _MAX_DELEGATION_DEPTH:
            raise RuntimeError("scanner delegation is limited to %d levels" % _MAX_DELEGATION_DEPTH)
        child = ScanContext(view=self._view, verdict=self._verdict, cfg=self._cfg, console=self._console, tools=self._tools,
                            wrappers=self._wrappers, registry=self._registry, policy=self._policy, temp=self._temp, scan_dir=self._scan_dir,
                            deadline=self._deadline, sniffed=sniffed, depth=self._depth + 1)
        return invoke(self._registry, scanner_id, child)

    # -- used by invoke and guard only -------------------------------------------------------------------------------
    def _events(self) -> int:
        return self._verdict.events

    def _engine_fail(self, message: str) -> None:
        """An ``engine:`` FAIL for this file: never allowlisted, never below the threshold."""
        self.record_fail(message, downgradable=False)

    def _show(self, where: str, exc: BaseException) -> None:
        """The traceback goes to stderr only (sanitised by the console). Best effort: the FAIL is already recorded."""
        try:
            self._console.exception(where, exc)
        except Exception:                                  # noqa: BLE001  (a console that fails must not undo the recorded FAIL)
            pass


def invoke(registry: Registry, scanner_id: str, ctx: ScanContext) -> bool:
    """Run one scanner under the guard (contract 11 / D-028 for a single file). Steps:
      1. no spec or ``ported`` False -> WARN ``engine:scanner_not_ported:<id>`` on the file, ``note_incomplete`` with
         ``python engine has not ported scanner <id> yet``, return True (the file is reported, not silently clean);
      2. ``events0 = verdict.events``; call ``spec.fn(ctx)``;
      3. ``ScanBudgetExceeded`` -> FAIL ``engine:scan_incomplete:<id>:time_budget`` + ``partial`` note, handled (review log R-02);
         ``FileReadError`` -> FAIL ``engine:file_unreadable:<reason>``; ``rx.RegexTimeout`` -> FAIL ``engine:regex_timeout``;
         any other ``Exception`` (``NotImplementedError`` included) or ``SystemExit`` -> FAIL ``engine:scanner_error:<id>:<ExceptionClass>``
         and the sanitised traceback on stderr. All these FAILs are non-downgradable. Any other ``BaseException`` (the signal exception,
         Ctrl-C) propagates;
      4. handled but no event recorded since ``events0`` -> FAIL ``engine:scanner_error:<id>:no_outcome``;
         returned False while ``ctx.sniffed`` is False -> the same FAIL with ``:returned_not_mine``.
    Returns the scanner's boolean (False only for a sniffed "not mine")."""
    spec = registry.get(scanner_id)
    label = _word(scanner_id, _LABEL_CHARS)
    if spec is None or not spec.ported:
        ctx.record_warn("engine:scanner_not_ported:" + label)
        ctx.note_incomplete("python engine has not ported scanner %s yet" % label)
        return True                                        # reported, not silently clean; a sniffed RTF is never read as plain text
    return _run_guarded(label, spec.fn, ctx, True)


def guard(label: str, fn: ScannerFn, ctx: ScanContext, *, requires_outcome: bool = True) -> bool:
    """``invoke`` for a function that is not in the registry (the universal layer, label ``universal``). Same steps 2 to 4;
    ``requires_outcome=False`` skips the "no event recorded" check, because the universal layer legitimately records nothing
    for a clean file (bash: "do not set PASS here - handled by the per-type scanner")."""
    return _run_guarded(_word(label, _LABEL_CHARS), fn, ctx, requires_outcome)


def _run_guarded(label: str, fn: ScannerFn, ctx: ScanContext, requires_outcome: bool) -> bool:
    """Steps 2 to 4 of ``invoke``. Catches ``Exception`` and ``SystemExit`` and nothing else: the signal exception of ``pipeline``,
    ``KeyboardInterrupt`` and ``GeneratorExit`` travel up. Every recorded FAIL is an ``engine:`` message (not downgradable) and none of
    them contains repository text: ``label`` is a scanner id, the rest are class names and reason words."""
    events_before = ctx._events()
    try:
        result = fn(ctx)
    except ScanBudgetExceeded:
        ctx._engine_fail("engine:scan_incomplete:%s:time_budget" % label)
        ctx.note_incomplete(_BUDGET_NOTE)
        return True
    except FileReadError as exc:
        ctx._engine_fail("engine:file_unreadable:" + _reason_word(exc.reason))
        return True
    except rx.RegexTimeout:
        ctx._engine_fail("engine:regex_timeout:" + label)
        return True
    except (Exception, SystemExit) as exc:                 # SystemExit: a library or a helper import that exits costs one file, not the run
        ctx._engine_fail("engine:scanner_error:%s:%s" % (label, _word(type(exc).__name__)))
        ctx._show("scanner %s failed" % label, exc)
        return True
    handled = True if result is None else bool(result)    # a function with no return value is judged by what it recorded
    if not handled and not ctx.sniffed:
        ctx._engine_fail("engine:scanner_error:%s:returned_not_mine" % label)
        return True
    if requires_outcome and handled and ctx._events() == events_before:
        ctx._engine_fail("engine:scanner_error:%s:no_outcome" % label)
        return True
    return handled
