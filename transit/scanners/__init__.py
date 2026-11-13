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
from typing import Callable, Iterator, Mapping, Sequence

from transit.config import Config
from transit.console import Console
from transit.files import FileView, TempArea
from transit.rules import Cond, Matcher, RuleSet, SearchPolicy, Target
from transit.tools import Record, ToolLocator, WrapperSet
from transit.verdict import Outcome, Verdict

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
        raise NotImplementedError

    def unported(self) -> tuple[str, ...]:
        """Sorted ids of ``KNOWN_SCANNERS`` that have no spec or whose spec has ``ported=False``. Must be empty before the
        Python engine becomes the default (a Phase 6 gate)."""
        raise NotImplementedError


def load_registry(module_names: "Sequence[str] | None" = None) -> Registry:
    """Discover the scanner modules (``pkgutil.iter_modules`` over this package, minus ``SCRIPT_MODULES`` and ``_*``; or exactly
    ``module_names`` for tests), import each and collect ``SCANNERS``. See the module docstring for what is a load error."""
    raise NotImplementedError


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
        raise NotImplementedError

    # -- identity ---------------------------------------------------------------------------------------------
    @property
    def path(self) -> str:
        """The recorded path ``scan_dir/rel``: the key in ``file_results`` and the first argument of every ``record_*``."""
        raise NotImplementedError

    @property
    def rel(self) -> str:
        raise NotImplementedError

    @property
    def basename(self) -> str:
        raise NotImplementedError

    @property
    def ext(self) -> str:
        """Lower-cased extension without the dot (``FileView.ext``)."""
        raise NotImplementedError

    @property
    def sniffed(self) -> bool:
        """True when dispatch chose this scanner by looking at the content, not at the name (see the module docstring)."""
        raise NotImplementedError

    @property
    def view(self) -> FileView:
        raise NotImplementedError

    @property
    def cfg(self) -> Config:
        raise NotImplementedError

    @property
    def temp(self) -> TempArea:
        """The run's private temporary area (S16), for scanners that need a view file for a helper program."""
        raise NotImplementedError

    # -- recording --------------------------------------------------------------------------------------------
    def record_pass(self) -> None:
        raise NotImplementedError

    def record_warn(self, message: str, *, file: "str | None" = None) -> None:
        """WARN against ``file`` (default: this file). ``message`` is the exact contract-5 text."""
        raise NotImplementedError

    def record_fail(self, message: str, *, file: "str | None" = None, severity: "str | None" = None,
                    downgradable: bool = True) -> Outcome:
        """FAIL against ``file`` (default: this file); see ``Verdict.record_fail`` (allowlist, threshold, mirroring)."""
        raise NotImplementedError

    def note_incomplete(self, reason: str, *, layer: str = "L5_per_language_sast") -> None:
        """Say part of the work was not done (``Verdict.note_incomplete``). ``reason`` is engine text, never repository text."""
        raise NotImplementedError

    def finish(self, fired: bool) -> None:
        """The last line of nearly every bash scanner, ``$failed || record_pass "$f"``: ``record_pass`` unless ``fired``."""
        raise NotImplementedError

    # -- matching ---------------------------------------------------------------------------------------------
    def run_rules(self, ruleset: RuleSet, *, data: "bytes | None" = None) -> RuleOutcome:
        """Evaluate ``ruleset`` against this file (or against ``data``, a derived view such as a decoded text) with the run's
        ``SearchPolicy`` and the file deadline, then record each hit in table order: a ``fail`` rule through ``record_fail``
        (message from the row, severity from the row), a ``warn`` rule through ``record_warn``. A rule skipped for time becomes the
        non-downgradable FAIL ``engine:scan_incomplete:<ruleset name>:time_budget`` (once per call) and a ``partial`` note: a file
        whose rules were not all evaluated must not read as clean, and a hostile file must not be able to buy a WARN by burning the
        budget (review log R-02). A rule that timed out with no linear matcher becomes the non-downgradable FAIL
        ``engine:regex_timeout:<rule id>``."""
        raise NotImplementedError

    def search(self, cond: Cond, *, data: "bytes | None" = None) -> bool:
        """``rules.evaluate`` with the run's policy, for scanners whose logic is not one table row. ``cond`` must be built at module level
        from ``Match`` objects registered by a ``RuleSet`` or a ``Matcher`` (``ValueError`` otherwise: an unregistered pattern would be
        invisible to the fuzz gate). Raises ``ScanBudgetExceeded`` when the file deadline has passed."""
        raise NotImplementedError

    def spans(self, matcher: Matcher, *, data: "bytes | None" = None) -> Iterator[tuple[int, int]]:
        """``matcher.spans`` with the run's policy over this file (or over ``data``, a derived view): the ``(start, end)`` offsets of the
        matching lines, lazily. Calls ``check_deadline`` before each item, so a file with a very large number of matching lines
        cannot outlast the per-file deadline. For code that needs positions (the private-key windows, the credential-format lines); a
        table row never needs it."""
        raise NotImplementedError

    def target(self, data: "bytes | None" = None) -> Target:
        """``FileView.target`` (for ``credentials`` and other helpers that take a ``Target``)."""
        raise NotImplementedError

    def check_deadline(self) -> None:
        """Raise ``rules.ScanBudgetExceeded`` if the per-file deadline has passed. Long loops in a scanner call it."""
        raise NotImplementedError

    # -- tools and other scanners ----------------------------------------------------------------------------------
    def file_tool(self, name: str) -> FileToolRun:
        """Run the per-file external tool ``name`` (a key of ``tools.FILE_TOOLS``; ``KeyError`` otherwise) on this file. Decision, in this order: ``ToolLocator.find(FILE_TOOLS[name])`` is None ->
        ``missing``; no wrapper -> ``not_ported`` (and once per run the WARN ``engine:tool_not_ported:<name>`` on ``__global__``, recorded with
        ``Verdict.record_warn_once("tool_not_ported:<name>", ...)`` because a ``ScanContext`` lives for one file and the memory has to be in the
        run's one mutable object; and ``note_incomplete`` with ``python engine has not ported <name> yet``); otherwise ``wrapper.run`` and
        ``ok`` / ``failed``. The scanner applies the result with ``apply_tool_records``. A wrapper that raises is NOT a ``failed`` run: the
        exception propagates to ``invoke`` and becomes the FAIL ``engine:scanner_error:<id>:<class>``."""
        raise NotImplementedError

    def apply_tool_records(self, run: FileToolRun) -> bool:
        """Record the ``records`` of a ``FileToolRun``, in order: ``warn`` through ``record_warn`` and ``fail`` through ``record_fail`` (with the
        record's ``severity``), against ``record.file`` or, when that is empty, this file. Returns True if some ``fail`` record was
        applied, WHETHER OR NOT the allowlist or the threshold turned it into a WARN (bash ``failed=true``; ``finish`` needs it). A run with
        status ``missing`` or ``not_ported`` has no records and returns False. A ``pass`` record from a per-file wrapper is a bug in the
        wrapper (``finish`` owns the file's PASS) and raises ``ValueError``. Every scanner calls this instead of looping over ``run.records``
        itself, so the WARN a ``failed`` wrapper returns to explain why the tool was unusable is never dropped (review log R-24)."""
        raise NotImplementedError

    def delegate(self, scanner_id: str, *, sniffed: bool = False) -> bool:
        """Run another scanner on the same file through ``invoke`` (``scan_unknown`` routing by shebang, ``docs`` handing an RTF
        to ``rtf``). Returns what ``invoke`` returns. Depth is limited to 3; a deeper call raises ``RuntimeError``."""
        raise NotImplementedError


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
    raise NotImplementedError


def guard(label: str, fn: ScannerFn, ctx: ScanContext, *, requires_outcome: bool = True) -> bool:
    """``invoke`` for a function that is not in the registry (the universal layer, label ``universal``). Same steps 2 to 4;
    ``requires_outcome=False`` skips the "no event recorded" check, because the universal layer legitimately records nothing
    for a clean file (bash: "do not set PASS here - handled by the per-type scanner")."""
    raise NotImplementedError
