"""The run state: the verdict, per-file status and messages, counters, the findings stream, the allowlist and threshold,
and the coverage block. Everything bash keeps in globals.

Owner of: contract 6.1 (the three states, first-writer status, event counters), 6.2 (``record_fail`` step by step),
7 (coverage storage, validation and the ``partial`` composition), S13 (an allowlist only lowers, visibly), the
D-028 abort path (``abort``).

Layering: depends on ``transit.console`` and ``transit.findings`` only (the threshold and the allowlist arrive as arguments). No file system, no
processes.

WHO MAY MUTATE (the rule that replaces "global variables"):
  * ``pipeline.main`` constructs exactly one ``Verdict`` and passes it to ``layers.RunEnv``.
  * ``layers`` (whole-directory tools, the per-file loop) may call every method.
  * A scanner never sees a ``Verdict``. It receives a ``ScanContext`` (transit.scanners) whose ``record_*`` methods
    forward to this class for the file being scanned. A lint forbids ``import transit.verdict`` in every module under
    ``transit/scanners/`` and ``transit/rules/`` EXCEPT ``transit/scanners/__init__.py``, which defines ``ScanContext`` and
    therefore has to name the type (review log R-11).
  * ``pipeline.main`` constructs the ``Verdict`` immediately after the report directories exist (before the temporary area, the
    allowlist, the exclusions and the diff selection are loaded), with an EMPTY allowlist that ``set_allowlist`` replaces once, so
    that an exception at any later step has a ``Verdict`` to ``abort`` (review log R-05).
  * ``report`` reads ``snapshot()``, an immutable copy, and never the live object.
Nothing outside this class holds a reference to its dictionaries; every accessor returns a copy or a read-only view.
"""
from __future__ import annotations

import dataclasses
import enum
from typing import Mapping

from transit.console import Console
from transit.findings import Allowlist, FindingRecord

GLOBAL_FILE = "__global__"


class Outcome(enum.Enum):
    """What ``record_fail`` actually did. A scanner's ``fired`` flag (bash ``failed=true``) is set whatever this is: a rule
    that fired but was allowlisted still means "do not record_pass" (golden ``allowlisted``, ``minsev_critical``)."""
    FAILED = "failed"        # a FAIL record exists, the verdict is FAIL
    ALLOWED = "allowed"      # downgraded to the WARN ``ALLOWED:<msg> (reason: <reason>)``
    LOW_SEV = "low_sev"      # downgraded to the WARN ``LOW_SEV(below --min-severity <v>):<msg>``


@dataclasses.dataclass(frozen=True)
class Counters:
    """Event counters (contract 6.1, A13/D-013): not file counts. ``pass_`` counts ``record_pass`` calls (even when the file
    already has a WARN or FAIL), ``warn`` counts ``record_warn`` calls, ``fail`` counts surviving FAILs."""
    pass_: int
    warn: int
    fail: int


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """Immutable end state handed to ``report``. All paths are the recorded strings (``scan_dir/rel``, ``scan_dir``,
    ``__global__``). ``file_message`` is the bash accumulation (``"[WARN] a | [FAIL] b | "``) BEFORE the final strip;
    ``report`` applies the D-009 rule. ``findings`` are in the order recorded."""
    verdict: str                                  # "PASS" | "FAIL"
    counters: Counters
    file_status: Mapping[str, str]                # path -> PASS | WARN | FAIL
    file_message: Mapping[str, str]
    fail_messages: Mapping[str, str]              # path -> "msg | msg | " (bash FINDINGS)
    findings: tuple[FindingRecord, ...]
    coverage: Mapping[str, str]                   # layer id -> ran | skipped:<r> | partial:<r>   (incomplete reasons folded in)


class Verdict:
    """The one mutable run-state object. Single-threaded by design."""

    def __init__(self, scan_dir: str, allowlist: Allowlist, *, threshold: int, min_severity: str,
                 console: Console, first_writer: bool = True, dot_matches_directory: bool = False) -> None:
        """``allowlist``: ``pipeline`` passes the EMPTY one (``Allowlist({})``) and installs the parsed one with ``set_allowlist`` (the Verdict has
        to exist before the allowlist is read, so that an exception while reading it still has a Verdict to ``abort``; review log R-05).
        ``scan_dir``: the directory string as given (used for ``rel_path`` and the record ``file`` field).
        ``threshold``/``min_severity``: ``Config.sev_threshold`` and the text printed in ``LOW_SEV(...)`` messages.
        ``first_writer=False`` is the D-012 switch (status = worst event instead of first writer).
        ``dot_matches_directory=True`` is the D-011 switch: for a whole-directory finding (``file == scan_dir``) the allowlist is
        ALSO tried with ``rel_path == "."``."""
        raise NotImplementedError

    def set_allowlist(self, allowlist: Allowlist) -> None:
        """Install the allowlist parsed from ``.transit-allow.json``. Legal exactly once, before the first event (``events == 0``);
        a later call raises ``RuntimeError`` (S13: an allowlist is loaded before anything is judged and is never swapped while
        findings are being decided). Before this call the allowlist is the empty one given to ``__init__``."""
        raise NotImplementedError

    # -- reads ------------------------------------------------------------------------------------------------
    @property
    def verdict(self) -> str:
        """``"PASS"`` until the first surviving FAIL, then ``"FAIL"`` forever (contract 6.1)."""
        raise NotImplementedError

    @property
    def counters(self) -> Counters:
        raise NotImplementedError

    @property
    def events(self) -> int:
        """Total number of ``record_*`` calls so far. ``scanners.invoke`` compares it before and after a scanner to detect
        a scanner that handled a file without recording any outcome (a bug, turned into a FAIL)."""
        raise NotImplementedError

    def status_of(self, file: str) -> "str | None":
        """The file's status, or None if it has none yet."""
        raise NotImplementedError

    def coverage_state(self, layer_id: str) -> "str | None":
        """The base state recorded for ``layer_id`` (before ``partial`` folding), or None."""
        raise NotImplementedError

    # -- writes: events ---------------------------------------------------------------------------------------
    def record_pass(self, file: "str | None" = None) -> None:
        """Bash ``record_pass``: counter +1 ALWAYS; the file gets status PASS and an empty message only if it has no status
        yet. ``None`` or ``""`` touches no file."""
        raise NotImplementedError

    def record_warn(self, file: "str | None", message: str) -> None:
        """Bash ``record_warn``: counter +1; mirrored on stderr (message only); status WARN only if the file has none;
        appends ``[WARN] <message> | ``. ``None`` or ``""`` means ``__global__``."""
        raise NotImplementedError

    def record_warn_once(self, key: str, file: "str | None", message: str) -> bool:
        """``record_warn(file, message)`` the first time ``key`` is seen in this run, nothing afterwards. Returns True if it recorded.
        ``key`` is engine-generated (``tool_not_ported:bandit``), never repository text. This is the run-scoped state behind
        ``ScanContext.file_tool``'s "once per run" WARN: a ``ScanContext`` lives for one file, so the memory has to be here, in
        the one mutable object, and not in a module global (which would leak between two ``pipeline.main`` calls in one process;
        review log R-22)."""
        raise NotImplementedError

    def record_fail(self, file: str, message: str, *, severity: "str | None" = None,
                    downgradable: bool = True) -> Outcome:
        """Contract 6.2, in this order:
          1. ``rel_path = relative_to_scan_dir(file)``.
          2. Allowlist (skipped when ``downgradable`` is False or the message starts ``engine:``): first non-empty reason ->
             ``record_warn(file, "ALLOWED:<message> (reason: <reason>)")``, return ``ALLOWED``.
          3. Threshold (skipped likewise): ``classify_severity(message)`` (or ``severity`` if the producer gave one) below
             ``threshold`` -> ``record_warn(file, "LOW_SEV(below --min-severity <min_severity>):<message>")``, ``LOW_SEV``.
          4. Otherwise: append ``build_record`` to the findings stream, status FAIL (unconditionally), append
             ``[FAIL] <message> | `` and the bare ``<message> | `` to the per-file FAIL text, fail counter +1, mirror
             ``[<file>] <message>`` on stderr, verdict FAIL, return ``FAILED``.
        ``downgradable=False`` is for ``engine:`` records and any producer whose failure must not be configurable by the
        repository."""
        raise NotImplementedError

    # -- writes: coverage -------------------------------------------------------------------------------------
    def record_layer(self, layer_id: str, state: str, *, overwrite: bool = True) -> None:
        """Set the base state of a layer. ``layer_id`` must be in ``config.COVERAGE_LAYERS`` and ``state`` must match
        ``ran | skipped:<non-empty> | partial:<non-empty>`` or ``ValueError`` is raised (a mistyped id must not create a
        tenth layer). ``overwrite=False`` keeps an earlier state (bash ``[[ -z ${LAYER_COVERAGE[x]} ]] && record_layer``)."""
        raise NotImplementedError

    def note_incomplete(self, layer_id: str, reason: str) -> None:
        """Say that part of ``layer_id`` did not run (an unported tool or scanner, a time budget, an unreadable directory).
        ``snapshot()`` turns base state ``ran`` into ``partial:<reasons>`` (reasons de-duplicated, sorted, joined with
        ``"; "``, at most 300 characters); a ``skipped:`` state is left as it is. ``reason`` is engine-generated text, never
        repository text (names go in the WARN, not here)."""
        raise NotImplementedError

    # -- end of run -------------------------------------------------------------------------------------------
    def abort(self, reason: str) -> None:
        """D-028. Callable at any moment after construction (the Verdict exists before the first step that can fail, so this is
        never "too early"). Called by the top-level handler after an internal error: records the FAIL ``engine:internal_error:<reason>``
        on ``__global__`` (not downgradable) and gives every REQUIRED layer that has no state the state
        ``skipped:engine aborted (<reason>)``, so the report still validates and cannot read as a clean run."""
        raise NotImplementedError

    def snapshot(self) -> Snapshot:
        """Freeze the state for ``report``. Folds ``note_incomplete`` reasons into the coverage states. Idempotent."""
        raise NotImplementedError
