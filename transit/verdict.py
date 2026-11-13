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
import types
from typing import Mapping

from transit.console import BIDI_CONTROLS, Console
from transit.findings import (ENGINE_PREFIX, SEVERITY_NUMBER, Allowlist, FindingRecord, build_record,
                              relative_to_scan_dir)

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


#: The nine coverage layer ids (contract 7), copied from ``config.COVERAGE_REQUIRED`` / ``COVERAGE_OPTIONAL`` because this
#: module depends on ``console`` and ``findings`` only; ``tests/engine/test_verdict.py`` asserts the copy equals the original.
_COVERAGE_REQUIRED = ("L1_secrets_gitleaks", "L1_secrets_entropy", "L1_malware", "L2_owasp_cwe", "L3_dependency_cve",
                      "L4_patterns", "L5_per_language_sast")
_COVERAGE_OPTIONAL = ("L1_ioc_yara", "L6_licence")
_COVERAGE_LAYERS = frozenset(_COVERAGE_REQUIRED + _COVERAGE_OPTIONAL)
#: Characters a coverage text may not contain: the schema pattern ``^(ran|skipped:.+|partial:.+)$`` has a ``.`` that stops there.
_LINE_BREAKS = ("\n", "\r", "\u2028", "\u2029")
#: ``snapshot`` cuts the reasons folded into a ``partial:`` state to this many characters.
_MAX_REASON_CHARS = 300
#: ``abort`` cuts the reason (an exception class name) to this many characters.
_MAX_ABORT_REASON = 80


def _check_layer(layer_id: object) -> None:
    if not isinstance(layer_id, str) or layer_id not in _COVERAGE_LAYERS:
        raise ValueError("unknown coverage layer id: %r" % (layer_id,))


def _has_line_break(text: str) -> bool:
    return any(mark in text for mark in _LINE_BREAKS)


def _check_state(state: object) -> None:
    """``ran``, ``skipped:<reason>`` or ``partial:<reason>`` with a non-empty reason and no line break."""
    ok = isinstance(state, str) and not _has_line_break(state) and (
        state == "ran"
        or (state.startswith("skipped:") and len(state) > len("skipped:"))
        or (state.startswith("partial:") and len(state) > len("partial:")))
    if not ok:
        raise ValueError("malformed coverage state: %r" % (state,))


def _partial(reasons: "set[str]") -> str:
    return "partial:" + "; ".join(sorted(reasons))[:_MAX_REASON_CHARS]


def _safe_reason(reason: str) -> str:
    """The text of an exception class name made safe to put in a message and in a coverage state: control characters,
    line breaks and bidi controls become ``?``, the length is bounded, and nothing at all becomes ``unknown``."""
    text = "".join("?" if (c < " " or "\x7f" <= c <= "\x9f" or c in BIDI_CONTROLS or c in _LINE_BREAKS) else c
                   for c in str(reason)[:_MAX_ABORT_REASON])
    return text or "unknown"


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
        self._scan_dir = scan_dir
        self._allowlist = allowlist
        self._allowlist_installed = False
        self._threshold = threshold
        self._min_severity = min_severity
        self._console = console
        self._first_writer = first_writer
        self._dot_matches_directory = dot_matches_directory
        self._verdict = "PASS"
        self._pass = 0
        self._warn = 0
        self._fail = 0
        self._events = 0
        self._status: "dict[str, str]" = {}
        self._message_parts: "dict[str, list[str]]" = {}     # file -> ["[WARN] a | ", "[FAIL] b | ", ...]
        self._fail_parts: "dict[str, list[str]]" = {}        # file -> ["b | ", ...]
        self._findings: "list[FindingRecord]" = []
        self._layers: "dict[str, str]" = {}
        self._incomplete: "dict[str, set[str]]" = {}
        self._once: "set[str]" = set()

    def set_allowlist(self, allowlist: Allowlist) -> None:
        """Install the allowlist parsed from ``.transit-allow.json``. Legal exactly once, before the first event (``events == 0``);
        a later call raises ``RuntimeError`` (S13: an allowlist is loaded before anything is judged and is never swapped while
        findings are being decided). Before this call the allowlist is the empty one given to ``__init__``."""
        if self._events != 0 or self._allowlist_installed:
            raise RuntimeError("set_allowlist is legal once, before the first event")
        self._allowlist = allowlist
        self._allowlist_installed = True

    # -- reads ------------------------------------------------------------------------------------------------
    @property
    def verdict(self) -> str:
        """``"PASS"`` until the first surviving FAIL, then ``"FAIL"`` forever (contract 6.1)."""
        return self._verdict

    @property
    def counters(self) -> Counters:
        return Counters(self._pass, self._warn, self._fail)

    @property
    def events(self) -> int:
        """Total number of ``record_*`` calls so far. ``scanners.invoke`` compares it before and after a scanner to detect
        a scanner that handled a file without recording any outcome (a bug, turned into a FAIL)."""
        return self._events

    def status_of(self, file: str) -> "str | None":
        """The file's status, or None if it has none yet."""
        return self._status.get(file)

    def coverage_state(self, layer_id: str) -> "str | None":
        """The base state recorded for ``layer_id`` (before ``partial`` folding), or None."""
        return self._layers.get(layer_id)

    # -- writes: events ---------------------------------------------------------------------------------------
    def record_pass(self, file: "str | None" = None) -> None:
        """Bash ``record_pass``: counter +1 ALWAYS; the file gets status PASS and an empty message only if it has no status
        yet. ``None`` or ``""`` touches no file."""
        self._pass += 1
        self._events += 1
        if file and file not in self._status:
            self._status[file] = "PASS"
            self._message_parts.setdefault(file, [])

    def _note_warn(self, file: str, message: str) -> None:
        """The state change of a WARN (bash ``record_warn`` without the console line): one event, one counter, the status
        only if the file has none (D-012: or only a PASS), and the ``[WARN]`` text."""
        self._warn += 1
        self._events += 1
        status = self._status.get(file)
        if status is None or (not self._first_writer and status == "PASS"):
            self._status[file] = "WARN"
        self._message_parts.setdefault(file, []).append(f"[WARN] {message} | ")

    def record_warn(self, file: "str | None", message: str) -> None:
        """Bash ``record_warn``: counter +1; mirrored on stderr (message only); status WARN only if the file has none;
        appends ``[WARN] <message> | ``. ``None`` or ``""`` means ``__global__``."""
        file = file or GLOBAL_FILE
        self._note_warn(file, message)
        self._console.warn(message)

    def record_warn_once(self, key: str, file: "str | None", message: str) -> bool:
        """``record_warn(file, message)`` the first time ``key`` is seen in this run, nothing afterwards. Returns True if it recorded.
        ``key`` is engine-generated (``tool_not_ported:bandit``), never repository text. This is the run-scoped state behind
        ``ScanContext.file_tool``'s "once per run" WARN: a ``ScanContext`` lives for one file, so the memory has to be here, in
        the one mutable object, and not in a module global (which would leak between two ``pipeline.main`` calls in one process;
        review log R-22)."""
        if key in self._once:
            return False
        self._once.add(key)
        self.record_warn(file, message)
        return True

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
        file = file or GLOBAL_FILE
        exempt = not downgradable or message.startswith(ENGINE_PREFIX)
        if not exempt:
            reason = self._allowlist.lookup(message, relative_to_scan_dir(file, self._scan_dir))
            if reason is None and self._dot_matches_directory and file == self._scan_dir:
                reason = self._allowlist.lookup(message, ".")           # D-011: "." names the scanned directory
            if reason:
                text = f"ALLOWED:{message} (reason: {reason})"
                self._note_warn(file, text)
                self._console.warn(text)
                return Outcome.ALLOWED
        # one severity decides both the threshold and the record: the record is built first and read back
        record = build_record(file, message, self._scan_dir, severity=severity)
        if not exempt and SEVERITY_NUMBER[record.severity] < self._threshold:
            text = f"LOW_SEV(below --min-severity {self._min_severity}):{message}"
            self._note_warn(file, text)
            self._console.warn(text)
            return Outcome.LOW_SEV
        self._findings.append(record)
        self._status[file] = "FAIL"                                      # unconditionally, in both modes
        self._message_parts.setdefault(file, []).append(f"[FAIL] {message} | ")
        self._fail_parts.setdefault(file, []).append(f"{message} | ")
        self._fail += 1
        self._events += 1
        self._verdict = "FAIL"
        self._console.fail_line(f"[{file}] {message}")                  # last: the state above survives a console failure
        return Outcome.FAILED

    # -- writes: coverage -------------------------------------------------------------------------------------
    def record_layer(self, layer_id: str, state: str, *, overwrite: bool = True) -> None:
        """Set the base state of a layer. ``layer_id`` must be in ``config.COVERAGE_LAYERS`` and ``state`` must match
        ``ran | skipped:<non-empty> | partial:<non-empty>`` or ``ValueError`` is raised (a mistyped id must not create a
        tenth layer). ``overwrite=False`` keeps an earlier state (bash ``[[ -z ${LAYER_COVERAGE[x]} ]] && record_layer``)."""
        _check_layer(layer_id)
        _check_state(state)
        if overwrite or layer_id not in self._layers:
            self._layers[layer_id] = state

    def note_incomplete(self, layer_id: str, reason: str) -> None:
        """Say that part of ``layer_id`` did not run (an unported tool or scanner, a time budget, an unreadable directory).
        ``snapshot()`` turns base state ``ran`` into ``partial:<reasons>`` (reasons de-duplicated, sorted, joined with
        ``"; "``, at most 300 characters); a ``skipped:`` state is left as it is. ``reason`` is engine-generated text, never
        repository text (names go in the WARN, not here)."""
        _check_layer(layer_id)
        if not isinstance(reason, str) or not reason or _has_line_break(reason):
            raise ValueError("an incomplete-coverage reason is one non-empty line")
        self._incomplete.setdefault(layer_id, set()).add(reason)

    # -- end of run -------------------------------------------------------------------------------------------
    def abort(self, reason: str) -> None:
        """D-028. Callable at any moment after construction (the Verdict exists before the first step that can fail, so this is
        never "too early"). Called by the top-level handler after an internal error: records the FAIL ``engine:internal_error:<reason>``
        on ``__global__`` (not downgradable) and gives every REQUIRED layer that has no state the state
        ``skipped:engine aborted (<reason>)``, so the report still validates and cannot read as a clean run."""
        safe = _safe_reason(reason)
        for layer_id in _COVERAGE_REQUIRED:
            self._layers.setdefault(layer_id, f"skipped:engine aborted ({safe})")
        self.record_fail(GLOBAL_FILE, f"{ENGINE_PREFIX}internal_error:{safe}", downgradable=False)

    def snapshot(self) -> Snapshot:
        """Freeze the state for ``report``. Folds ``note_incomplete`` reasons into the coverage states. Idempotent."""
        coverage: "dict[str, str]" = {}
        for layer_id in sorted(set(self._layers) | set(self._incomplete)):
            base = self._layers.get(layer_id)
            notes = self._incomplete.get(layer_id)
            if not notes:
                coverage[layer_id] = base or "ran"                      # unreachable without notes: `base` exists
            elif base is None or base == "ran":
                coverage[layer_id] = _partial(notes)
            elif base.startswith("partial:"):
                coverage[layer_id] = _partial(notes | {base[len("partial:"):]})
            else:                                                       # skipped: stays as it is
                coverage[layer_id] = base
        return Snapshot(
            verdict=self._verdict,
            counters=Counters(self._pass, self._warn, self._fail),
            file_status=types.MappingProxyType(dict(self._status)),
            file_message=types.MappingProxyType({f: "".join(parts) for f, parts in self._message_parts.items()}),
            fail_messages=types.MappingProxyType({f: "".join(parts) for f, parts in self._fail_parts.items()}),
            findings=tuple(self._findings),
            coverage=types.MappingProxyType(coverage))
