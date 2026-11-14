"""Layer orchestration: L1 to L6, the per-file loop for L4 and L5, and the coverage block.

Owner of: contract 7 (every coverage state and when it is written), 8.1 (the two sets of files: whole-directory tools get
``scan_dir``, the per-file layers get the list), S9 (a layer is ``ran`` only if its tool ran and its output parsed; an
installed tool without a wrapper is ``skipped:python engine has not ported <tool> yet``), the `OFFLINE:` notes of layer 3,
contract 8.8 rule 1 (the universal layer runs on every file before dispatch), and the progress line.

Layering: the top of the dependency graph below ``pipeline``: it uses ``config``, ``console``, ``verdict``, ``files``,
``dispatch``, ``tools`` and ``scanners`` (registry, context, guard); ``run_all`` imports ``transit.scanners.universal`` itself, while
``run_file_layers`` takes it as a parameter so tests can inject a fake. Nothing imports ``layers`` except ``pipeline``.

This module is GENERIC. Every tool-specific decision (what to run, which flags, what a non-zero exit means, which message a
finding gets, which coverage state results) lives in the tool's wrapper (``transit/tools/<tool>_wrapper.py``) and comes back
as a ``ToolOutcome``. A Phase 4 package therefore adds a file and edits nothing here. The tool-independent facts are the
``ToolSlot`` rows below: the exact missing-tool WARN and state of contract 5.1 / 7.

Behaviour of the HARDENED bash engine (2026-11-13) that the frozen docstrings below do not mention, implemented here as ADDITIVE behaviour (the
goldens in ``tests/conformance/golden`` are the target, ``docs/engine_divergences.md`` the register):

* ``search_policy`` builds ``excl_nul_blind=False``: D-029 is closed in bash (an exclusion rule reads a file with a NUL byte as text), so the
  switch ``D-029`` of ``config.KNOWN_FIXES`` describes the pre-hardening behaviour and is not read.
* the three control files (``files.CONTROL_FILE_NAMES``) are scanned but do not count as "something was examined": ``run_file_layers`` takes
  its decision from ``ScanList.nothing_scanned`` and never from the count of entries, which cannot see a repository whose only listed file is
  its own ``.transitignore``. In a diff run the files that count are the changed ones, which the flag already says.
* ``engine:nothing_scanned`` and ``engine:file_listing_failed`` are recorded on ``__global__`` and have no detail segment (golden
  ``transitignore_everything``); the layers read ``skipped:nothing scanned (every file excluded)`` and ``skipped:file listing failed (find exit N)``.
* a symbolic link is reported, never followed (``ScanList.symlinks``): FAIL ``symlink:target_outside_the_scanned_directory`` or WARN
  ``symlink:not_followed_its_target_is_not_scanned_through_the_link``, both through the allowlist and the threshold like any other finding.
* the child environment of ``tools.child_env`` carries ``LC_ALL=C`` (the script exports it for the whole run).
"""
from __future__ import annotations

import dataclasses
import os
import time
from typing import Callable

from transit.cli import Args
from transit.config import Config
from transit.console import Console
from transit.dispatch import classify_file
from transit.files import MAX_WALK_DEPTH, DiffSelection, Exclusions, FileReadError, FileView, ScanList, TempArea
from transit.findings import SEVERITY_NUMBER, join_scan_path
from transit.rules import SearchPolicy
from transit.scanners import Registry, ScanContext, guard, invoke
from transit.tools import DIRECTORY_TOOLS, Record, ToolLocator, ToolOutcome, ToolRequest, WrapperSet
from transit.verdict import GLOBAL_FILE, Verdict


@dataclasses.dataclass(frozen=True)
class ToolSlot:
    """A whole-directory tool of layers 1, 2, 3 or 6. ``tool`` is the wrapper key (a key of ``tools.DIRECTORY_TOOLS``; the executable is
    its value); ``layer_id`` the coverage id it feeds;
    ``missing_message`` / ``missing_state`` the exact texts when it is not installed (``missing_message`` is recorded as a
    WARN on ``missing_file``). ``requires_dir``: a directory below ``WORK_DIR`` that must also exist (yara-rules); when it
    does not, the tool counts as missing."""
    tool: str
    layer_id: str
    missing_message: str
    missing_state: str
    requires_dir: "str | None" = None
    missing_file: str = "__global__"


LAYER1_SLOTS: tuple[ToolSlot, ...] = (
    ToolSlot("gitleaks", "L1_secrets_gitleaks", "gitleaks missing — secret scan skipped", "skipped:gitleaks not installed"),
    ToolSlot("detect-secrets", "L1_secrets_entropy", "detect-secrets missing", "skipped:detect-secrets not installed"),
    ToolSlot("clamscan", "L1_malware", "clamscan missing", "skipped:clamav not installed"),
    ToolSlot("yara", "L1_ioc_yara", "yara or rules directory missing", "skipped:yara or rules directory missing",
             requires_dir="yara-rules"),
)
LAYER2_SLOTS: tuple[ToolSlot, ...] = (
    ToolSlot("semgrep", "L2_owasp_cwe", "semgrep missing — OWASP/CWE layer skipped (pip install semgrep)",
             "skipped:semgrep not installed"),
)
LAYER3_SLOTS: tuple[ToolSlot, ...] = (
    ToolSlot("trivy", "L3_dependency_cve", "trivy missing — dependency CVE scan skipped", "skipped:trivy not installed"),
)
LAYER6_SLOTS: tuple[ToolSlot, ...] = (
    ToolSlot("scancode", "L6_licence",
             "scancode missing — licence/copyright layer skipped (pip install scancode-toolkit)",
             "skipped:scancode not installed"),
)

#: Exact coverage texts of contract 7 for a layer that is switched off.
LAYER3_DISABLED = "skipped:disabled (RUN_SCA is not true)"
LAYER6_DISABLED = "skipped:disabled (RUN_SCANCODE is not true)"


@dataclasses.dataclass
class RunEnv:
    """Everything a layer needs, built by ``pipeline.main`` after the arguments, configuration, allowlist, exclusions and diff
    selection are loaded. ``scan_dir`` is ``args.scan_dir`` (trailing slashes already removed)."""
    cfg: Config
    args: Args
    scan_dir: str
    console: Console
    verdict: Verdict
    tools: ToolLocator
    wrappers: WrapperSet
    registry: Registry
    temp: TempArea
    exclusions: Exclusions
    diff: DiffSelection


@dataclasses.dataclass(frozen=True)
class FileLayerSummary:
    """Result of the per-file loop: files seen, files skipped because they vanished, files that could not be read."""
    scanned: int
    vanished: int
    unreadable: int


#: The two notes of layer 3 (bash ``scan_dependencies``, offline branch; D-026: pip-audit, safety and ``npm audit`` are not ported). Each has an em dash U+2014.
_OFFLINE_PYTHON = ("OFFLINE:Python dependency CVE scan unavailable (pip-audit and safety both require a network advisory service) "
                   "— rely on the staged trivy database for Python CVEs")
_OFFLINE_JAVASCRIPT = ("OFFLINE:JavaScript dependency CVE scan unavailable (npm audit requires the registry) "
                       "— rely on the staged trivy database for JS CVEs")
#: ``find "$SCAN_DIR" -name "requirements*.txt" -o -name "Pipfile.lock" -o -name "pyproject.toml"`` and ``-name "package-lock.json" -o -name "yarn.lock"`` of bash,
#: tested against the name of an entry (a file, a directory or a link: ``find`` had no ``-type``). ``requirements*.txt`` is a prefix and a suffix: the suffix
#: starts with a dot, which the prefix does not contain, so the two cannot overlap and no glob matcher is needed.
_PYTHON_DEPENDENCY_NAMES = frozenset({"Pipfile.lock", "pyproject.toml"})
_PYTHON_REQUIREMENTS_PREFIX = "requirements"
_PYTHON_REQUIREMENTS_SUFFIX = ".txt"
_JAVASCRIPT_DEPENDENCY_NAMES = frozenset({"package-lock.json", "yarn.lock"})

#: How many directories ``run_slot`` / ``run_file_layers`` report one by one (``engine:directory_unreadable:<reason>``) before one summary.
_MAX_DIRECTORY_FAILS = 200
#: The words ``run_slot`` puts after ``engine:tool_error:<tool>:`` when the wrapper did not raise but returned something unusable.
_BAD_OUTCOME = "bad_outcome"
_NO_LAYER_STATE = "no_layer_state"
_BAD_LAYER_STATE = "bad_layer_state"
_BAD_RECORD = "bad_record"
#: The kinds of ``tools.Record`` a whole-directory wrapper may return (bash ``record_pass`` / ``record_warn`` / ``record_fail``).
_RECORD_KINDS = ("pass", "warn", "fail")
#: The L5 reasons ``finalise`` and the listing failures note.
_LOAD_ERROR_NOTE = "scanner module failed to load"
_LISTING_NOTE = "a directory could not be listed"
_NOTHING_SCANNED_NOTE = "every file was excluded by .transitignore"

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_CLASS_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _class_word(exc: BaseException) -> str:
    """The class name of ``exc`` reduced to ``[A-Za-z0-9_]`` and at most 60 characters: the only part of an exception that reaches a report (its text
    can carry a file name; the class is chosen by a library, but it is still filtered)."""
    cleaned = "".join(ch if ch in _CLASS_CHARS else "_" for ch in type(exc).__name__[:60])
    return cleaned or "unknown"


def _reason_word(reason: object) -> str:
    """``FileReadError.reason`` and the reason of a ``ScanList.errors`` item (``permission``, ``io``, ``too_deep``, ``too_large``, ``vanished``): kept
    only if it looks like one of those words, else ``unknown``. A reason is engine text; the filter makes sure of it."""
    text = reason if isinstance(reason, str) else ""
    if 0 < len(text) <= 24 and text.isascii() and text.islower() and text.replace("_", "").isalpha():
        return text
    return "unknown"


def search_policy(cfg: Config) -> SearchPolicy:
    """The ONLY producer of a ``SearchPolicy``: ``SearchPolicy(rule_budget_s=cfg.limits.rule_budget_s, long_line_bytes=cfg.limits.long_line_bytes,
    excl_nul_blind=False)``. ``run_file_layers`` calls it once per run and hands the result to every ``ScanContext`` (review
    log R-25: the stub had a consumer and no producer).

    ``excl_nul_blind`` is ALWAYS False, and the frozen docstring's ``not cfg.fix("D-029")`` is not what runs: D-029 is closed in the bash engine
    (hardened 2026-11-13: an exclusion rule reads a file with a NUL byte as text, Layer J of ``tests/run_tests.sh``), and ``docs/engine_divergences.md``
    says that ``layers.search_policy`` builds ``excl_nul_blind=False``. The class default (True) and the id ``D-029`` in ``config.KNOWN_FIXES`` describe the
    pre-hardening behaviour and are not read here."""
    return SearchPolicy(rule_budget_s=cfg.limits.rule_budget_s, long_line_bytes=cfg.limits.long_line_bytes, excl_nul_blind=False)


def file_deadline(cfg: Config, size: int, *, now: float) -> float:
    """The ``time.monotonic()`` value after which the rules of ONE file may no longer start:
    ``now + limits.file_budget_s + limits.file_budget_s_per_mb * size / 2**20``, ``size`` being ``FileEntry.size``. Scaled with the size
    because the cost of the linear matcher is linear in it (about 38 ns per byte per rule, measured: a 20 MiB file with one long line
    costs 0.4 s per rule); a fixed 120 s could not cover the 512 MiB the engine accepts, and its expiry was a WARN that a hostile file
    could buy cheaply (review log R-02). Expiry is a FAIL (``ScanContext.run_rules``, ``scanners.invoke``). A size below zero counts as zero."""
    limits = cfg.limits
    return now + limits.file_budget_s + limits.file_budget_s_per_mb * (max(size, 0) / 2 ** 20)


def _valid_record(record: object) -> bool:
    """Is ``record`` a ``tools.Record`` the engine can apply: a known kind, text where text is expected, a severity the classifier knows?"""
    return (isinstance(record, Record) and record.kind in _RECORD_KINDS and isinstance(record.file, str) and isinstance(record.message, str)
            and (record.severity is None or record.severity in SEVERITY_NUMBER))


def _apply_outcome(env: RunEnv, slot: ToolSlot, outcome: object) -> "str | None":
    """Apply what a wrapper returned: the state of the layer, then the records in order, then the notes. Returns None when it was applied, else the
    engine word that says why NOTHING was (the caller records the ``engine:tool_error`` FAIL and the failed state): a result the engine cannot
    read is not a result, and a half-applied one would be a tool that partly ran and still reads as ``ran``."""
    if not isinstance(outcome, ToolOutcome):
        return _BAD_OUTCOME
    state = outcome.layer_state
    if state is None:
        return _NO_LAYER_STATE
    try:
        records = tuple(outcome.records)
    except TypeError:
        return _BAD_RECORD
    if not all(_valid_record(record) for record in records):
        return _BAD_RECORD
    if outcome.timed_out and state == "ran":
        state = "skipped:%s timed out" % slot.tool          # a tool that was killed did not run to the end, whatever its wrapper said
    try:
        env.verdict.record_layer(slot.layer_id, state)      # ValueError for a state outside ran | skipped:<reason> | partial:<reason>
    except ValueError:
        return _BAD_LAYER_STATE
    for record in records:
        if record.kind == "pass":
            env.verdict.record_pass(record.file or None)
        elif record.kind == "warn":
            env.verdict.record_warn(record.file or None, record.message)
        else:                                               # through the allowlist and the threshold exactly as a rule's finding is (6.2)
            env.verdict.record_fail(record.file, record.message, severity=record.severity)
    for note in outcome.notes:
        env.console.info(note)                              # console only; Console sanitises it (S10)
    return None


def _tool_error(env: RunEnv, slot: ToolSlot, word: str) -> None:
    """The wrapper failed (it raised, or returned something the engine cannot use): a FAIL on the scanned directory that nothing can allowlist or lower,
    and a layer that did not run."""
    env.verdict.record_fail(env.scan_dir, "engine:tool_error:%s:%s" % (slot.tool, word), downgradable=False)
    env.verdict.record_layer(slot.layer_id, "skipped:%s wrapper failed" % slot.tool)


def run_slot(env: RunEnv, slot: ToolSlot) -> None:
    """One whole-directory tool. Decision, in this order:
      1. not found (or ``requires_dir`` absent) -> ``record_warn(slot.missing_file, slot.missing_message)`` and
         ``record_layer(slot.layer_id, slot.missing_state)``;
      2. found, no wrapper -> WARN ``engine:tool_not_ported:<tool>`` on ``__global__`` and the state
         ``skipped:python engine has not ported <tool> yet``;
      3. otherwise ``wrapper.run(ToolRequest)``; its ``records`` are applied in order (``pass`` -> ``record_pass``, ``warn`` ->
         ``record_warn``, ``fail`` -> ``record_fail``) and its ``layer_state`` is recorded;
      4. the wrapper raised, or returned ``layer_state`` None -> FAIL ``engine:tool_error:<tool>:<ExceptionClass>`` on ``scan_dir``
         (not downgradable) and the state ``skipped:<tool> wrapper failed``. A hostile repository must not be able to turn a crash
         in a parser into a PASS.

    Step 4 also covers a result the engine cannot read (the word after the tool is then ``bad_outcome``, ``no_layer_state``, ``bad_layer_state`` or
    ``bad_record`` instead of a class name): nothing of it is applied. A wrapper that raises ``SystemExit`` costs its tool and not the run; any other
    ``BaseException`` (the signal exception of ``pipeline``, Ctrl-C) propagates. The text of an exception never reaches the report, only its class name;
    the traceback goes to the console, sanitised. A result of ``ran`` with ``timed_out`` set is recorded as ``skipped:<tool> timed out`` (a safety net:
    a wrapper reports a timeout with its own state and WARN)."""
    info = env.tools.find(DIRECTORY_TOOLS[slot.tool])
    needed_dir_ok = slot.requires_dir is None or os.path.isdir(os.path.join(env.cfg.work_dir, slot.requires_dir))
    if info is None or not needed_dir_ok:
        env.verdict.record_warn(slot.missing_file, slot.missing_message)
        env.verdict.record_layer(slot.layer_id, slot.missing_state)
        return
    wrapper = env.wrappers.get(slot.tool)
    if wrapper is None:
        env.verdict.record_warn(GLOBAL_FILE, "engine:tool_not_ported:" + slot.tool)
        env.verdict.record_layer(slot.layer_id, "skipped:python engine has not ported %s yet" % slot.tool)
        return
    env.console.info(slot.tool + "…")
    request = ToolRequest(cfg=env.cfg, scan_dir=env.scan_dir, target=None, temp=env.temp, exclude_dirs=env.exclusions.semgrep_dirs(), info=info)
    try:
        outcome = wrapper.run(request)
    except (Exception, SystemExit) as exc:                  # SystemExit: a library that exits costs its tool, never the run
        try:
            env.console.exception("%s wrapper failed" % slot.tool, exc)
        except Exception:                                   # noqa: BLE001  (a console that fails must not undo the FAIL below)
            pass
        _tool_error(env, slot, _class_word(exc))
        return
    word = _apply_outcome(env, slot, outcome)
    if word is not None:
        _tool_error(env, slot, word)


def run_layer1(env: RunEnv) -> None:
    """Layer 1 in bash order (gitleaks, detect-secrets, clamscan, yara): ``run_slot`` for each of ``LAYER1_SLOTS``."""
    env.console.info("=== Layer 1: Global (AV, secrets, IOC) ===")
    for slot in LAYER1_SLOTS:
        run_slot(env, slot)


def run_layer2(env: RunEnv) -> None:
    """Layer 2: ``run_slot`` for ``LAYER2_SLOTS``."""
    env.console.info("=== Layer 2: OWASP Top 10 2021 + CWE Top 25 (Semgrep) ===")
    for slot in LAYER2_SLOTS:
        run_slot(env, slot)


def _open_chain(root_fd: int, parts: "tuple[str, ...]") -> int:
    """A new descriptor for the directory ``parts`` below the directory ``root_fd``, opened one component at a time without following a link (so the
    length of the path never matters, and a link swapped in during the run is not followed)."""
    current = os.open(".", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC, dir_fd=root_fd)
    try:
        for part in parts:
            following = os.open(part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=current)
            os.close(current)
            current = following
    except BaseException:
        os.close(current)
        raise
    return current


def _dependency_files(scan_dir: str) -> "tuple[bool, bool]":
    """``(python, javascript)``: does an entry named like a Python dependency file (``requirements*.txt``, ``Pipfile.lock``, ``pyproject.toml``) or a JavaScript
    lock file (``package-lock.json``, ``yarn.lock``) exist below ``scan_dir``? As the ``find`` of ``scan_dependencies`` does: EVERY entry counts (no ``-type``),
    nothing is pruned (``node_modules`` and ``.transitignore`` do not hide one) and no link is followed. A directory that cannot be listed is not an error
    here (the file listing of layers 4 and 5 reports it). Walks directory descriptors, at most ``files.MAX_WALK_DEPTH`` deep, and stops when both are found."""
    python = javascript = False
    try:
        root = os.open(scan_dir, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    except OSError:
        return False, False
    try:
        stack: "list[tuple[str, ...]]" = [()]
        while stack and not (python and javascript):
            parts = stack.pop()
            try:
                fd = _open_chain(root, parts)
            except OSError:
                continue
            try:
                with os.scandir(fd) as listing:
                    for entry in listing:
                        name = entry.name
                        if not python and (name in _PYTHON_DEPENDENCY_NAMES or (name.startswith(_PYTHON_REQUIREMENTS_PREFIX)
                                                                                   and name.endswith(_PYTHON_REQUIREMENTS_SUFFIX))):
                            python = True
                        if not javascript and name in _JAVASCRIPT_DEPENDENCY_NAMES:
                            javascript = True
                        try:
                            descend = entry.is_dir(follow_symlinks=False) and len(parts) < MAX_WALK_DEPTH
                        except OSError:
                            continue
                        if descend:
                            stack.append(parts + (name,))
            except OSError:
                pass
            finally:
                os.close(fd)
    finally:
        os.close(root)
    return python, javascript


def run_layer3(env: RunEnv) -> None:
    """Layer 3. ``RUN_SCA`` not exactly ``true`` -> ``record_layer("L3_dependency_cve", LAYER3_DISABLED)`` and an info line.
    Otherwise ``run_slot`` for trivy, then the offline notes (D-026: pip-audit, safety and npm audit are not ported): if the
    first five paths matching ``requirements*.txt``, ``Pipfile.lock`` or ``pyproject.toml`` exist, the WARN
    ``OFFLINE:Python dependency CVE scan unavailable (pip-audit and safety both require a network advisory service) - rely on the
    staged trivy database for Python CVEs``; if the first three ``package-lock.json`` / ``yarn.lock`` exist, the WARN
    ``OFFLINE:JavaScript dependency CVE scan unavailable (npm audit requires the registry) - rely on the staged trivy database for
    JS CVEs`` (exact texts: ``scan_dependencies`` in the reference script; each has an em dash U+2014 where the lines above show a hyphen).

    "The first five" and "the first three" of the script only bound a pipeline; what decides is whether one exists, anywhere below the scanned directory
    (``_dependency_files``)."""
    if not env.cfg.run_sca:
        env.console.info("Layer 3 (dependency CVEs) is disabled — set RUN_SCA=true to run it")
        env.verdict.record_layer("L3_dependency_cve", LAYER3_DISABLED)
        return
    env.console.info("=== Layer 3: SCA — Vulnerable dependencies (OWASP A06) ===")
    for slot in LAYER3_SLOTS:
        run_slot(env, slot)
    python, javascript = _dependency_files(env.scan_dir)
    if python:
        env.verdict.record_warn(GLOBAL_FILE, _OFFLINE_PYTHON)
    if javascript:
        env.verdict.record_warn(GLOBAL_FILE, _OFFLINE_JAVASCRIPT)


def run_layer6(env: RunEnv) -> None:
    """Layer 6: ``RUN_SCANCODE`` not exactly ``true`` -> ``record_layer("L6_licence", LAYER6_DISABLED)``; otherwise ``run_slot`` for
    ``LAYER6_SLOTS`` (the wrapper adds the ``OFFLINE:scancode CVE lookup disabled ...`` WARN)."""
    if not env.cfg.run_scancode:
        env.console.info("Layer 6 (ScanCode licences) is disabled — set RUN_SCANCODE=true to run it")
        env.verdict.record_layer("L6_licence", LAYER6_DISABLED)
        return
    env.console.info("=== Layer 6: ScanCode — licence, copyright & vulnerability ===")
    for slot in LAYER6_SLOTS:
        run_slot(env, slot)


def _report_links(env: RunEnv, scan: ScanList) -> None:
    """Hardened bash: a symbolic link is reported and never followed. FAIL when the text of its target is absolute or climbs above the scan root, else
    WARN; both through ``record_fail`` / ``record_warn``, so the allowlist and ``--min-severity`` apply. Not subject to the diff selection."""
    for link in scan.symlinks:
        if link.escapes:
            env.verdict.record_fail(link.path, "symlink:target_outside_the_scanned_directory")
        else:
            env.verdict.record_warn(link.path, "symlink:not_followed_its_target_is_not_scanned_through_the_link")


def _report_unlistable(env: RunEnv, scan: ScanList) -> None:
    """The listing did not complete: ``engine:file_listing_failed`` on ``__global__`` (bash ``record_fail_hard``), one ``engine:directory_unreadable:<reason>``
    per directory that could not be listed (the first 200, then ``more_not_listed_<n>`` on the scanned directory), all non-downgradable. A directory is a
    subtree that was not examined: the same case as an unreadable file (review log R-09)."""
    code = scan.listing_exit or 1
    env.console.warn("the file listing of %s did not complete (find exit %d): files may have been missed" % (env.scan_dir, code))
    env.verdict.record_fail(GLOBAL_FILE, "engine:file_listing_failed", downgradable=False)
    for rel, reason in scan.errors[:_MAX_DIRECTORY_FAILS]:
        where = env.scan_dir if rel == "." else join_scan_path(env.scan_dir, rel)
        env.verdict.record_fail(where, "engine:directory_unreadable:" + _reason_word(reason), downgradable=False)
    rest = len(scan.errors) - _MAX_DIRECTORY_FAILS
    if rest > 0:
        env.verdict.record_fail(env.scan_dir, "engine:directory_unreadable:more_not_listed_%d" % rest, downgradable=False)
    for layer in ("L4_patterns", "L5_per_language_sast"):
        env.verdict.note_incomplete(layer, _LISTING_NOTE)


def _scan_file(env: RunEnv, entry_rel: str, size: int, policy: SearchPolicy, universal: Callable[..., object],
               dispatch_file: Callable[..., None]) -> str:
    """One file of the loop: ``"scanned"``, ``"vanished"`` or ``"unreadable"``. The file is read ONCE, here, so that a file that vanished or cannot be read is
    known before any context exists; the universal layer and the family scanner then share the cached bytes and ONE deadline."""
    view = FileView(env.scan_dir, entry_rel, env.cfg.limits)
    try:
        try:
            view.data()
        except FileReadError as exc:
            if exc.reason == "vanished":
                return "vanished"                           # bash ``[[ -f ]] || continue``: no event, no trace
            env.verdict.record_fail(view.path, "engine:file_unreadable:" + _reason_word(exc.reason), downgradable=False)
            return "unreadable"
        except MemoryError:                                 # a file the host cannot hold is a file that was not examined
            env.verdict.record_fail(view.path, "engine:file_unreadable:memory", downgradable=False)
            return "unreadable"
        deadline = file_deadline(env.cfg, size, now=time.monotonic())

        def context(sniffed: bool) -> ScanContext:
            return ScanContext(view=view, verdict=env.verdict, cfg=env.cfg, console=env.console, tools=env.tools, wrappers=env.wrappers,
                               registry=env.registry, policy=policy, temp=env.temp, scan_dir=env.scan_dir, deadline=deadline, sniffed=sniffed)

        def run(scanner_id: str, sniffed: bool) -> bool:
            return invoke(env.registry, scanner_id, context(sniffed))

        guard("universal", universal, context(False), requires_outcome=False)
        dispatch_file(view, run)
        return "scanned"
    finally:
        view.release()


def run_file_layers(env: RunEnv, scan: ScanList, *, universal: Callable[..., object], dispatch_file: Callable[..., None]) -> FileLayerSummary:
    """Layers 4 and 5 (bash ``scan_by_type``). Builds the run's ``SearchPolicy`` once (``search_policy(env.cfg)``). For each entry of
    ``scan.entries``: draw the progress line (``Console.progress`` sanitises the name); build a ``FileView(env.scan_dir, entry.rel, limits)``;
    read it once (``vanished`` -> skip silently, as bash ``[[ -f ]] || continue``; another ``FileReadError`` -> FAIL
    ``engine:file_unreadable:<reason>`` on the file and go on); compute ONE deadline for the file, ``file_deadline(env.cfg, entry.size,
    now=time.monotonic())``; build a ``ScanContext`` and run the universal layer through
    ``scanners.guard("universal", universal, ctx, requires_outcome=False)``; then ``dispatch.classify_file(view, run)`` where
    ``run(id, sniffed)`` builds a fresh context with the SAME deadline (a new deadline per scanner call is NOT allowed) and calls
    ``scanners.invoke``; finally ``view.release()``. After the loop: the info line ``Layer 5: <n> files scanned``,
    ``record_layer("L4_patterns", "ran")`` and ``record_layer("L5_per_language_sast", "ran")`` (even with zero files, golden
    ``diff_mode_zero_files``), then:
      * for each ``(rel, reason)`` of ``scan.errors`` (the first 200; then one summary on ``env.scan_dir`` named
        ``engine:directory_unreadable:more_not_listed_<n>``): the non-downgradable FAIL ``engine:directory_unreadable:<reason>`` on the
        recorded path of the directory, plus ``note_incomplete`` on both layers. A directory is a subtree that was not examined; it is
        the same case as an unreadable file (review log R-09);
      * [SUPERSEDED, see "WHAT THE HARDENED BASH ENGINE CHANGED" below] if ``scan.entries`` is empty, ``scan.excluded_by_patterns`` > 0 and
        ``env.diff.active`` is False: the non-downgradable FAIL ``engine:nothing_scanned:transitignore`` on ``env.scan_dir`` plus ``note_incomplete`` on
        both layers: the repository's own ``.transitignore`` removed everything and nothing was examined (review log R-03). What runs is the
        ``engine:nothing_scanned`` of the golden ``transitignore_everything``, on ``__global__``, decided by ``ScanList.nothing_scanned``.
    ``universal`` and ``dispatch_file`` are parameters only so that tests can inject fakes;
    ``pipeline`` passes ``transit.scanners.universal.scan`` and ``transit.dispatch.classify_file``.

    WHAT THE HARDENED BASH ENGINE CHANGED (additive; the docstring above is the frozen one). The order is bash's: first the symbolic links
    (``ScanList.symlinks``; FAIL ``symlink:target_outside_the_scanned_directory`` or WARN ``symlink:not_followed_its_target_is_not_scanned_through_the_link``),
    then ONE of two scan-level FAILs, then the loop, then the coverage:
      * the listing did not complete (``scan.errors`` or ``scan.listing_exit``): FAIL ``engine:file_listing_failed`` on ``__global__``, the per-directory
        FAILs above, and both layers ``skipped:file listing failed (find exit N)``; the files that WERE listed are still scanned (bash E24);
      * else ``scan.nothing_scanned`` (the flag of ``files_for_scan``, NOT the test "no entries and a pattern removed something", which cannot see that the
        only entry left is the repository's own ``.transitignore``, and which diff mode and the empty directories make wrong): FAIL ``engine:nothing_scanned``
        on ``__global__`` (no detail segment, golden ``transitignore_everything``) and both layers ``skipped:nothing scanned (every file excluded)``.
    Both are non-downgradable. Neither the loop nor the scanners are skipped for them: whatever could be examined is."""
    policy = search_policy(env.cfg)
    env.console.info("=== Layer 5: Per-type SAST ===")
    _report_links(env, scan)
    listing_failed = bool(scan.errors) or scan.listing_exit != 0
    skipped: "str | None" = None
    if listing_failed:
        _report_unlistable(env, scan)
        skipped = "skipped:file listing failed (find exit %d)" % (scan.listing_exit or 1)
    elif scan.nothing_scanned:
        env.console.warn(".transitignore removed every file from the scan (%d pattern(s)): nothing was examined" % len(env.exclusions.patterns))
        env.verdict.record_fail(GLOBAL_FILE, "engine:nothing_scanned", downgradable=False)
        for layer in ("L4_patterns", "L5_per_language_sast"):
            env.verdict.note_incomplete(layer, _NOTHING_SCANNED_NOTE)
        skipped = "skipped:nothing scanned (every file excluded)"
    total = len(scan.entries)
    counts = {"scanned": 0, "vanished": 0, "unreadable": 0}
    for index, entry in enumerate(scan.entries, 1):
        env.console.progress(index, total, entry.rel)
        counts[_scan_file(env, entry.rel, entry.size, policy, universal, dispatch_file)] += 1
    env.console.clear_progress()
    env.console.ok("Layer 5: %d files scanned" % counts["scanned"])
    if skipped is not None:
        env.verdict.record_layer("L4_patterns", skipped)
        env.verdict.record_layer("L5_per_language_sast", skipped)
    else:
        env.verdict.record_layer("L4_patterns", "ran")
        env.verdict.record_layer("L5_per_language_sast", "ran")
    return FileLayerSummary(scanned=counts["scanned"], vanished=counts["vanished"], unreadable=counts["unreadable"])


def finalise(env: RunEnv) -> None:
    """After the last layer: one WARN ``engine:scanner_load_error:<module>`` per ``Registry.load_errors`` entry and one
    ``engine:wrapper_load_error:<module>`` per ``WrapperSet.load_errors`` entry, each with ``note_incomplete`` on
    ``L5_per_language_sast`` (``scanner module failed to load``). Nothing else: the other incomplete notes are recorded where the
    gap is found."""
    for entry in env.registry.load_errors:
        env.verdict.record_warn(GLOBAL_FILE, "engine:scanner_load_error:" + entry)
        env.verdict.note_incomplete("L5_per_language_sast", _LOAD_ERROR_NOTE)
    for entry in env.wrappers.load_errors:
        env.verdict.record_warn(GLOBAL_FILE, "engine:wrapper_load_error:" + entry)
        env.verdict.note_incomplete("L5_per_language_sast", _LOAD_ERROR_NOTE)


def run_all(env: RunEnv, scan: ScanList) -> FileLayerSummary:
    """The order of ``scan_pipeline.sh``'s main block: layer 1, layer 2, layer 3, layers 4 and 5, layer 6, ``finalise``."""
    from transit.scanners import universal                  # here and not at import time: a broken layer-4 module is then an internal error of the run
    run_layer1(env)
    run_layer2(env)
    run_layer3(env)
    summary = run_file_layers(env, scan, universal=universal.scan, dispatch_file=classify_file)
    run_layer6(env)
    finalise(env)
    return summary
