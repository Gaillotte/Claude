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
"""
from __future__ import annotations

import dataclasses
from typing import Callable

from transit.cli import Args
from transit.config import Config
from transit.console import Console
from transit.dispatch import RunScanner
from transit.files import DiffSelection, Exclusions, ScanList, TempArea
from transit.rules import SearchPolicy
from transit.scanners import Registry
from transit.tools import ToolLocator, ToolOutcome, WrapperSet
from transit.verdict import Verdict


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


def search_policy(cfg: Config) -> SearchPolicy:
    """The ONLY producer of a ``SearchPolicy``: ``SearchPolicy(rule_budget_s=cfg.limits.rule_budget_s, long_line_bytes=cfg.limits.long_line_bytes,
    excl_nul_blind=not cfg.fix("D-029"))``. ``run_file_layers`` calls it once per run and hands the result to every ``ScanContext`` (review
    log R-25: the stub had a consumer and no producer)."""
    raise NotImplementedError


def file_deadline(cfg: Config, size: int, *, now: float) -> float:
    """The ``time.monotonic()`` value after which the rules of ONE file may no longer start:
    ``now + limits.file_budget_s + limits.file_budget_s_per_mb * size / 2**20``, ``size`` being ``FileEntry.size``. Scaled with the size
    because the cost of the linear matcher is linear in it (about 38 ns per byte per rule, measured: a 20 MiB file with one long line
    costs 0.4 s per rule); a fixed 120 s could not cover the 512 MiB the engine accepts, and its expiry was a WARN that a hostile file
    could buy cheaply (review log R-02). Expiry is a FAIL (``ScanContext.run_rules``, ``scanners.invoke``)."""
    raise NotImplementedError


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
         in a parser into a PASS."""
    raise NotImplementedError


def run_layer1(env: RunEnv) -> None:
    """Layer 1 in bash order (gitleaks, detect-secrets, clamscan, yara): ``run_slot`` for each of ``LAYER1_SLOTS``."""
    raise NotImplementedError


def run_layer2(env: RunEnv) -> None:
    """Layer 2: ``run_slot`` for ``LAYER2_SLOTS``."""
    raise NotImplementedError


def run_layer3(env: RunEnv) -> None:
    """Layer 3. ``RUN_SCA`` not exactly ``true`` -> ``record_layer("L3_dependency_cve", LAYER3_DISABLED)`` and an info line.
    Otherwise ``run_slot`` for trivy, then the offline notes (D-026: pip-audit, safety and npm audit are not ported): if the
    first five paths matching ``requirements*.txt``, ``Pipfile.lock`` or ``pyproject.toml`` exist, the WARN
    ``OFFLINE:Python dependency CVE scan unavailable (pip-audit and safety both require a network advisory service) - rely on the
    staged trivy database for Python CVEs``; if the first three ``package-lock.json`` / ``yarn.lock`` exist, the WARN
    ``OFFLINE:JavaScript dependency CVE scan unavailable (npm audit requires the registry) - rely on the staged trivy database for
    JS CVEs`` (exact texts: ``scan_dependencies`` in the reference script; each has an em dash U+2014 where the lines above show a hyphen)."""
    raise NotImplementedError


def run_layer6(env: RunEnv) -> None:
    """Layer 6: ``RUN_SCANCODE`` not exactly ``true`` -> ``record_layer("L6_licence", LAYER6_DISABLED)``; otherwise ``run_slot`` for
    ``LAYER6_SLOTS`` (the wrapper adds the ``OFFLINE:scancode CVE lookup disabled ...`` WARN)."""
    raise NotImplementedError


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
      * if ``scan.entries`` is empty, ``scan.excluded_by_patterns`` > 0 and ``env.diff.active`` is False: the non-downgradable FAIL
        ``engine:nothing_scanned:transitignore`` on ``env.scan_dir`` plus ``note_incomplete`` on both layers: the repository's own
        ``.transitignore`` removed everything and nothing was examined (review log R-03; golden ``diff_mode_zero_files`` is unaffected,
        diff mode is active there).
    ``universal`` and ``dispatch_file`` are parameters only so that tests can inject fakes;
    ``pipeline`` passes ``transit.scanners.universal.scan`` and ``transit.dispatch.classify_file``."""
    raise NotImplementedError


def finalise(env: RunEnv) -> None:
    """After the last layer: one WARN ``engine:scanner_load_error:<module>`` per ``Registry.load_errors`` entry and one
    ``engine:wrapper_load_error:<module>`` per ``WrapperSet.load_errors`` entry, each with ``note_incomplete`` on
    ``L5_per_language_sast`` (``scanner module failed to load``). Nothing else: the other incomplete notes are recorded where the
    gap is found."""
    raise NotImplementedError


def run_all(env: RunEnv, scan: ScanList) -> FileLayerSummary:
    """The order of ``scan_pipeline.sh``'s main block: layer 1, layer 2, layer 3, layers 4 and 5, layer 6, ``finalise``."""
    raise NotImplementedError
