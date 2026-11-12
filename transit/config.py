"""Run configuration: every environment variable the engine reads (contract section 2), parsed once.

Owner of: contract 2 (environment), the constant tables other modules share (excluded directories, coverage
layer ids, the ``standards`` list), the divergence switches (docs/engine_divergences.md) and the engine's own
resource limits.

Layering: a LEAF module. It imports nothing from ``transit`` and performs no I/O at import time. ``load_config``
reads only the mapping it is given (never ``os.environ`` directly), so a test can pass a plain dict.

Divergence switches. Every ``proposed`` entry of docs/engine_divergences.md means "copy bash until decided".
The entries that touch the machinery are therefore named switches in ``KNOWN_FIXES``, all OFF by default, enabled
for testing with ``TRANSIT_FIXES=D-003,D-012``. Code asks ``cfg.fix("D-012")``; nothing else ever changes
behaviour between the two engines. Three behaviours are deliberately NOT switchable because the contract makes
them a MUST: S1/D-017 (bidi controls are replaced on the console, control bytes are escaped in the HTML), D-019
(a relative scan directory is compared by absolute path in diff mode, because copying bash there passes a
repository with nothing examined) and D-028 (an internal error writes a FAIL verdict, never a PASS).
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Mapping

ENGINE_NAME = "python"
ENGINE_VERSION = "0.1.0"
MIN_PYTHON = (3, 10)
DEFAULT_WORK_DIR = "/opt/ai-transit"

#: Contract 8.2: pruned when they are DIRECTORIES below the scan root (D-001/D-002 are closed: ancestors of the
#: scan root and regular files with these names are not affected).
DEFAULT_EXCLUDE_DIRS: tuple[str, ...] = (
    "node_modules", ".git", "vendor", ".tox", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", ".cache", "target", "coverage",
)

#: MIN_SEVERITY word -> threshold (contract 6.3). Anything else is 3 (``high``).
SEVERITY_THRESHOLDS: Mapping[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

#: Contract 7. The seven ids a report always carries (docs/report.schema.json ``required``) ...
COVERAGE_REQUIRED: tuple[str, ...] = (
    "L1_secrets_gitleaks", "L1_secrets_entropy", "L1_malware", "L2_owasp_cwe",
    "L3_dependency_cve", "L4_patterns", "L5_per_language_sast",
)
#: ... and the two that may be absent (bash records L1_ioc_yara only when skipped, L6_licence unless ScanCode failed).
COVERAGE_OPTIONAL: tuple[str, ...] = ("L1_ioc_yara", "L6_licence")
COVERAGE_LAYERS: tuple[str, ...] = tuple(sorted(COVERAGE_REQUIRED + COVERAGE_OPTIONAL))

#: Contract 4 ``standards``: three heads, SCA-CVE if RUN_SCA, ScanCode-Licence-Copyright if RUN_SCANCODE, twelve tails.
STANDARDS_HEAD: tuple[str, ...] = ("OWASP-Top10-2021", "CWE-Top25", "CERT-Secure-Coding")
STANDARDS_TAIL: tuple[str, ...] = (
    "PDF-Active-Content", "Build-Script-Hardening", "HTML-Active-Content", "XML-Build-Hardening",
    "Package-Manifest-Integrity", "Gradle-Build-Hardening", "Install-Time-Python", "Known-Credential-Formats",
    "PowerShell-Hardening", "Windows-Batch-Hardening", "Java-Archive-Hardening", "Office-Document-Hardening",
)

#: Switchable divergences (see the module docstring). D-029 and D-031 are new entries proposed by
#: docs/python_engine_design.md section 12 (D-029: ``excl`` rules go blind on a file holding a NUL byte; D-031: a
#: shebang line with arguments, ``#!/bin/bash -e``, is not routed to the shell scanner).
KNOWN_FIXES: frozenset[str] = frozenset(
    {"D-003", "D-004", "D-009", "D-010", "D-011", "D-012", "D-014", "D-029", "D-031"})

EXIT_PASS = 0
EXIT_FAIL = 1


@dataclasses.dataclass(frozen=True)
class Limits:
    """The engine's own resource limits. None of them exists in bash; every one is REPORTED when reached (the per-file
    budget as a WARN plus a ``partial:`` coverage state, the file-size cap as a FAIL), never silent.

    Environment overrides (a number that does not parse or is not above 0 means the default, as for ``JAR_*``):
    ``TRANSIT_RULE_BUDGET_S``, ``TRANSIT_FILE_BUDGET_S``, ``TRANSIT_LONG_LINE_BYTES``, ``TRANSIT_MAX_FILE_MB``,
    ``TRANSIT_TOOL_TIMEOUT_S``, ``TRANSIT_HELPER_TIMEOUT_S``.
    """
    #: Seconds a backtracking search may run before ``rx`` finishes the buffer with its linear matcher.
    rule_budget_s: float = 0.25
    #: Cooperative wall-clock budget for ALL rules of ONE file (checked between rules, never by SIGALRM).
    file_budget_s: float = 120.0
    #: A buffer holding a line longer than this goes straight to the linear matcher (see design section 9.2).
    long_line_bytes: int = 8192
    #: Largest file the engine reads into memory. A larger file is not skipped: ``FileView.data`` raises
    #: ``FileReadError('too_large')`` and the file gets the non-downgradable FAIL ``engine:file_unreadable:too_large``.
    max_file_bytes: int = 1 << 30
    #: Default timeout for an external scanner process.
    tool_timeout_s: float = 1800.0
    #: Default timeout for one of the stdlib helper scripts (jar/office also arm their own alarm).
    helper_timeout_s: float = 300.0


@dataclasses.dataclass(frozen=True)
class Notice:
    """A message found while parsing the environment, printed by the pipeline once the console exists.
    Notices are console-only; they are never recorded in the report (contract 2: OFFLINE, D-020, D-025)."""
    level: str  # "warn" | "info"
    text: str


@dataclasses.dataclass(frozen=True)
class Config:
    """Immutable view of the run's configuration. Built only by ``load_config``.

    ``min_severity`` is the text exactly as given (default ``high``): it is printed verbatim inside the
    ``LOW_SEV(below --min-severity <value>)`` message (contract 5.1), while ``sev_threshold`` is the number.
    """
    environ: Mapping[str, str]
    work_dir: str
    verbosity: str            # "quiet" | "normal" ("verbose" and anything else are "normal", contract 2)
    min_severity: str
    sev_threshold: int
    since_commit: str
    run_sca: bool
    run_scancode: bool
    offline_cache: str
    semgrep_rules_dir: str
    trivy_cache_dir: str
    clamav_db_dir: str
    repo_input: str
    tmpdir: str
    timestamp: str            # local %Y%m%d_%H%M%S at start: the default report name and the default scan_name
    limits: Limits
    fixes: frozenset[str]
    notices: tuple[Notice, ...]

    def fix(self, fix_id: str) -> bool:
        """True if the divergence switch ``fix_id`` (a member of ``KNOWN_FIXES``) is enabled."""
        raise NotImplementedError


def load_config(environ: Mapping[str, str], *, now: _dt.datetime | None = None) -> Config:
    """Parse ``environ`` into a ``Config`` (contract 2).

    Rules, all taken from the table in contract section 2:
      * ``WORK_DIR`` default ``/opt/ai-transit``; ``OFFLINE_CACHE`` default ``$WORK_DIR/offline-cache``; the three
        staged-data directories default under it; empty values mean "unset" (bash ``${X:-default}``).
      * ``MIN_SEVERITY``: lower-cased and looked up in ``SEVERITY_THRESHOLDS``; any other value, an empty value and
        a value with surrounding spaces mean 3 (E15). A Notice names a rejected non-empty value (D-020, copy + warn).
      * ``VERBOSITY``: only ``quiet`` has an effect; a value outside quiet/normal/verbose gets a Notice (D-020).
      * ``OFFLINE``: not a switch. A value other than ``true`` yields the Notice
        ``OFFLINE=<v> ignored: scan_pipeline.sh has no online mode`` (golden ``offline_false_ignored``, D-025).
      * ``RUN_SCA`` / ``RUN_SCANCODE``: true only for the exact string ``true`` (case-sensitive).
      * ``TRANSIT_FIXES``: comma-separated ``KNOWN_FIXES`` members. An unknown id raises ``ValueError`` (a typo
        must not silently disable a fix). ``TRANSIT_*`` limits: see ``Limits``.
      * ``now`` is only for tests; ``timestamp`` is its local ``%Y%m%d_%H%M%S``.
    Raises ``ValueError`` for an unknown ``TRANSIT_FIXES`` id. Never reads the file system and never writes.
    """
    raise NotImplementedError


def env_number(environ: Mapping[str, str], name: str, default: float) -> float:
    """The ``JAR_*``/``OFFICE_*`` knob rule (contract 2): parse as float; not a number or not above 0 means ``default``."""
    raise NotImplementedError
