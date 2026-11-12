"""Reports and sidecars: the JSON report, the HTML report, the two sidecar files (contract 3.3, 3.4, 4).

Owner of: contract 3.3 (``.scan_verdict`` / ``.scan_report_json``), 3.4 (report paths, atomic write, HTML content), 4 (every key
of the JSON report and its invariants), 3.6 (what ``ai_transit.sh`` and ``generate_excel_report.py`` read), S3 (HTML is
escaped), S4 (the JSON is always valid), S5 (the report appears whole or not at all), D-009 (``file_results`` message strip),
D-017 (control bytes escaped in the HTML), D-024 (sorted output).

Layering: depends on ``transit.config``, ``transit.cli`` (Args), ``transit.findings`` (``json_safe``), ``transit.verdict`` (Snapshot) and
``transit.files`` (SourceHashes). It computes nothing about files and records nothing.

``transit/report_json.py`` is the BASH engine's report writer: a program with top-level code that needs ``REPORT_*``
variables. It is NOT imported and NOT run by the Python engine; ``build_report`` is its pure-function equivalent, and
tests/engine/test_report.py compares the two on the same inputs (the old script run as a subprocess is the oracle until
the bash engine is retired).
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Mapping

from transit.cli import Args
from transit.config import Config
from transit.files import SourceHashes
from transit.verdict import Snapshot


@dataclasses.dataclass(frozen=True)
class ReportPaths:
    """Contract 3.4. ``json``/``html`` are ``<report_dir>/report_scan_<name>.json|html`` for a non-empty report directory and
    ``<WORK_DIR>/reports/report_<timestamp>.json|html`` otherwise (a relative ``report_dir`` stays relative). ``scan_name`` is
    the name stored in the report (the third argument, or the timestamp). ``verdict_sidecar`` / ``report_sidecar`` are in
    ``WORK_DIR``, never in the report directory (3.3)."""
    json: str
    html: str
    scan_name: str
    verdict_sidecar: str
    report_sidecar: str


def report_paths(args: Args, cfg: Config) -> ReportPaths:
    """Pure path arithmetic; creates nothing."""
    raise NotImplementedError


def standards(run_sca: bool, run_scancode: bool) -> list[str]:
    """Contract 4 ``standards``: ``STANDARDS_HEAD``, ``SCA-CVE`` if ``run_sca``, ``ScanCode-Licence-Copyright`` if ``run_scancode``,
    then ``STANDARDS_TAIL``."""
    raise NotImplementedError


def message_for_file_results(accumulated: str) -> str:
    """D-009 (copied): ``accumulated.rstrip(" | ")``, a CHARACTER-SET strip of trailing spaces and pipes, as the bash writer does.
    With switch ``D-009`` exactly one trailing ``" | "`` is removed."""
    raise NotImplementedError


def build_report(snapshot: Snapshot, source: SourceHashes, *, args: Args, scan_name: str, repo_input: str, run_sca: bool,
                 run_scancode: bool, now_utc: _dt.datetime, fix_d009: bool = False) -> dict:
    """The raw report of contract 4 as a ``dict``: ``verdict``; ``decision`` (APPROVED iff PASS) with ``status_color`` /
    ``status_background`` (``#198754``/``#D1E7DD`` PASS, ``#B02A37``/``#F8D7DA`` FAIL); ``scan_name``; ``source`` {directory,
    sha256}; ``coverage`` (the snapshot's states), ``coverage_complete`` (no gaps), ``coverage_gaps`` (sorted ids whose state does
    not start with ``ran``); ``timestamp`` (UTC, ``%Y-%m-%dT%H:%M:%SZ``); ``repo_input``; ``directory`` (= source.directory);
    ``repo_hash``; ``standards``; ``summary`` {pass, warn, fail} from the event counters; ``findings`` (records sorted by
    (file, rule_id, line or 0, message), each ``to_json()``); ``findings_by_file`` (path -> FAIL messages joined with `` | ``, one
    trailing separator removed); ``file_results`` (path -> {status, message}). Keys sorted. Every string goes through
    ``findings.json_safe`` (S4). The result satisfies docs/report.schema.json and every invariant of
    tests/conformance/check_schema.py."""
    raise NotImplementedError


def html_escape(text: str) -> str:
    """S3 / D-017: ``&`` first, then ``<``, ``>``, ``"``, ``'`` (as ``&#39;``); then every C0 control (TAB and LF included), DEL and every C1
    control is written as ``&#xNN;``; lone surrogates become U+FFFD."""
    raise NotImplementedError


def render_html(report: dict, *, timestamp_local: str) -> str:
    """The HTML report (contract 3.4): title ``AI Transit Report - <timestamp_local>``, ``<h1>Verdict: <V></h1>``, the escaped
    directory, the three counters, a coverage table (new, allowed), and one row for EVERY ``file_results`` entry with path,
    status class (``pass``/``warn``/``fail``) and message. Every interpolated value goes through ``html_escape``. No
    script, no external resource."""
    raise NotImplementedError


def write_atomic(path: str, data: bytes, *, mode: int = 0o666) -> None:
    """S5. Write ``data`` to a new file in the same directory (``mkstemp``, so an unpredictable name and mode 0600 first), set the
    mode to ``mode & ~umask``, ``fsync``, ``os.replace`` over ``path``. On any error remove the temporary file and re-raise; no
    truncated ``path`` ever exists. Replaces an existing file without a message (D-021 copied)."""
    raise NotImplementedError


def write_reports(report: dict, paths: ReportPaths, *, timestamp_local: str) -> None:
    """JSON first (``json.dumps(..., ensure_ascii=False, indent=2)`` + LF, UTF-8, strict), then HTML, each through ``write_atomic``."""
    raise NotImplementedError


def write_sidecars(paths: ReportPaths, verdict: str) -> None:
    """Contract 3.3, in this order: ``.scan_verdict`` = ``PASS``/``FAIL`` + LF, then ``.scan_report_json`` = the JSON path as
    constructed + LF. Both in ``WORK_DIR``, both through ``write_atomic``. ``verdict`` other than PASS/FAIL raises ``ValueError``."""
    raise NotImplementedError
