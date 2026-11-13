"""Reports and sidecars: the JSON report, the HTML report, the two sidecar files (contract 3.3, 3.4, 4).

Owner of: contract 3.3 (``.scan_verdict`` / ``.scan_report_json``), 3.4 (report paths, atomic write, HTML content), 4 (every key
of the JSON report and its invariants), 3.6 (what ``ai_transit.sh`` and ``generate_excel_report.py`` read), S3 (HTML is
escaped), S4 (the JSON is always valid), S5 (the report appears whole or not at all), D-009 (``file_results`` message strip),
D-017 (control bytes escaped in the HTML), D-024 (sorted output), D-040 (stale sidecars removed).

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
import json
import os
import tempfile
import types
from typing import Mapping

from transit.cli import Args
from transit.config import STANDARDS_HEAD, STANDARDS_TAIL, Config
from transit.console import BIDI_CONTROLS
from transit.files import SourceHashes
from transit.findings import json_safe
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
    name = args.scanning_name or cfg.timestamp
    if args.report_dir:
        stem = "%s/report_scan_%s" % (args.report_dir, name)
    else:
        stem = "%s/reports/report_%s" % (cfg.work_dir, cfg.timestamp)
    # Built as bash builds it ("${REPORT_DIR}/report_scan_${NAME}", "${WORK_DIR}/.scan_verdict"): the sidecar names the path "as constructed".
    return ReportPaths(json=stem + ".json", html=stem + ".html", scan_name=name,
                       verdict_sidecar=cfg.work_dir + "/.scan_verdict", report_sidecar=cfg.work_dir + "/.scan_report_json")


#: The bash writer's ``m.rstrip(" | ")``: a CHARACTER SET (space and pipe), not a suffix (D-009, copied).
_SEPARATOR_CHARS = " | "
_SEPARATOR = " | "
#: Worst status wins when two names collapse to one key (D-045).
_STATUS_RANK = {"PASS": 0, "WARN": 1, "FAIL": 2}


def _strip_one_separator(accumulated: str) -> str:
    """Exactly one trailing `` | `` (bash ``${VAR%' | '}``); the D-009 behaviour for ``file_results``, and what ``findings_by_file`` always does."""
    return accumulated[:-len(_SEPARATOR)] if accumulated.endswith(_SEPARATOR) else accumulated


def _json_safe_value(value):
    """``findings.json_safe`` on every string of a JSON-like value (S4)."""
    if isinstance(value, str):
        return json_safe(value)
    if isinstance(value, Mapping):
        return {json_safe(key) if isinstance(key, str) else key: _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe_value(item) for item in value]
    return value


def _utc_text(now_utc: _dt.datetime) -> str:
    """``%Y-%m-%dT%H:%M:%SZ`` in UTC; a naive value is taken as UTC already, an aware one is converted."""
    if now_utc.tzinfo is not None:
        now_utc = now_utc.astimezone(_dt.timezone.utc)
    return now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def standards(run_sca: bool, run_scancode: bool) -> list[str]:
    """Contract 4 ``standards``: ``STANDARDS_HEAD``, ``SCA-CVE`` if ``run_sca``, ``ScanCode-Licence-Copyright`` if ``run_scancode``,
    then ``STANDARDS_TAIL``."""
    result = list(STANDARDS_HEAD)
    if run_sca:
        result.append("SCA-CVE")
    if run_scancode:
        result.append("ScanCode-Licence-Copyright")
    result.extend(STANDARDS_TAIL)
    return result


def message_for_file_results(accumulated: str) -> str:
    """D-009 (copied): ``accumulated.rstrip(" | ")``, a CHARACTER-SET strip of trailing spaces and pipes, as the bash writer does.
    With switch ``D-009`` exactly one trailing ``" | "`` is removed."""
    return accumulated.rstrip(_SEPARATOR_CHARS)


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
    tests/conformance/check_schema.py.

    COLLISIONS (review log R-12, D-023/D-045). Two different non-UTF-8 names can map to the same key after ``json_safe``. The entries are
    MERGED, never overwritten, whatever order a dict comprehension would visit them in: ``file_results`` takes the worst status
    (FAIL > WARN > PASS) and the accumulated messages of both in snapshot order (``a`` then ``b``, before the D-009 strip);
    ``findings_by_file`` joins the FAIL messages the same way; ``findings`` keeps every record. Counters are event counters and do
    not change. Without the merge a clean ``x<0xFF>.py`` could overwrite the FAIL entry of ``x<0xFE>.py`` and the report would violate
    the checker's invariant "every ``findings_by_file`` key is a FAIL file"."""
    verdict = snapshot.verdict
    approved = verdict == "PASS"

    # file_results: keyed by the json_safe name; two names that collapse to one key are MERGED (worst status, both messages, snapshot order).
    merged_status: dict = {}
    merged_message: dict = {}
    for path, status in snapshot.file_status.items():
        key = json_safe(path)
        message = snapshot.file_message.get(path, "")
        if key in merged_status:
            if _STATUS_RANK.get(status, -1) > _STATUS_RANK.get(merged_status[key], -1):
                merged_status[key] = status
            merged_message[key] += message
        else:
            merged_status[key] = status
            merged_message[key] = message
    strip = _strip_one_separator if fix_d009 else message_for_file_results
    file_results = {key: {"message": json_safe(strip(merged_message[key])), "status": json_safe(merged_status[key])}
                    for key in sorted(merged_status)}

    # findings_by_file: the FAIL messages of the file, one trailing separator removed (bash ${FINDINGS[$path]%' | '}); merged the same way.
    merged_fail: dict = {}
    for path, accumulated in snapshot.fail_messages.items():
        key = json_safe(path)
        merged_fail[key] = merged_fail.get(key, "") + accumulated
    findings_by_file = {key: json_safe(_strip_one_separator(merged_fail[key])) for key in sorted(merged_fail)}

    records = [_json_safe_value(record.to_json()) for record in snapshot.findings]
    records.sort(key=lambda r: (r["file"], r["rule_id"], r["line"] or 0, r["message"]))

    coverage = {json_safe(layer): json_safe(state) for layer, state in sorted(snapshot.coverage.items())}
    gaps = sorted(layer for layer, state in coverage.items() if not state.startswith("ran"))
    directory = json_safe(args.scan_dir)
    counters = snapshot.counters

    result = {
        "verdict": json_safe(verdict),
        "decision": "APPROVED" if approved else "REJECTED",
        "status_color": "#198754" if approved else "#B02A37",
        "status_background": "#D1E7DD" if approved else "#F8D7DA",
        "scan_name": json_safe(scan_name),
        "source": {"directory": directory, "sha256": json_safe(source.sha256)},
        "coverage": coverage,
        "coverage_complete": not gaps,
        "coverage_gaps": gaps,
        "timestamp": _utc_text(now_utc),
        "repo_input": json_safe(repo_input),
        "directory": directory,
        "repo_hash": json_safe(source.repo_hash),
        "standards": [json_safe(item) for item in standards(run_sca, run_scancode)],
        "summary": {"fail": counters.fail, "pass": counters.pass_, "warn": counters.warn},
        "findings": records,
        "findings_by_file": findings_by_file,
        "file_results": file_results,
    }
    return dict(sorted(result.items()))


def _html_table() -> Mapping[int, str]:
    """Code point -> replacement for ``str.translate`` (one pass, so an ``&`` written by an earlier replacement is never escaped again)."""
    table: dict = {ord("&"): "&amp;", ord("<"): "&lt;", ord(">"): "&gt;", ord('"'): "&quot;", ord("'"): "&#39;"}
    for code in list(range(0x20)) + [0x7F] + list(range(0x80, 0xA0)):     # C0 (TAB and LF included), DEL, C1
        table[code] = "&#x%02X;" % code
    for char in BIDI_CONTROLS:                                            # review log R-14: the set is console's, not a copy
        table[ord(char)] = "&#x%04X;" % ord(char)
    for code in range(0xD800, 0xE000):                                    # an undecodable byte left by os.fsdecode
        table[code] = "\ufffd"
    return types.MappingProxyType(table)


_HTML_TABLE = _html_table()
#: The three status classes of the file table; anything else (a status the engine never writes) is shown as a warning.
_STATUS_CLASS = {"PASS": "pass", "WARN": "warn", "FAIL": "fail"}
#: Inline style only: the page has no script and loads nothing. ``@COLOUR@`` is replaced by one of two fixed colours.
_STYLE = """<style>
body{background:#0d1b2a;color:#eee;font-family:monospace;padding:2rem;max-width:1400px;margin:0 auto}
h1{color:@COLOUR@} h2{color:#00a8ff}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th{background:#1f3864;padding:.6rem;text-align:left}
td{border:1px solid #334;padding:.5rem;vertical-align:top}
tr:nth-child(even){background:#16213e}
.pass{color:#2ecc71;font-weight:bold} .fail{color:#e74c3c;font-weight:bold} .warn{color:#f39c12;font-weight:bold}
.tag{background:#1f3864;border-radius:4px;padding:2px 6px;font-size:.85em;margin:1px;display:inline-block}
</style>
"""


def _as_mapping(value) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def html_escape(text: str) -> str:
    """S3 / D-017: ``&`` first, then ``<``, ``>``, ``"``, ``'`` (as ``&#39;``); then every C0 control (TAB and LF included), DEL, every C1
    control and every character of ``console.BIDI_CONTROLS`` (U+202A-U+202E, U+2066-U+2069, U+061C, U+200E, U+200F) is written as a
    numeric character reference (``&#xNN;`` / ``&#xNNNN;``); lone surrogates become U+FFFD. The bidi characters matter here more than on
    the console: the HTML report is the reviewer's main view, and an override in a file name reorders the displayed path of the flagged
    file (review log R-14)."""
    if not isinstance(text, str):
        text = bytes(text).decode("utf-8", "surrogateescape") if isinstance(text, (bytes, bytearray, memoryview)) else str(text)
    return str.translate(text, _HTML_TABLE)


def render_html(report: dict, *, timestamp_local: str) -> str:
    """The HTML report (contract 3.4): title ``AI Transit Report - <timestamp_local>``, ``<h1>Verdict: <V></h1>``, the escaped
    directory, the three counters, a coverage table (new, allowed), and one row for EVERY ``file_results`` entry with path,
    status class (``pass``/``warn``/``fail``) and message. Every interpolated value goes through ``html_escape``. No
    script, no external resource."""
    esc = html_escape
    verdict = report.get("verdict", "")
    directory = report.get("directory")
    if directory is None:
        directory = _as_mapping(report.get("source")).get("directory", "")
    summary = _as_mapping(report.get("summary"))
    colour = "#2ecc71" if verdict == "PASS" else "#e74c3c"        # chosen here: nothing from the report is ever written into the style sheet
    ts = esc(timestamp_local)

    out = ["<!DOCTYPE html>\n", '<html lang="en"><head><meta charset="utf-8">\n',
           "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n",
           "<title>AI Transit Report - %s</title>\n" % ts, _STYLE.replace("@COLOUR@", colour), "</head><body>\n",
           "<h1>Verdict: %s</h1>\n" % esc(verdict),
           "<p>Directory: <code>%s</code> | Date: %s</p>\n" % (esc(directory), ts)]

    standards_list = report.get("standards")
    if isinstance(standards_list, (list, tuple)) and standards_list:
        out.append("<p>Standards: %s</p>\n" % " ".join('<span class="tag">%s</span>' % esc(item) for item in standards_list))

    out.append('<p>PASS: <span class="pass">%s</span> | WARN: <span class="warn">%s</span> | FAIL: <span class="fail">%s</span></p>\n'
               % tuple(esc(summary.get(name, "?")) for name in ("pass", "warn", "fail")))

    out.append("<h2>Coverage</h2>\n<table><tr><th>Layer</th><th>State</th></tr>\n")
    for layer, state in _as_mapping(report.get("coverage")).items():
        state_text = state if isinstance(state, str) else str(state)
        out.append('<tr><td><code>%s</code></td><td class="%s">%s</td></tr>\n'
                   % (esc(layer), "pass" if state_text.startswith("ran") else "warn", esc(state_text)))
    out.append("</table>\n")

    out.append("<h2>Results by file</h2>\n<table><tr><th>File</th><th>Status</th><th>Finding</th></tr>\n")
    for path, entry in _as_mapping(report.get("file_results")).items():
        entry = _as_mapping(entry)
        status = entry.get("status", "")
        status_text = status if isinstance(status, str) else str(status)
        out.append('<tr><td><code>%s</code></td><td class="%s">%s</td><td>%s</td></tr>\n'
                   % (esc(path), _STATUS_CLASS.get(status_text, "warn"), esc(status_text), esc(entry.get("message", ""))))
    out.append("</table></body></html>\n")
    return "".join(out)


def _write_all(fd: int, data) -> None:
    view = memoryview(data)
    while len(view):
        written = os.write(fd, view)
        view = view[written:]


def _sync_directory(directory: str) -> None:
    """Make the rename durable. Best effort: the report is already in place, so a failure here is not an error."""
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def write_atomic(path: str, data: bytes, *, mode: int = 0o666) -> None:
    """S5. Write ``data`` to a new file in the same directory (``mkstemp``, so an unpredictable name and mode 0600 first), set the
    mode to ``mode & ~umask``, ``fsync``, ``os.replace`` over ``path``. On any error remove the temporary file and re-raise; no
    truncated ``path`` ever exists. Replaces an existing file without a message (D-021 copied)."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("write_atomic needs bytes, not %s" % type(data).__name__)
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".transit_", suffix=".tmp", dir=directory)       # private (0600) and unpredictable
    try:
        try:
            mask = os.umask(0)
            os.umask(mask)
            os.fchmod(fd, mode & ~mask)
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _sync_directory(directory)


def write_reports(report: dict, paths: ReportPaths, *, timestamp_local: str) -> None:
    """JSON first (``json.dumps(..., ensure_ascii=False, indent=2)`` + LF, UTF-8, strict), then HTML, each through ``write_atomic``."""
    # Both are encoded and rendered BEFORE the first file is touched: an encoding error (strict UTF-8) leaves no report at all.
    json_bytes = (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    html_bytes = render_html(report, timestamp_local=timestamp_local).encode("utf-8")
    write_atomic(paths.json, json_bytes)
    write_atomic(paths.html, html_bytes)


def _overwrite_in_place(path: str, content: bytes) -> None:
    """The last resort of ``clear_sidecars``: truncate and rewrite an existing file that could not be removed (a directory that
    forbids unlinking may still allow the file to be written). Never follows a symbolic link; raises ``OSError`` when it cannot."""
    flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:           # it disappeared in the meantime: nothing stale is left
        return
    try:
        _write_all(fd, content)
        os.fsync(fd)
    finally:
        os.close(fd)


def clear_sidecars(paths: ReportPaths) -> None:
    """D-040, pipeline step 5. Remove ``.scan_verdict`` and ``.scan_report_json`` (a missing file is fine). The bash engine leaves the
    sidecars of an earlier run in place until the end, so a run that dies without reaching the end (an OOM kill, SIGKILL, a full disk)
    leaves the previous verdict, possibly PASS, for any caller that reads sidecars instead of checking the exit status. After this call
    the only way a sidecar exists is that THIS run wrote it. If a file cannot be removed (``OSError`` other than "does not exist"),
    ``.scan_verdict`` is overwritten with ``FAIL`` and ``.scan_report_json`` with an empty line; if even that fails the ``OSError`` is
    raised and ``pipeline`` aborts exactly as for a ``WORK_DIR`` that cannot be prepared (step 4). Never touches the reports."""
    for path, fallback in ((paths.verdict_sidecar, b"FAIL\n"), (paths.report_sidecar, b"\n")):
        try:
            os.remove(path)
        except FileNotFoundError:
            continue
        except OSError:
            _overwrite_in_place(path, fallback)


def write_sidecars(paths: ReportPaths, verdict: str) -> None:
    """Contract 3.3, in this order: ``.scan_verdict`` = ``PASS``/``FAIL`` + LF, then ``.scan_report_json`` = the JSON path as
    constructed + LF. Both in ``WORK_DIR``, both through ``write_atomic``. ``verdict`` other than PASS/FAIL raises ``ValueError``."""
    if not isinstance(verdict, str) or verdict not in ("PASS", "FAIL"):
        raise ValueError("verdict must be PASS or FAIL, not %r" % (verdict,))
    write_atomic(paths.verdict_sidecar, (verdict + "\n").encode("ascii"))
    write_atomic(paths.report_sidecar, os.fsencode(paths.json) + b"\n")
