#!/usr/bin/env python3
"""Run the bash engine and the Python engine on the fixtures of some scanners and print what differs, file by file.

    python3 tests/conformance/family_diff.py shell python               # scanner ids
    python3 tests/conformance/family_diff.py manifest powershell        # family keys: every id of the family
    python3 tests/conformance/family_diff.py --list batch               # which fixtures are routed to it; runs no engine
    python3 tests/conformance/family_diff.py --engines bash makefile    # one engine only: print its per-file results
    python3 tests/conformance/family_diff.py --fixtures DIR [--fixtures DIR2] ids...

This is the acceptance tool of every scanner package of Waves 2 and 3 (docs/python_engine_design.md section 14.2, item 2: "reports no
difference in per-file status and rule ids against bash on tests/fixtures/rules"). It is the narrow version of ``conformance.py diff``: that
runs whole cases for a minute and compares the whole report; this one copies only the fixtures that ``transit.dispatch`` routes to the ids
you name into a scratch directory (keeping their relative paths, because ``composer.json`` and ``Makefile`` are routed by basename), runs
both engines on it with the same environment, and compares per file:

  * the status (PASS, WARN, FAIL);
  * the messages ("rule ids": ``[FAIL] CWE-78:OS_command_injection_risk``, ``[WARN] bandit missing``), as a set, so the order of the
    events of one file does not matter (contract section 10);
  * the ``rule_id`` of every finding record of the file.

The ``__global__`` entry (a missing tool, a skipped layer) and the coverage block are NOT compared: they are the business of
``conformance.py``. A scanner the Python engine has not ported yet shows up as ``engine:scanner_not_ported:<id>`` on its files (D-032); the
tool says so at the end instead of hiding the difference.

Exit status: 0 no difference, 1 differences, 2 usage error or an engine that produced no report. Standard library only; Python 3.10 or
newer. Everything the fixtures say is repository text: it is made printable before it is written to the terminal.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping, Sequence, TextIO

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: How each engine is started: ``<cmd> <scan dir> <report dir> <scanning name>`` with ``WORK_DIR`` in the environment (as ``conformance.py``).
ENGINES: "dict[str, list[str]]" = {
    "bash": ["bash", str(ROOT / "scan_pipeline.sh")],
    "python": [sys.executable, "-I", str(ROOT / "scan_pipeline.py")],
}
DEFAULT_FIXTURES = (ROOT / "tests" / "fixtures" / "rules",)
SCAN_NAME = "family"
#: Fixture files that are not fixtures.
_SKIPPED_NAMES = frozenset({"__pycache__", ".DS_Store"})


class UsageError(Exception):
    """A request that cannot be served (an unknown id, a missing directory): exit status 2 with the message."""


@dataclasses.dataclass(frozen=True)
class FileRow:
    """What one engine said about one file."""
    status: str
    messages: "tuple[str, ...]"      # ``[FAIL] text`` / ``[WARN] text``, sorted, duplicates kept
    rule_ids: "tuple[str, ...]"      # ``rule_id`` of the finding records of the file, sorted, duplicates kept


@dataclasses.dataclass(frozen=True)
class EngineRun:
    name: str
    exit_status: int
    last_line: str
    report: "dict | None"
    stderr_tail: str


@dataclasses.dataclass(frozen=True)
class Difference:
    """One disagreement: ``kind`` is ``only in <engine>``, ``status``, ``messages`` or ``rule ids``."""
    file: str
    kind: str
    left: str
    right: str


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# printable output
# ═══════════════════════════════════════════════════════════════════════════════════════════════
#: The bidirectional format controls (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069); written as numbers so that this file holds none.
_BIDI_CONTROLS = frozenset(chr(code) for code in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)))


def printable(text: object, limit: int = 300) -> str:
    """Repository text made safe for a terminal: every control character, DEL and C1 byte, the bidi controls and anything that does not
    encode becomes ``?``; long text is cut."""
    out = []
    for ch in str(text)[:limit]:
        code = ord(ch)
        if code < 0x20 or 0x7F <= code <= 0x9F or ch in _BIDI_CONTROLS or 0xD800 <= code <= 0xDFFF:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out) + ("..." if len(str(text)) > limit else "")


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# which fixture goes to which scanner
# ═══════════════════════════════════════════════════════════════════════════════════════════════
def known_scanners() -> "dict[str, str]":
    """Scanner id -> family key, from the registry of the Python engine (``transit.scanners.KNOWN_SCANNERS``)."""
    from transit.scanners import KNOWN_SCANNERS
    return dict(KNOWN_SCANNERS)


def resolve_ids(words: "Sequence[str]", scanners: "Mapping[str, str]") -> "list[str]":
    """Scanner ids named by ``words``: an id as it is, or a family key standing for every id of the family. An unknown word is an error that
    lists the known ones. The result keeps the order of ``words``, without duplicates."""
    families: "dict[str, list[str]]" = {}
    for scanner_id, family in scanners.items():
        families.setdefault(family, []).append(scanner_id)
    chosen: "list[str]" = []
    unknown: "list[str]" = []
    for word in words:
        if word in scanners:
            found = [word]
        elif word in families:
            found = sorted(families[word])
        else:
            unknown.append(word)
            continue
        chosen.extend(i for i in found if i not in chosen)
    if unknown:
        raise UsageError("unknown scanner id or family: %s\nscanner ids: %s\nfamilies: %s" % (
            ", ".join(printable(w, 60) for w in unknown), ", ".join(sorted(scanners)), ", ".join(sorted(families))))
    if not chosen:
        raise UsageError("name at least one scanner id or family; known ids: %s" % ", ".join(sorted(scanners)))
    return chosen


def routed_ids(scan_dir: Path, rel: str) -> "set[str]":
    """The scanner ids the Python engine's dispatch would call for ``scan_dir/rel`` (``transit.dispatch.classify_file`` with a recording
    callback). A scanner that is asked to sniff (``rtf``, ``ooxml``) may answer False and let the next one run, so the file is classified twice,
    once with every sniffing scanner answering True and once with each answering False, and the ids are united. A file the dispatch sends to
    ``unknown`` is also routed to the scanner its shebang names (the hardened rule: the interpreter word decides, D-031)."""
    from transit import dispatch
    from transit.config import Limits
    from transit.files import FileReadError, FileView

    found: "set[str]" = set()
    view = FileView(str(scan_dir), rel, Limits())
    for sniffed_answer in (True, False):
        def run(scanner_id: str, sniffed: bool, _answer: bool = sniffed_answer) -> bool:
            found.add(scanner_id)
            return _answer if sniffed else True
        try:
            dispatch.classify_file(view, run)
        except FileReadError:
            return set()
    if "unknown" in found:
        try:
            delegated = dispatch.shebang_scanner(view.first_line(), first_word_only=True)
        except FileReadError:
            delegated = None
        if delegated:
            found.add(delegated)
    return found


def list_files(directory: Path) -> "list[str]":
    """Every regular file below ``directory`` (symlinks are not followed and not listed), relative POSIX paths, sorted."""
    found: "list[str]" = []
    for top, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in _SKIPPED_NAMES and not os.path.islink(os.path.join(top, d)))
        for name in files:
            full = os.path.join(top, name)
            if name in _SKIPPED_NAMES or name.endswith(".pyc") or os.path.islink(full) or not os.path.isfile(full):
                continue
            found.append(Path(os.path.relpath(full, directory)).as_posix())
    return sorted(found)


def select_fixtures(directories: "Sequence[Path]", ids: "Sequence[str]") -> "list[tuple[Path, str]]":
    """``(directory, relative path)`` of every file of ``directories`` that is routed to at least one of ``ids``."""
    wanted = set(ids)
    chosen: "list[tuple[Path, str]]" = []
    for directory in directories:
        for rel in list_files(directory):
            if routed_ids(directory, rel) & wanted:
                chosen.append((directory, rel))
    return chosen


def build_scratch(selection: "Sequence[tuple[Path, str]]", target: Path) -> "dict[str, str]":
    """Copy the selected files below ``target`` and return ``{path below target: <fixture directory name>/<relative path>}``. With one
    fixture directory the relative paths are kept as they are (a basename route needs them); with several, each goes under its directory's name
    so that two fixtures of the same name cannot collide."""
    many = len({directory for directory, _ in selection}) > 1
    origin: "dict[str, str]" = {}
    for directory, rel in selection:
        placed = "%s/%s" % (directory.name, rel) if many else rel
        destination = target / placed
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(directory / rel, destination)
        origin[placed] = "%s/%s" % (directory.name, rel)
    return origin


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# running an engine and reading its report
# ═══════════════════════════════════════════════════════════════════════════════════════════════
def run_engine(name: str, command: "Sequence[str]", scan: Path, reports: Path, work: Path, env: "Mapping[str, str]",
               timeout: float = 900.0) -> EngineRun:
    """``command <scan> <reports> family`` with ``WORK_DIR`` set; the JSON report is read back (None when there is none)."""
    environment = dict(os.environ, LC_ALL="C.UTF-8", WORK_DIR=str(work))
    environment.update(env)
    try:
        done = subprocess.run([*command, str(scan), str(reports), SCAN_NAME], env=environment, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return EngineRun(name, 124, "", None, "timed out after %d s" % timeout)
    except OSError as exc:
        return EngineRun(name, 127, "", None, "cannot start: %s" % type(exc).__name__)
    lines = done.stdout.decode("utf-8", "replace").strip().splitlines()
    found = sorted(reports.glob("report_scan_*.json"))
    report = None
    if found:
        try:
            parsed = json.loads(found[0].read_text(encoding="utf-8"))
            report = parsed if isinstance(parsed, dict) else None
        except (OSError, ValueError):
            report = None
    tail = done.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
    return EngineRun(name, done.returncode, lines[-1] if lines else "", report, " / ".join(tail))


def _relative(path: str, scan: Path) -> "str | None":
    """``path`` below the scanned directory (the engines write ``<scan>/<rel>``), or None when it is not below it."""
    for prefix in {str(scan).rstrip("/") + "/", os.path.realpath(scan).rstrip("/") + "/"}:
        if path.startswith(prefix):
            return path[len(prefix):]
    return None


def _split_messages(text: str) -> "list[str]":
    """``"[WARN] a | [FAIL] b | "`` -> ``["[WARN] a", "[FAIL] b"]`` (the separator is `` | ``; a message may itself hold a ``|``)."""
    parts: "list[str]" = []
    for piece in (text or "").split(" | "):
        piece = piece.strip()
        if piece.startswith(("[WARN]", "[FAIL]")) or not parts:
            if piece:
                parts.append(piece)
        elif piece:
            parts[-1] += " | " + piece
    return parts


def file_rows(report: "Mapping | None", scan: Path) -> "dict[str, FileRow]":
    """Per file of the report: status, messages and the rule ids of its finding records. ``__global__`` (a missing tool, a skipped layer)
    and anything else outside the scanned directory are left out."""
    rows: "dict[str, FileRow]" = {}
    if not report:
        return rows
    by_file: "dict[str, list[str]]" = {}
    for record in report.get("findings", []) or []:
        if not isinstance(record, dict):
            continue
        rel = _relative(str(record.get("file", "")), scan)
        if rel is not None:
            by_file.setdefault(rel, []).append(str(record.get("rule_id", "")))
    results = report.get("file_results", {}) or {}
    for key, value in results.items():
        if not isinstance(value, dict):
            continue
        rel = _relative(str(key), scan)            # ``__global__`` is not below the scanned directory: left out here
        if rel is None:
            continue
        rows[rel] = FileRow(status=str(value.get("status", "")), messages=tuple(sorted(_split_messages(str(value.get("message", ""))))),
                            rule_ids=tuple(sorted(by_file.get(rel, []))))
    return rows


def compare(left_name: str, left: "Mapping[str, FileRow]", right_name: str, right: "Mapping[str, FileRow]") -> "list[Difference]":
    """Every disagreement between two engines' rows, sorted by file."""
    found: "list[Difference]" = []
    for rel in sorted(set(left) | set(right)):
        a, b = left.get(rel), right.get(rel)
        if a is None or b is None:
            only = left_name if a is not None else right_name
            row = a or b
            assert row is not None
            found.append(Difference(rel, "only in " + only, "%s %s" % (row.status, "; ".join(row.messages)), ""))
            continue
        if a.status != b.status:
            found.append(Difference(rel, "status", a.status, b.status))
        if a.messages != b.messages:
            found.append(Difference(rel, "messages", "; ".join(a.messages) or "(none)", "; ".join(b.messages) or "(none)"))
        if a.rule_ids != b.rule_ids:
            found.append(Difference(rel, "rule ids", ", ".join(a.rule_ids) or "(none)", ", ".join(b.rule_ids) or "(none)"))
    return found


def unported_ids(ids: "Sequence[str]") -> "list[str]":
    """The ids among ``ids`` that the Python engine reports as not ported (empty when that cannot be asked)."""
    try:
        from transit.scanners import load_registry
        missing = set(load_registry().unported())
    except Exception:                                      # a registry that does not load is the unit tests' finding, not this tool's
        return []
    return [i for i in ids if i in missing]


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# the command
# ═══════════════════════════════════════════════════════════════════════════════════════════════
def parse_environment(items: "Sequence[str]") -> "dict[str, str]":
    env: "dict[str, str]" = {}
    for item in items:
        name, separator, value = item.partition("=")
        if not separator or not name or not all(c.isalnum() or c == "_" for c in name):
            raise UsageError("--env wants NAME=VALUE, got %s" % printable(item, 60))
        env[name] = value
    return env


def main(argv: "Sequence[str] | None" = None, *, out: "TextIO | None" = None, engines: "Mapping[str, Sequence[str]] | None" = None,
         scanners: "Mapping[str, str] | None" = None) -> int:
    """The whole command. ``engines``, ``scanners`` and ``out`` are for the unit tests (fake engine programs, a fake registry, a buffer)."""
    out = out or sys.stdout
    commands = dict(engines or ENGINES)
    parser = argparse.ArgumentParser(prog="family_diff.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ids", nargs="*", help="scanner ids or family keys (python, shell, manifest, powershell.text ...)")
    parser.add_argument("--fixtures", action="append", metavar="DIR", help="fixture directory (repeatable; default tests/fixtures/rules)")
    parser.add_argument("--engines", default="bash,python", help="comma-separated: bash,python (default), or one of them")
    parser.add_argument("--list", action="store_true", help="only list the fixtures routed to the ids; run no engine")
    parser.add_argument("--env", action="append", default=[], metavar="NAME=VALUE", help="extra environment for the engines (repeatable)")
    parser.add_argument("--verbose", action="store_true", help="print every file, not only the ones that differ")
    parser.add_argument("--keep", action="store_true", help="keep the scratch directory and print its path")
    parser.add_argument("--timeout", type=float, default=900.0, help="seconds an engine may take (default 900)")
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:                              # argparse prints its own message; 0 is --help
        return 0 if exc.code in (0, None) else 2
    try:
        ids = resolve_ids(args.ids, scanners if scanners is not None else known_scanners())
        chosen_engines = [word.strip() for word in args.engines.split(",") if word.strip()]
        if not chosen_engines or any(word not in commands for word in chosen_engines):
            raise UsageError("--engines wants a comma-separated subset of %s" % ",".join(sorted(commands)))
        directories = [Path(d) for d in args.fixtures] if args.fixtures else list(DEFAULT_FIXTURES)
        for directory in directories:
            if not directory.is_dir():
                raise UsageError("not a directory: %s" % printable(directory, 120))
        env = parse_environment(args.env)
    except UsageError as exc:
        sys.stderr.write("family_diff: %s\n" % exc)
        return 2

    selection = select_fixtures(directories, ids)
    out.write("family_diff: %s; %d fixture file(s) routed from %s\n" % (", ".join(ids), len(selection), ", ".join(printable(d, 80) for d in directories)))
    if args.list or not selection:
        for directory, rel in selection:
            out.write("  %s/%s\n" % (printable(directory.name, 60), printable(rel, 200)))
        if not selection:
            out.write("  nothing is routed to these ids in these directories\n")
        return 0

    scratch = Path(tempfile.mkdtemp(prefix="family_diff_"))
    try:
        scan = scratch / "scan"
        scan.mkdir()
        origin = build_scratch(selection, scan)
        runs: "dict[str, EngineRun]" = {}
        for name in chosen_engines:
            work, reports = scratch / ("work_" + name), scratch / ("reports_" + name)
            work.mkdir()
            reports.mkdir()
            runs[name] = run_engine(name, commands[name], scan, reports, work, env, timeout=args.timeout)
        rows = {name: file_rows(run.report, scan) for name, run in runs.items()}
        if args.keep:
            out.write("scratch directory kept: %s\n" % printable(scratch, 200))
        return _report(out, ids, origin, runs, rows, chosen_engines, args.verbose)
    finally:
        if not args.keep:
            shutil.rmtree(scratch, ignore_errors=True)


def _report(out: TextIO, ids: "Sequence[str]", origin: "Mapping[str, str]", runs: "Mapping[str, EngineRun]",
            rows: "Mapping[str, Mapping[str, FileRow]]", names: "Sequence[str]", verbose: bool) -> int:
    broken = [run for run in runs.values() if run.report is None]
    for run in broken:
        out.write("ENGINE %s produced no report (exit %d, last line %r): %s\n" % (run.name, run.exit_status, printable(run.last_line, 40),
                                                                                 printable(run.stderr_tail, 300)))
    if broken:
        return 2
    if len(names) == 1:
        only = names[0]
        for rel in sorted(rows[only]):
            row = rows[only][rel]
            out.write("  %-5s %s  %s\n" % (row.status, printable(origin.get(rel, rel), 120), printable("; ".join(row.messages), 400)))
        out.write("%s: %d file(s) reported; exit %d, last line %s\n" % (only, len(rows[only]), runs[only].exit_status, printable(runs[only].last_line, 40)))
        return 0
    left, right = names[0], names[1]
    if verbose:
        for rel in sorted(set(rows[left]) | set(rows[right])):
            a, b = rows[left].get(rel), rows[right].get(rel)
            out.write("  %-34s %s %-5s  %s %-5s\n" % (printable(origin.get(rel, rel), 34), left, a.status if a else "-", right, b.status if b else "-"))
    differences = compare(left, rows[left], right, rows[right])
    for item in differences:
        out.write("DIFF %s  %s\n" % (printable(origin.get(item.file, item.file), 120), item.kind))
        if item.kind.startswith("only in"):
            out.write("     %s\n" % printable(item.left, 400))
        else:
            out.write("     %-7s %s\n     %-7s %s\n" % (left, printable(item.left, 400), right, printable(item.right, 400)))
    missing = unported_ids(ids) if right == "python" else []
    if missing:
        out.write("note: the Python engine has not ported %s yet; its files carry engine:scanner_not_ported WARNs (D-032), so a difference "
                  "there is expected\n" % ", ".join(missing))
    files = len(set(rows[left]) | set(rows[right]))
    out.write("%d file(s) compared, %d difference(s)\n" % (files, len(differences)))
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
