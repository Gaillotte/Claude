"""Shared test support for the scanner packages of the Python engine (WP-05 owns this file; every scanner package imports it).

A scanner test needs four things, and each is here so that no package builds its own:

  * a ``ScanContext`` over fakes (``make_context``): a real ``ScanContext`` whose collaborators are test doubles or the real thing, as the
    test chooses: a recording ``FakeVerdict`` or the real ``Verdict`` (the default), a real ``Console`` over in-memory buffers, a
    ``FakeLocator`` for ``ToolLocator``, ``FakeWrappers`` / ``StubWrapper`` for the tool wrappers, a registry built from plain functions;
  * a temporary repository (``TempRepo``): files written below a private directory, a real ``FileView`` over any of them, symlinks, hostile
    names;
  * a stub-tool directory (``StubTools``): executable stand-ins for external tools on a PRIVATE ``PATH``, that print what the test says,
    exit with the status the test says and log their arguments and chosen environment variables, so a wrapper is tested against a program
    and never against the host's tools;
  * a recording sink for the verdict (``FakeVerdict``), with the methods a ``ScanContext`` calls.

How a test module imports it (``-I`` removes the current directory, so a test module starts with the three ``sys.path`` lines of
``tests/engine/__init__.py`` and then)::

    from tests.engine import support          # ``tests`` is a namespace package once the repository root is on sys.path

Typical use::

    h = support.make_context(self, rel="src/app.py", data=b"import os\\nos.system(x)\\n")
    scan(h.ctx)                                # the scanner under test
    self.assertEqual(h.messages(), [("FAIL", "CWE-78:OS_command_injection_risk")])

Nothing here sleeps, reads the network or the host's ``PATH``. A token-shaped credential is never written contiguously in a test: build it
from two halves at run time (``tests/run_tests.sh`` does the same).
"""
from __future__ import annotations

import collections
import contextlib
import dataclasses
import datetime
import io
import os
import stat
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from transit.config import Config, load_config  # noqa: E402
from transit.console import COLOUR_FAIL, COLOUR_INFO, COLOUR_OK, COLOUR_RESET, COLOUR_WARN, Console  # noqa: E402
from transit.files import FileView, TempArea  # noqa: E402
from transit.findings import Allowlist, join_scan_path  # noqa: E402
from transit.rules import SearchPolicy  # noqa: E402
from transit.scanners import KNOWN_SCANNERS, Registry, ScanContext, ScannerFn, ScannerSpec  # noqa: E402
from transit.tools import FILE_TOOLS, Record, ToolInfo, ToolOutcome, ToolRequest, ToolWrapper  # noqa: E402
from transit.verdict import GLOBAL_FILE, Outcome, Verdict  # noqa: E402

#: The clock every ``make_config`` uses (the report timestamp is not what a scanner test looks at).
FIXED_NOW = datetime.datetime(2026, 11, 13, 12, 0, 0)


def two_halves(first: str, second: str) -> str:
    """A token-shaped string built at run time from two halves, so that no test file holds it contiguously."""
    return first + second


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# configuration, console
# ═══════════════════════════════════════════════════════════════════════════════════════════════
def make_config(environ: "Mapping[str, str] | None" = None, **env: str) -> Config:
    """A real ``Config`` from a small environment. ``WORK_DIR`` and ``TMPDIR`` default to the system temporary directory; extra
    variables come as keyword arguments (``make_config(TRANSIT_FIXES="D-031", MIN_SEVERITY="low")``) or as a mapping (``PATH`` of a
    ``StubTools``)."""
    merged = {"WORK_DIR": tempfile.gettempdir(), "TMPDIR": tempfile.gettempdir()}
    merged.update(environ or {})
    merged.update(env)
    return load_config(merged, now=FIXED_NOW)


class ConsoleBuffers:
    """A real ``Console`` writing to two in-memory buffers (``out`` is stdout, ``err`` stderr)."""

    def __init__(self, verbosity: str = "normal") -> None:
        self.out = io.BytesIO()
        self.err = io.BytesIO()
        self.console = Console(verbosity, out=self.out, err=self.err, err_is_tty=False)

    @property
    def stdout(self) -> str:
        return self.out.getvalue().decode("utf-8", "replace")

    @property
    def stderr(self) -> str:
        return self.err.getvalue().decode("utf-8", "replace")


def strip_engine_colours(raw: bytes) -> bytes:
    """``raw`` console bytes without the engine's own colour sequences (``COLOUR_*``), so that what is left can be asserted to be printable:
    any other ESC byte is repository text that got through."""
    for colour in (COLOUR_INFO, COLOUR_WARN, COLOUR_OK, COLOUR_FAIL, COLOUR_RESET):
        raw = raw.replace(colour.encode("ascii"), b"")
    return raw


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# a recording sink for the verdict
# ═══════════════════════════════════════════════════════════════════════════════════════════════
class FakeVerdict:
    """The part of ``verdict.Verdict`` a ``ScanContext`` calls, recording every call in ``log`` as a tuple:

        ("pass", file)                                   ("warn", file, message)
        ("fail", file, message, severity, downgradable)  ("incomplete", layer_id, reason)
        ("layer", layer_id, state)

    ``events`` counts ``record_*`` calls like the real one (``record_warn_once`` counts one event, and only the first time a key is seen).
    ``record_fail`` returns ``Outcome.FAILED`` unless ``outcomes`` holds queued answers (``FakeVerdict(outcomes=[Outcome.ALLOWED])`` is the
    allowlist downgrading the first FAIL). It never prints and has no allowlist: a test of the allowlist uses the real ``Verdict``."""

    def __init__(self, *, outcomes: "Iterable[Outcome]" = ()) -> None:
        self.log: "list[tuple]" = []
        self._outcomes = collections.deque(outcomes)
        self._events = 0
        self._once: "set[str]" = set()
        self._status: "dict[str, str]" = {}

    @property
    def events(self) -> int:
        return self._events

    def status_of(self, file: str) -> "str | None":
        return self._status.get(file)

    def record_pass(self, file: "str | None" = None) -> None:
        self._events += 1
        self.log.append(("pass", file))
        if file and file not in self._status:
            self._status[file] = "PASS"

    def record_warn(self, file: "str | None", message: str) -> None:
        file = file or GLOBAL_FILE
        self._events += 1
        self.log.append(("warn", file, message))
        self._status.setdefault(file, "WARN")

    def record_warn_once(self, key: str, file: "str | None", message: str) -> bool:
        if key in self._once:
            return False
        self._once.add(key)
        self.record_warn(file, message)
        return True

    def record_fail(self, file: str, message: str, *, severity: "str | None" = None, downgradable: bool = True) -> Outcome:
        file = file or GLOBAL_FILE
        self.log.append(("fail", file, message, severity, downgradable))
        outcome = self._outcomes.popleft() if self._outcomes else Outcome.FAILED
        if outcome is Outcome.FAILED:
            self._events += 1
            self._status[file] = "FAIL"
        else:
            self._events += 1
            self._status.setdefault(file, "WARN")
        return outcome

    def record_layer(self, layer_id: str, state: str, *, overwrite: bool = True) -> None:
        self.log.append(("layer", layer_id, state))

    def note_incomplete(self, layer_id: str, reason: str) -> None:
        self.log.append(("incomplete", layer_id, reason))

    # -- convenience for assertions
    def of(self, kind: str) -> "list[tuple]":
        return [entry for entry in self.log if entry[0] == kind]

    def messages(self, kind: "str | None" = None) -> "list[str]":
        """Messages of the ``warn`` and ``fail`` calls (or of one ``kind``), in order."""
        return [entry[2] for entry in self.log if entry[0] in ("warn", "fail") and kind in (None, entry[0])]


def parse_file_message(text: str) -> "list[tuple[str, str]]":
    """``Snapshot.file_message`` (``"[WARN] a | [FAIL] b | "``) as ``[("WARN", "a"), ("FAIL", "b")]`` (the conformance normaliser's view)."""
    if not text:
        return []
    parts = text[:-3].split(" | ") if text.endswith(" | ") else text.split(" | ")
    result = []
    for part in parts:
        level, _, rest = part.partition("] ")
        result.append((level.lstrip("["), rest))
    return result


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# a temporary repository
# ═══════════════════════════════════════════════════════════════════════════════════════════════
class TempRepo:
    """A private directory holding a small repository. ``files`` maps a relative path (a ``str``, ``surrogateescape`` for a name that is not
    UTF-8) to its content (``bytes`` or ``str``). Use as a context manager, or call ``cleanup`` (``make_context(test, ...)`` does it)."""

    def __init__(self, files: "Mapping[str, bytes | str] | None" = None, *, tmpdir: "str | None" = None) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="transit-test-", dir=tmpdir)
        self.path = os.path.realpath(self._tmp.name)
        for rel, data in (files or {}).items():
            self.write(rel, data)

    def write(self, rel: str, data: "bytes | str" = b"", *, mode: "int | None" = None) -> str:
        """Create ``rel`` (with parents) and return its recorded path (``scan_dir/rel``)."""
        target = os.path.join(os.fsencode(self.path), os.fsencode(rel))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        payload = data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data
        with open(target, "wb") as handle:
            handle.write(payload)
        if mode is not None:
            os.chmod(target, mode)
        return self.recorded(rel)

    def mkdir(self, rel: str) -> str:
        os.makedirs(os.path.join(os.fsencode(self.path), os.fsencode(rel)), exist_ok=True)
        return self.recorded(rel)

    def symlink(self, rel: str, target: str) -> str:
        link = os.path.join(os.fsencode(self.path), os.fsencode(rel))
        os.makedirs(os.path.dirname(link), exist_ok=True)
        os.symlink(os.fsencode(target), link)
        return self.recorded(rel)

    def recorded(self, rel: str) -> str:
        """The recorded path of ``rel``: the key a report uses (``findings.join_scan_path``)."""
        return join_scan_path(self.path, rel)

    def view(self, rel: str, *, cfg: "Config | None" = None) -> FileView:
        """A real ``FileView`` of ``rel`` (a new one each call: a view caches the bytes)."""
        return FileView(self.path, rel, (cfg or make_config()).limits)

    def cleanup(self) -> None:
        self._tmp.cleanup()

    def __enter__(self) -> "TempRepo":
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# stub tools
# ═══════════════════════════════════════════════════════════════════════════════════════════════
class StubTools:
    """A directory of executable stand-ins for external tools. ``StubTools({"bandit": {"stdout": "...", "exit_code": 1}})``, or ``add`` later.

    Each stub is a ``/bin/sh`` script that appends its arguments (NUL-separated, one call ended by ``\\x01``) and the variables named in
    ``record_env`` to ``<dir>/<name>.calls``, prints ``stdout`` / ``stderr`` and exits with ``exit_code``; ``script`` replaces the generated
    body (the argument log is still written first). ``environ()`` is the environment of a run whose ``PATH`` is THIS directory only, so a
    tool the test did not add is "not installed" whatever the host has. ``calls(name)`` returns the logged calls, each a list of arguments,
    and ``env(name)`` the logged variables of the last call."""

    def __init__(self, tools: "Mapping[str, Mapping[str, object]] | None" = None, *, record_env: "Sequence[str]" = ()) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="transit-stubs-")
        self.dir = os.path.realpath(self._tmp.name)
        self._record_env = tuple(record_env)
        for name, spec in (tools or {}).items():
            self.add(name, **dict(spec))

    def add(self, name: str, *, stdout: str = "", stderr: str = "", exit_code: int = 0, script: "str | None" = None) -> str:
        """Create the executable ``name`` and return its path. ``name`` has no separator."""
        if not name or "/" in name or name in (".", ".."):
            raise ValueError("a stub tool name is a plain word: %r" % (name,))
        log = os.path.join(self.dir, name + ".calls")
        lines = ["#!/bin/sh", "# stub generated by tests/engine/support.py"]
        lines.append('for a in "$@"; do printf \'%%s\\0\' "$a" >> %s; done; printf \'\\001\' >> %s' % (_sh_quote(log), _sh_quote(log)))
        for var in self._record_env:
            lines.append('printf \'%%s=%%s\\0\' %s "${%s-}" >> %s.env' % (_sh_quote(var), var, _sh_quote(log)))
        if script is not None:
            lines.append(script)
        else:
            if stdout:
                lines.append("printf '%%s' %s" % _sh_quote(stdout))
            if stderr:
                lines.append("printf '%%s' %s >&2" % _sh_quote(stderr))
            lines.append("exit %d" % exit_code)
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return path

    def environ(self, base: "Mapping[str, str] | None" = None) -> "dict[str, str]":
        """``base`` plus ``PATH`` = this directory only."""
        merged = dict(base or {})
        merged["PATH"] = self.dir
        return merged

    def calls(self, name: str) -> "list[list[str]]":
        """The arguments of every call of ``name``, in order (``[]`` if it never ran)."""
        try:
            raw = Path(os.path.join(self.dir, name + ".calls")).read_bytes()
        except OSError:
            return []
        result = []
        for chunk in raw.split(b"\x01"):
            if chunk:
                result.append([part.decode("utf-8", "surrogateescape") for part in chunk.split(b"\0")[:-1]])
        return result

    def env(self, name: str) -> "dict[str, str]":
        """The ``record_env`` variables as ``name`` last saw them."""
        try:
            raw = Path(os.path.join(self.dir, name + ".calls.env")).read_bytes()
        except OSError:
            return {}
        values = {}
        for chunk in raw.split(b"\0"):
            if chunk:
                key, _, value = chunk.decode("utf-8", "surrogateescape").partition("=")
                values[key] = value
        return values

    def cleanup(self) -> None:
        self._tmp.cleanup()

    def __enter__(self) -> "StubTools":
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()


def _sh_quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


class FakeLocator:
    """``tools.ToolLocator`` without a file system: ``FakeLocator({"bandit": "/opt/bin/bandit"})``. ``asked`` lists every name looked up."""

    def __init__(self, found: "Mapping[str, str] | None" = None) -> None:
        self._found = dict(found or {})
        self.asked: "list[str]" = []

    def find(self, name: str) -> "ToolInfo | None":
        if not name or "/" in name:
            raise ValueError("a tool name is a plain word: %r" % (name,))
        self.asked.append(name)
        path = self._found.get(name)
        return ToolInfo(name, path) if path else None


class StubWrapper(ToolWrapper):
    """A per-file ``ToolWrapper`` that returns a canned ``ToolOutcome`` (or raises ``raises``) and remembers each ``ToolRequest``."""
    scope = "file"
    layer = "L5_per_language_sast"

    def __init__(self, name: str, outcome: "ToolOutcome | None" = None, *, raises: "BaseException | None" = None) -> None:
        self.name = name
        self.binary = FILE_TOOLS[name]
        self.outcome = outcome if outcome is not None else ToolOutcome(layer_state=None)
        self.raises = raises
        self.requests: "list[ToolRequest]" = []

    def run(self, request: ToolRequest) -> ToolOutcome:
        self.requests.append(request)
        if self.raises is not None:
            raise self.raises
        return self.outcome


class FakeWrappers:
    """``tools.WrapperSet`` as a plain object: ``FakeWrappers(StubWrapper("bandit"), ...)``."""

    def __init__(self, *wrappers: ToolWrapper, load_errors: "tuple[str, ...]" = ()) -> None:
        self.wrappers = types.MappingProxyType({w.name: w for w in wrappers})
        self.load_errors = load_errors

    def get(self, name: str) -> "ToolWrapper | None":
        return self.wrappers.get(name)


def warn_record(message: str, file: str = "", severity: "str | None" = None) -> Record:
    return Record("warn", file, message, severity)


def fail_record(message: str, file: str = "", severity: "str | None" = None) -> Record:
    return Record("fail", file, message, severity)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# registry
# ═══════════════════════════════════════════════════════════════════════════════════════════════
def make_registry(scanners: "Mapping[str, ScannerFn | ScannerSpec]| None" = None, *, ported: bool = True,
                  load_errors: "tuple[str, ...]" = ()) -> Registry:
    """A ``Registry`` from plain functions: ``make_registry({"python": scan, "rtf": other})``. Each id must be a key of ``KNOWN_SCANNERS``
    (its family comes from there); a ``ScannerSpec`` value is used as it is."""
    specs: "dict[str, ScannerSpec]" = {}
    for scanner_id, entry in (scanners or {}).items():
        if isinstance(entry, ScannerSpec):
            specs[scanner_id] = entry
        else:
            specs[scanner_id] = ScannerSpec(id=scanner_id, family=KNOWN_SCANNERS[scanner_id], fn=entry,
                                            bash_function="scan_" + scanner_id.replace(".", "_"), ported=ported)
    return Registry(specs=types.MappingProxyType(specs), load_errors=load_errors)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# the context
# ═══════════════════════════════════════════════════════════════════════════════════════════════
def default_policy(cfg: "Config | None" = None) -> SearchPolicy:
    """The policy ``layers.search_policy`` builds, with the hardened ``excl_nul_blind=False`` (D-029 is closed in bash)."""
    limits = (cfg or make_config()).limits
    return SearchPolicy(rule_budget_s=limits.rule_budget_s, long_line_bytes=limits.long_line_bytes, excl_nul_blind=False)


@dataclasses.dataclass
class Harness:
    """What ``make_context`` returns. ``ctx`` is the context of the first file; ``new_context`` builds another one over the SAME verdict,
    console, registry, tools and deadline (a second file of the same run, or a delegated scanner's context)."""
    ctx: ScanContext
    verdict: "Verdict | FakeVerdict"
    buffers: ConsoleBuffers
    repo: TempRepo
    view: FileView
    cfg: Config
    registry: Registry
    locator: object
    wrappers: object
    temp: TempArea
    policy: SearchPolicy
    deadline: float
    allowlist: Allowlist
    _cleanups: "list[Callable[[], None]]" = dataclasses.field(default_factory=list)

    @property
    def path(self) -> str:
        return self.ctx.path

    @property
    def console(self) -> Console:
        return self.buffers.console

    def new_context(self, rel: "str | None" = None, *, data: "bytes | str | None" = None, sniffed: bool = False, depth: int = 0,
                    deadline: "float | None" = None) -> ScanContext:
        """A context for ``rel`` (default: the first file; ``data`` writes it first)."""
        if rel is None:
            rel = self.ctx.rel
        if data is not None:
            self.repo.write(rel, data)
        return ScanContext(view=self.repo.view(rel, cfg=self.cfg), verdict=self.verdict, cfg=self.cfg, console=self.console,
                           tools=self.locator, wrappers=self.wrappers, registry=self.registry, policy=self.policy, temp=self.temp,
                           scan_dir=self.repo.path, deadline=self.deadline if deadline is None else deadline, sniffed=sniffed, depth=depth)

    # -- what happened (real Verdict only)
    def snapshot(self):
        return self.verdict.snapshot()

    def messages(self, file: "str | None" = None) -> "list[tuple[str, str]]":
        """``[("WARN", "..."), ("FAIL", "...")]`` of ``file`` (default: the context's file), in order. Real ``Verdict`` only."""
        return parse_file_message(self.snapshot().file_message.get(file or self.ctx.path, ""))

    def status(self, file: "str | None" = None) -> "str | None":
        return self.verdict.status_of(file or self.ctx.path)

    def close(self) -> None:
        for cleanup in reversed(self._cleanups):
            with contextlib.suppress(Exception):
                cleanup()
        self._cleanups.clear()


def make_context(test: "unittest.TestCase | None" = None, rel: str = "a.txt", data: "bytes | str" = b"", *,
                 files: "Mapping[str, bytes | str] | None" = None, verdict: "object | str | None" = None,
                 allowlist: "Allowlist | None" = None, threshold: int = 3, min_severity: str = "high",
                 cfg: "Config | None" = None, environ: "Mapping[str, str] | None" = None, locator: "object | None" = None,
                 wrappers: "object | None" = None, registry: "Registry | None" = None, policy: "SearchPolicy | None" = None,
                 deadline: "float | None" = None, sniffed: bool = False, depth: int = 0, verbosity: str = "normal") -> Harness:
    """A real ``ScanContext`` for the file ``rel`` (written with ``data``; ``files`` adds others) of a fresh ``TempRepo``.

    ``verdict``: None (default) is a REAL ``Verdict`` (with ``allowlist``, ``threshold``, ``min_severity`` and a real ``Console`` over buffers);
    ``"fake"`` a ``FakeVerdict``; any other object is used as it is. ``locator`` / ``wrappers`` default to ``FakeLocator()`` (no tool is
    installed) and ``FakeWrappers()``; ``registry`` to an empty one. ``deadline`` is a ``time.monotonic()`` value (default: an hour from now).
    With ``test`` the temporary directories are removed by ``test.addCleanup``; without it the caller calls ``Harness.close``."""
    cfg = cfg or make_config(environ)
    repo = TempRepo(files)
    repo.write(rel, data)
    buffers = ConsoleBuffers(verbosity)
    allow = allowlist if allowlist is not None else Allowlist({})
    if verdict is None:
        verdict_obj: object = Verdict(repo.path, allow, threshold=threshold, min_severity=min_severity, console=buffers.console)
    elif verdict == "fake":
        verdict_obj = FakeVerdict()
    else:
        verdict_obj = verdict
    temp = TempArea(tempfile.gettempdir())
    harness = Harness(ctx=None, verdict=verdict_obj, buffers=buffers, repo=repo, view=None, cfg=cfg,  # type: ignore[arg-type]
                      registry=registry if registry is not None else make_registry({}),
                      locator=locator if locator is not None else FakeLocator(),
                      wrappers=wrappers if wrappers is not None else FakeWrappers(),
                      temp=temp, policy=policy if policy is not None else default_policy(cfg),
                      deadline=deadline if deadline is not None else time.monotonic() + 3600.0, allowlist=allow)
    harness._cleanups.extend([repo.cleanup, temp.cleanup])
    harness.ctx = harness.new_context(rel, sniffed=sniffed, depth=depth)
    harness.view = harness.ctx.view
    if test is not None:
        test.addCleanup(harness.close)
    return harness
