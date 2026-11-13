"""External tools: finding them, running them safely, and the protocol a tool wrapper implements.

Owner of: S6 (repository text never reaches a shell), S9 (fail closed, and say so) as far as a process is concerned, S10 (tool
output is never echoed raw), the offline child environment of contract 2, and the policy for a tool that is installed
but whose wrapper is not written yet.

Layering: depends on ``transit.config`` and ``transit.console`` only. Wrappers (``transit/tools/<tool>_wrapper.py``, one per
tool, written in Phase 4) import this module; this module never imports a wrapper at import time (``load_wrappers`` does,
on request).

THE OLD HELPER FILES ARE PROGRAMS, NOT MODULES. They were moved out of the bash engine with their top-level code intact (it reads
``sys.argv``): ``import transit.containers.pdf`` raises ``SystemExit(0)`` (a silent exit with status 0), the others raise
``IndexError``. The Python engine never imports any of them (a lint forbids it). Four are RUN as programs with
``run_helper_script`` (jar, office, pdf, manifests: one implementation shared by both engines); ``tools/gitleaks.py``,
``tools/scancode.py`` and ``report_json.py`` are re-implemented as pure functions (their line protocols cannot carry a file name
that contains the delimiter) and kept only as test oracles. Design section 3.3 has the table.

Policy for an installed tool without a wrapper (it MUST NOT be skipped silently):
  * a whole-directory tool (gitleaks, detect-secrets, clamscan, yara, semgrep, trivy, scancode): the layer's coverage
    state is ``skipped:python engine has not ported <tool> yet`` and the WARN ``engine:tool_not_ported:<tool>`` is
    recorded on ``__global__`` (``layers.run_slot``);
  * a per-file tool (bandit, shellcheck, cppcheck, hadolint, checkov, semgrep per file, file(1), strings, unzip):
    ``ScanContext.file_tool`` returns status ``not_ported``, notes ``partial:python engine has not ported <tool> yet`` on
    ``L5_per_language_sast`` and records the same WARN once per run.
Both keep ``coverage_complete`` false. ``Registry.unported()`` must be empty before the Python engine becomes the default.
"""
from __future__ import annotations

import abc
import dataclasses
import importlib
import os
import pkgutil
import select
import selectors
import signal
import subprocess
import sys
import time
import types
from typing import Mapping, Sequence

from transit.config import Config, env_number

#: Environment added to every child process (contract 2, "Offline operation"). Never put into ``os.environ``.
OFFLINE_CHILD_ENV: Mapping[str, str] = {
    "SEMGREP_SEND_METRICS": "off", "DO_NOT_TRACK": "1", "CHECKPOINT_DISABLE": "1", "PIP_NO_INDEX": "1",
}

#: Name -> path (relative to the ``transit`` package directory) of the standalone helper PROGRAMS of the bash engine that the Python
#: engine runs as programs, unchanged (design section 3.3). ``gitleaks.py``, ``scancode.py`` and ``report_json.py`` are deliberately
#: absent: they are re-implemented as pure functions and kept only as test oracles.
HELPER_SCRIPTS: Mapping[str, str] = {
    "office": "containers/office.py", "jar": "containers/jar.py", "pdf": "containers/pdf.py",
    "manifests": "scanners/manifests.py",
}

#: Wrapper key -> executable searched on ``PATH``, for the whole-directory tools. The key is what ``ToolWrapper.name`` and
#: ``ToolSlot.tool`` hold; it differs from the executable only where two wrappers share one program.
DIRECTORY_TOOLS: Mapping[str, str] = {
    "gitleaks": "gitleaks", "detect-secrets": "detect-secrets", "clamscan": "clamscan", "yara": "yara",
    "semgrep": "semgrep", "trivy": "trivy", "scancode": "scancode",
}
#: Same for the per-file tools asked for with ``ScanContext.file_tool``. ``semgrep-js`` is Semgrep run on one JavaScript file.
FILE_TOOLS: Mapping[str, str] = {
    "bandit": "bandit", "shellcheck": "shellcheck", "cppcheck": "cppcheck", "hadolint": "hadolint", "checkov": "checkov",
    "semgrep-js": "semgrep", "file": "file", "strings": "strings", "unzip": "unzip",
}

#: Every process output is cut to this many bytes in memory; the rest is dropped and ``truncated`` is set. Larger output
#: (a Semgrep JSON of a big repository) is requested with ``output_file`` instead.
MAX_CAPTURE_BYTES = 64 * 1024 * 1024

#: ADDITIVE (the hardened bash engine, 2026-11-13): ``scan_pipeline.sh`` runs under ``export LC_ALL=C``, so every tool and every helper it starts
#: ran in the C locale. ``child_env`` adds it (an ``extra`` entry may still override it). Private: the frozen ``OFFLINE_CHILD_ENV`` keeps its four names.
_CHILD_LOCALE: Mapping[str, str] = types.MappingProxyType({"LC_ALL": "C"})
#: The wall-clock budget knob each helper PROGRAM reads (``jar.py`` and ``office.py`` arm ``SIGALRM`` at budget + 10 s), and the default of that knob.
_HELPER_BUDGET_KNOB: Mapping[str, str] = types.MappingProxyType({"jar": "JAR_TIME_BUDGET_S", "office": "OFFICE_TIME_BUDGET_S"})
_HELPER_BUDGET_DEFAULT_S = 90.0
#: The alarm margin of those two helpers plus a little slack for start-up and for printing: the default process timeout is never below budget + this.
_HELPER_TIMEOUT_MARGIN_S = 10.0 + 20.0
#: ``run_process`` reads at most this much from a pipe at a time and writes at most this much to the standard input of a child at a time.
_READ_CHUNK = 1 << 20
_WRITE_CHUNK = 1 << 16
#: Longest timeout accepted (a year): ``selectors`` and ``Popen.wait`` refuse an infinite or enormous float.
_MAX_TIMEOUT_S = 365.0 * 24 * 3600
#: How long the engine waits for a killed child to be reaped before it gives up (a process in uninterruptible sleep cannot be killed).
_REAP_WAIT_S = 30.0
#: Seconds a child whose pipes are both closed is still given to end after its deadline.
_EXIT_GRACE_S = 0.5
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")


def _word(text: object, limit: int = 60) -> str:
    """``text`` cut to ``limit`` characters with every character outside ``[A-Za-z0-9_.-]`` replaced by ``_``: for a module name and an exception
    class name that are put into a load-error entry (engine words, never repository text; the filter makes sure of it)."""
    cleaned = "".join(ch if ch in _NAME_CHARS else "_" for ch in str(text)[:limit])
    return cleaned or "unknown"


@dataclasses.dataclass(frozen=True)
class ToolInfo:
    """A tool that was found on ``PATH``: ``name`` as asked, ``path`` absolute."""
    name: str
    path: str


class ToolLocator:
    """``command -v`` with a cache. Looks in the ``PATH`` of ``Config.environ`` (a test puts a stub directory first)."""

    def __init__(self, cfg: Config) -> None:
        # Only ABSOLUTE ``PATH`` components are searched. ``command -v`` also searches the working directory for an empty or relative component, and the
        # working directory of the engine is whatever the caller had; skipping them can only report a tool as not installed (a visible coverage gap),
        # never run one the operator did not install. No ``PATH`` at all finds nothing (the process default path is NOT substituted: a test, or an
        # operator, that wants no tools gets none).
        self._dirs = tuple(part for part in cfg.environ.get("PATH", "").split(":") if part.startswith("/"))
        self._cache: "dict[str, ToolInfo | None]" = {}

    def find(self, name: str) -> "ToolInfo | None":
        """The executable ``name`` (no path separator allowed; ``ValueError`` otherwise), or None."""
        if not isinstance(name, str) or not name or "/" in name or "\0" in name or name in (".", ".."):
            raise ValueError("a tool name is a plain word, not a path: %r" % (name,))
        if name in self._cache:
            return self._cache[name]
        found: "ToolInfo | None" = None
        for directory in self._dirs:
            candidate = os.path.join(directory, name)
            try:
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    found = ToolInfo(name=name, path=candidate)
                    break
            except (OSError, ValueError):
                continue
        self._cache[name] = found                          # a miss is remembered too: the tools do not appear during a run
        return found


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    """What a child process did. ``status`` is ``ok`` (exited by itself), ``timeout`` (killed after ``timeout_s``),
    ``signal`` (died of a signal; ``returncode`` is negative), ``not_found`` (could not be started), or ``error`` (any other
    start failure). ``stdout`` / ``stderr`` are captured bytes, NEVER printed by the engine (S10); a wrapper parses ``stdout``
    and may put a sanitised excerpt into a Console note."""
    status: str
    returncode: "int | None"
    stdout: bytes
    stderr: bytes
    truncated: bool
    elapsed_s: float


def child_env(cfg: Config, *, remove: Sequence[str] = (), extra: "Mapping[str, str] | None" = None) -> dict[str, str]:
    """``cfg.environ`` + ``OFFLINE_CHILD_ENV`` + ``extra``, minus the names in ``remove`` (gitleaks removes
    ``GITLEAKS_CONFIG`` and ``GITLEAKS_CONFIG_TOML``, S8d). A fresh dict; ``os.environ`` is not touched.

    ADDITIVE: ``LC_ALL=C`` is part of it (the hardened script exports it for the whole run), applied before ``extra``, which may override it."""
    env = dict(cfg.environ)
    env.update(OFFLINE_CHILD_ENV)
    env.update(_CHILD_LOCALE)
    if extra:
        env.update(extra)
    for name in remove:
        env.pop(name, None)
    return env


def run_process(argv: Sequence[str], *, env: Mapping[str, str], timeout_s: float, cwd: "str | None" = None,
                stdin: "bytes | None" = None, output_file: "str | None" = None) -> ProcessResult:
    """Run ``argv`` WITHOUT a shell (S6): ``subprocess`` with an argument list, ``shell=False``, ``stdin`` closed unless given,
    a new session so that on timeout the whole process group is killed, and the timeout enforced for sure (kill, then wait).
    Every argument that comes from the repository (a path) must be absolute or follow ``--``. ``output_file`` sends stdout
    to that file instead of memory. Never raises for a failing child; raises ``ValueError`` for an empty ``argv``.

    What the result says, beyond the class docstring of ``ProcessResult``:
      * ``not_found`` and ``error`` have ``returncode`` None and empty output (no process ran); a program name that is not on the ``PATH`` of ``env``,
        a missing working directory and a path that does not exist are ``not_found``; a file that is not executable, a directory, an argument with a NUL
        byte and an ``output_file`` that cannot be opened are ``error`` (in that last case the program is NOT started);
      * ``timeout`` has ``returncode`` None: the process did not end by itself. It is the answer whenever ``timeout_s`` passes before the process has ended
        AND closed both of its pipes (a descendant that keeps a pipe open after its parent left is waited for, and killed with the group, so a tool
        cannot leave the engine waiting for ever); what was captured until then is kept;
      * ``stdout`` and ``stderr`` are each cut to ``MAX_CAPTURE_BYTES`` in memory; the rest is read and dropped (the child is never blocked on a full
        pipe) and ``truncated`` is set. ``output_file`` is opened without following a symlink, created 0600, truncated; the file is the child's stdout;
      * the child is killed with SIGKILL through its process group BEFORE it is reaped (the group id cannot belong to anybody else yet). Any
        ``BaseException`` that reaches this function while it waits (the signal exception of ``pipeline``, Ctrl-C) kills the group the same way and
        propagates: an interrupted engine never leaves a tool running."""
    args = list(argv)
    if not args:
        raise ValueError("run_process needs a program to run")
    started = time.monotonic()
    out_fd = -1
    try:
        if output_file is not None:
            try:
                out_fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW | _O_CLOEXEC, 0o600)
            except (OSError, ValueError):
                return _not_run("error", started)
        try:
            proc = subprocess.Popen(  # noqa: S603  (an argument list, never a shell)
                args, shell=False, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE if out_fd < 0 else out_fd, stderr=subprocess.PIPE, cwd=cwd, env=dict(env),
                close_fds=True, start_new_session=True)
        except (FileNotFoundError, NotADirectoryError):
            return _not_run("not_found", started)
        except (OSError, ValueError, TypeError):
            return _not_run("error", started)
    finally:
        if out_fd >= 0:
            os.close(out_fd)                               # the child holds its own copy
    return _supervise(proc, stdin, started, _clamp_timeout(timeout_s))


def run_helper_script(name: str, args: Sequence[str], *, cfg: Config, timeout_s: "float | None" = None,
                      env_extra: "Mapping[str, str] | None" = None) -> ProcessResult:
    """Run one of ``HELPER_SCRIPTS`` as a program: ``[sys.executable, "-I", <path>, *args]`` with the environment of
    ``child_env`` (the ``JAR_*`` and ``OFFICE_*`` knobs reach the helper through it). The helper prints ``FACT`` lines or
    writes the view files named in ``args``; parsing is the caller's job. Unknown ``name`` raises ``KeyError``.

    ``timeout_s`` None means: ``Limits.helper_timeout_s``, but for the two helpers that arm their own alarm (``jar``, ``office``) never less than their
    time budget knob (``JAR_TIME_BUDGET_S`` / ``OFFICE_TIME_BUDGET_S``, read from the environment the helper will see) plus its 10 s alarm margin
    plus 20 s of slack, so a raised knob is not cut off by a shorter process timeout. A ``timeout_s`` that is given is used as it is."""
    path = _helper_path(name)                              # KeyError for a name that is not one of the four programs
    env = child_env(cfg, extra=env_extra)
    if timeout_s is None:
        timeout_s = cfg.limits.helper_timeout_s
        knob = _HELPER_BUDGET_KNOB.get(name)
        if knob is not None:
            timeout_s = max(timeout_s, env_number(env, knob, _HELPER_BUDGET_DEFAULT_S) + _HELPER_TIMEOUT_MARGIN_S)
    if not sys.executable:                                 # an embedded interpreter with no executable cannot start a helper: said, not skipped
        return ProcessResult("not_found", None, b"", b"", False, 0.0)
    return run_process([sys.executable, "-I", path, *args], env=env, timeout_s=timeout_s)


def _helper_path(name: str) -> str:
    """The absolute path of the helper program ``name`` (``HELPER_SCRIPTS``). The ONE place that turns a table entry into a file, so that the
    zipapp of Phase 6 can extract the four programs to a private directory and change this function alone."""
    relative = HELPER_SCRIPTS[name]
    transit_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(transit_dir, *relative.split("/"))


def _clamp_timeout(value: float) -> float:
    """``value`` as a usable number of seconds: not a number or not above 0 means 0 (an immediate timeout, never an unbounded wait), and at most a year."""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not seconds > 0:
        return 0.0
    return min(seconds, _MAX_TIMEOUT_S)


def _not_run(status: str, started: float) -> ProcessResult:
    return ProcessResult(status, None, b"", b"", False, time.monotonic() - started)


def _kill_group(proc: "subprocess.Popen[bytes]") -> None:
    """SIGKILL to the whole process group of ``proc`` (it leads one: ``start_new_session``), falling back to the process alone. Called before
    ``proc`` is reaped, so the group id is still its own."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def _reap(proc: "subprocess.Popen[bytes]", seconds: float) -> "int | None":
    try:
        return proc.wait(timeout=max(seconds, 0.0))
    except subprocess.TimeoutExpired:
        return None


def _close_pipes(proc: "subprocess.Popen[bytes]") -> None:
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass


def _supervise(proc: "subprocess.Popen[bytes]", stdin: "bytes | None", started: float, timeout_s: float) -> ProcessResult:
    """Feed ``stdin``, drain the pipes up to ``MAX_CAPTURE_BYTES`` each, and wait, all in this thread and bounded by one deadline. Nothing here
    can block for longer than ``timeout_s``: every wait is a ``select`` with the time that is left, and a timeout ends in SIGKILL to the group."""
    deadline = started + timeout_s
    limit = MAX_CAPTURE_BYTES
    captured = {"out": bytearray(), "err": bytearray()}
    truncated = False
    timed_out = False
    pending = memoryview(stdin) if stdin else None
    try:
        selector = selectors.DefaultSelector()
        try:
            if proc.stdin is not None:
                if pending:
                    os.set_blocking(proc.stdin.fileno(), False)
                    selector.register(proc.stdin.fileno(), selectors.EVENT_WRITE, "in")
                else:
                    proc.stdin.close()
            if proc.stdout is not None:
                selector.register(proc.stdout.fileno(), selectors.EVENT_READ, "out")
            if proc.stderr is not None:
                selector.register(proc.stderr.fileno(), selectors.EVENT_READ, "err")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _events in selector.select(timeout=remaining):
                    if key.data == "in":
                        try:
                            written = os.write(key.fd, pending[:_WRITE_CHUNK])  # type: ignore[index]
                        except BlockingIOError:
                            continue
                        except OSError:                    # the child closed its input (BrokenPipeError): nothing more to give
                            selector.unregister(key.fd)
                            proc.stdin.close()             # type: ignore[union-attr]
                            continue
                        pending = pending[written:]  # type: ignore[index]
                        if not pending:
                            selector.unregister(key.fd)
                            proc.stdin.close()             # type: ignore[union-attr]
                        continue
                    try:
                        chunk = os.read(key.fd, _READ_CHUNK)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        selector.unregister(key.fd)
                        continue
                    buffer = captured[key.data]
                    room = limit - len(buffer)
                    if room > 0:
                        buffer += chunk[:room]
                    if len(chunk) > room:
                        truncated = True                   # read and dropped: the child is never blocked on a full pipe
        finally:
            selector.close()
        returncode: "int | None" = None
        if not timed_out:
            # both pipes are closed, so the child is ending: a short grace past the deadline keeps a child that finished at the last moment an "ok"
            returncode = _reap(proc, max(deadline - time.monotonic(), _EXIT_GRACE_S))
            timed_out = returncode is None
        if timed_out:
            _kill_group(proc)
            _reap(proc, _REAP_WAIT_S)
    except BaseException:
        _kill_group(proc)                                  # an interrupted engine never leaves a tool running
        _reap(proc, _REAP_WAIT_S)
        raise
    finally:
        _close_pipes(proc)
    elapsed = time.monotonic() - started
    out, err = bytes(captured["out"]), bytes(captured["err"])
    if timed_out:
        return ProcessResult("timeout", None, out, err, truncated, elapsed)
    if returncode is None:                                 # not reachable: a child that was not reaped is a timeout above
        return ProcessResult("error", None, out, err, truncated, elapsed)
    return ProcessResult("signal" if returncode < 0 else "ok", returncode, out, err, truncated, elapsed)


@dataclasses.dataclass(frozen=True)
class Record:
    """One verdict call a wrapper asks for. ``kind`` is ``pass``, ``warn`` or ``fail``; ``file`` is the recorded path
    (``scan_dir/rel``, ``scan_dir``, or ``__global__``); ``message`` is the exact contract-5 text; ``severity`` is
    ``None`` unless the tool reports one as a field (D-016)."""
    kind: str
    file: str
    message: str = ""
    severity: "str | None" = None


@dataclasses.dataclass(frozen=True)
class ToolRequest:
    """Input of ``ToolWrapper.run``. ``target`` is None for a whole-directory tool (it uses ``scan_dir``) and the recorded
    path of the file for a per-file tool. ``temp`` is ``files.TempArea`` (typed ``object`` here to keep the layering)."""
    cfg: Config
    scan_dir: str
    target: "str | None"
    temp: object
    exclude_dirs: tuple[str, ...]
    info: ToolInfo


@dataclasses.dataclass(frozen=True)
class ToolOutcome:
    """What a wrapper reports back. The wrapper RUNS and PARSES; it never records anything itself.

    ``layer_state``: ``ran``, ``skipped:<reason>`` or ``partial:<reason>`` for a whole-directory tool; None for a per-file
    tool. It is ``ran`` ONLY if the tool started, ended with a status the wrapper understands AND its output parsed (S9);
    otherwise ``skipped:<tool> failed (exit <rc>)`` / ``skipped:<tool> timed out`` / ``skipped:<tool> output not parseable``,
    together with a WARN or FAIL in ``records``. ``records``: the verdict calls in the order bash made them. ``notes``:
    console-only, sanitised excerpts. ``exit_code``/``timed_out``: for tests and for the console."""
    layer_state: "str | None"
    records: tuple[Record, ...] = ()
    notes: tuple[str, ...] = ()
    exit_code: "int | None" = None
    timed_out: bool = False


class ToolWrapper(abc.ABC):
    """One external tool. A subclass sets the class attributes and implements ``run``.

    ``name``: the wrapper key, a key of ``DIRECTORY_TOOLS`` or ``FILE_TOOLS`` (``gitleaks``, ``semgrep-js``); ``binary``: the executable
    on ``PATH`` (``DIRECTORY_TOOLS[name]`` or ``FILE_TOOLS[name]``). ``layer``: the coverage id it feeds (``L1_secrets_gitleaks``) or
    ``L5_per_language_sast`` for a per-file tool. ``scope``: ``directory`` or ``file``. ``missing_message`` /
    ``missing_state``: the exact WARN text and coverage state when the tool is not installed (contract 5.1 "missing tool" and
    7), e.g. ``gitleaks missing — secret scan skipped`` and ``skipped:gitleaks not installed``; unused for per-file tools,
    whose scanner writes ``bandit missing`` itself.
    """
    name: str = ""
    binary: str = ""
    layer: str = ""
    scope: str = "directory"
    missing_message: str = ""
    missing_state: str = ""

    @abc.abstractmethod
    def run(self, request: ToolRequest) -> ToolOutcome:
        """Invoke the tool with ``run_process`` and return a ``ToolOutcome``. MUST: use an argument list; apply the offline flags
        of INSTALL.md section 11 for this tool; bound the time; treat any exit status it does not document as a failure
        (``layer_state`` not ``ran``), never as zero findings; never print captured output (S10); put no repository text
        into ``layer_state``. Tests run it against stub executables on a private ``PATH``."""
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class WrapperSet:
    """The wrappers that could be loaded, keyed by tool name, and the import failures (class name and module only, never
    a message that could carry repository text)."""
    wrappers: Mapping[str, ToolWrapper]
    load_errors: tuple[str, ...] = ()

    def get(self, name: str) -> "ToolWrapper | None":
        return self.wrappers.get(name)


def load_wrappers() -> WrapperSet:
    """Import every module of this package whose name ends in ``_wrapper`` and collect its module-level ``WRAPPERS`` tuple, keyed
    by ``ToolWrapper.name`` (which must be a key of ``DIRECTORY_TOOLS`` or ``FILE_TOOLS``, else ``ValueError``). Modules without that suffix (the two old scripts) are never imported. A wrapper module that
    fails to import is NOT fatal: its tool simply has no wrapper, which the not-ported policy reports, and the failure is
    listed in ``load_errors`` (the pipeline prints it and records ``engine:wrapper_load_error:<module>`` as a WARN).
    Two wrappers with the same ``name`` raise ``ValueError``.

    Load errors are ``"<module>:<ExceptionClass>"`` (an exception of any kind at import, ``SystemExit`` included), ``"<module>:no_WRAPPERS"`` (the module has
    no ``WRAPPERS``) and ``"<module>:invalid_WRAPPERS"`` (it is not a tuple of ``ToolWrapper`` instances), in module-name order. A module whose name starts
    with ``_`` is private and skipped. The text of an exception is never kept."""
    known = frozenset(DIRECTORY_TOOLS) | frozenset(FILE_TOOLS)
    found: "dict[str, ToolWrapper]" = {}
    errors: "list[str]" = []
    for short in sorted(info.name for info in pkgutil.iter_modules(__path__) if info.name.endswith("_wrapper")):
        if short.startswith("_"):
            continue
        label = _word(short)
        try:
            module = importlib.import_module(__name__ + "." + short)
        except (Exception, SystemExit) as exc:             # a module that cannot be imported costs its own tools, never the run
            errors.append("%s:%s" % (label, _word(type(exc).__name__)))
            continue
        if not hasattr(module, "WRAPPERS"):
            errors.append(label + ":no_WRAPPERS")
            continue
        declared = getattr(module, "WRAPPERS")
        if not isinstance(declared, tuple) or not all(isinstance(item, ToolWrapper) for item in declared):
            errors.append(label + ":invalid_WRAPPERS")
            continue
        for wrapper in declared:
            if wrapper.name not in known:
                raise ValueError("wrapper %r of %s is not a tool of DIRECTORY_TOOLS or FILE_TOOLS" % (wrapper.name, label))
            if wrapper.name in found:
                raise ValueError("two wrappers for the tool %r (the second is in %s)" % (wrapper.name, label))
            found[wrapper.name] = wrapper
    return WrapperSet(wrappers=types.MappingProxyType(dict(sorted(found.items()))), load_errors=tuple(errors))
