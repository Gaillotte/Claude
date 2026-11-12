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
from typing import Mapping, Sequence

from transit.config import Config

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


@dataclasses.dataclass(frozen=True)
class ToolInfo:
    """A tool that was found on ``PATH``: ``name`` as asked, ``path`` absolute."""
    name: str
    path: str


class ToolLocator:
    """``command -v`` with a cache. Looks in the ``PATH`` of ``Config.environ`` (a test puts a stub directory first)."""

    def __init__(self, cfg: Config) -> None:
        raise NotImplementedError

    def find(self, name: str) -> "ToolInfo | None":
        """The executable ``name`` (no path separator allowed; ``ValueError`` otherwise), or None."""
        raise NotImplementedError


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
    ``GITLEAKS_CONFIG`` and ``GITLEAKS_CONFIG_TOML``, S8d). A fresh dict; ``os.environ`` is not touched."""
    raise NotImplementedError


def run_process(argv: Sequence[str], *, env: Mapping[str, str], timeout_s: float, cwd: "str | None" = None,
                stdin: "bytes | None" = None, output_file: "str | None" = None) -> ProcessResult:
    """Run ``argv`` WITHOUT a shell (S6): ``subprocess`` with an argument list, ``shell=False``, ``stdin`` closed unless given,
    a new session so that on timeout the whole process group is killed, and the timeout enforced for sure (kill, then wait).
    Every argument that comes from the repository (a path) must be absolute or follow ``--``. ``output_file`` sends stdout
    to that file instead of memory. Never raises for a failing child; raises ``ValueError`` for an empty ``argv``."""
    raise NotImplementedError


def run_helper_script(name: str, args: Sequence[str], *, cfg: Config, timeout_s: "float | None" = None,
                      env_extra: "Mapping[str, str] | None" = None) -> ProcessResult:
    """Run one of ``HELPER_SCRIPTS`` as a program: ``[sys.executable, "-I", <path>, *args]`` with the environment of
    ``child_env`` (the ``JAR_*`` and ``OFFICE_*`` knobs reach the helper through it). The helper prints ``FACT`` lines or
    writes the view files named in ``args``; parsing is the caller's job. Unknown ``name`` raises ``KeyError``."""
    raise NotImplementedError


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
        raise NotImplementedError


def load_wrappers() -> WrapperSet:
    """Import every module of this package whose name ends in ``_wrapper`` and collect its module-level ``WRAPPERS`` tuple, keyed
    by ``ToolWrapper.name`` (which must be a key of ``DIRECTORY_TOOLS`` or ``FILE_TOOLS``, else ``ValueError``). Modules without that suffix (the two old scripts) are never imported. A wrapper module that
    fails to import is NOT fatal: its tool simply has no wrapper, which the not-ported policy reports, and the failure is
    listed in ``load_errors`` (the pipeline prints it and records ``engine:wrapper_load_error:<module>`` as a WARN).
    Two wrappers with the same ``name`` raise ``ValueError``."""
    raise NotImplementedError
