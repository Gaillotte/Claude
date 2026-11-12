"""The file system side of a run: which files are scanned, how one file is read, temporary files, and the content hashes.

Owner of: contract 2 (``WORK_DIR`` sub-directories), 3.5 and S16 (temporary files), 4 (``source.sha256``, ``repo_hash``),
8.2 to 8.6 (default exclusions, ``.transitignore``, what ``find`` lists, diff mode), S14 (nothing is written under the scan
directory), S15 (hostile ``.transitignore``), and the bounded read of one file (S12).

Layering: depends on ``transit.config``, ``transit.rules`` (only for the ``Target`` type), ``transit.rx``. NO regular
expressions are compiled here: ``.transitignore`` is repository text, so its globs are matched by ``glob_match``, an
iterative matcher whose cost is O(len(pattern) * len(path)) and cannot backtrack exponentially.

All paths are ``str`` decoded with ``surrogateescape`` (what ``os.scandir`` returns for a ``str`` argument). A path that
is recorded in a report is ``scan_dir + "/" + rel`` (``findings.join_scan_path``).
"""
from __future__ import annotations

import dataclasses
from typing import Iterator, Mapping, Sequence

from transit.config import Config, Limits
from transit.rules import Target

#: Contract 8.5: skipped by name wherever it is.
MANIFEST_SKIP_NAME = ".manifest_sha256.txt"


class FileReadError(Exception):
    """A file that was listed could not be read. ``reason`` is an engine-generated word (``vanished``, ``too_large``,
    ``permission``, ``io``), safe to put in a message; the path and the OS error text are not."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class FileEntry:
    """One regular file chosen for the per-file layers. ``path`` is the recorded string (``scan_dir/rel``); ``rel`` is the
    path below the scan directory; ``size`` is the ``lstat`` size at listing time."""
    path: str
    rel: str
    size: int


class FileView:
    """One file, read at most once. Created by ``layers.run_file_layers`` for each ``FileEntry``, shared by the universal
    layer and the family scanner, and released (``release()``) before the next file so a 500 MB repository never holds
    more than one file in memory.

    ``data()`` reads the whole file as ``bytes`` (the engine matches on bytes, like ``grep`` in the C locale). A file that
    is no longer a regular file when its turn comes is bash's ``[[ -f ]] || continue``: ``data()`` raises
    ``FileReadError("vanished")`` and the caller skips it silently. Any other failure is raised as ``FileReadError`` and
    becomes a FAIL ``engine:file_unreadable:<reason>`` (bash greps with ``2>/dev/null`` and reads an unreadable file as
    clean; the Python engine must not)."""

    def __init__(self, path: str, rel: str, limits: Limits) -> None:
        raise NotImplementedError

    @property
    def path(self) -> str:
        raise NotImplementedError

    @property
    def rel(self) -> str:
        raise NotImplementedError

    @property
    def basename(self) -> str:
        raise NotImplementedError

    @property
    def ext(self) -> str:
        """Lower-cased text after the LAST ``.`` of the FULL path (not the basename); a path with no dot gives the whole path
        (contract 8.8 rule 3). The leading dot is not included."""
        raise NotImplementedError

    def data(self) -> bytes:
        """Whole content, cached. Raises ``FileReadError`` (``too_large`` above ``Limits.max_file_bytes``)."""
        raise NotImplementedError

    def head(self, n: int = 8192) -> bytes:
        """The first ``n`` bytes without reading the rest when ``data()`` has not been called (sniffing: RTF, Flat OPC)."""
        raise NotImplementedError

    def first_line(self) -> bytes:
        """The bytes before the first LF (the whole file if there is none) with NUL bytes removed, as bash ``read -r``
        delivers them. Used for shebang routing; reads through ``data()``, so there is no length cap to evade."""
        raise NotImplementedError

    def has_long_line(self) -> bool:
        """True if any line is longer than ``Limits.long_line_bytes``. Computed once per file (``rx.lines_over``). Decides
        between the backtracking and the linear matcher (design section 9.2)."""
        raise NotImplementedError

    def flat(self) -> bytes:
        """``rx.flat_view(data())``, cached: CR, LF, TAB folded to spaces; ``b""`` above ``rx.FLAT_CAP`` (grep_flat)."""
        raise NotImplementedError

    def target(self, data: "bytes | None" = None) -> Target:
        """A ``rules.Target`` for this file, or for derived bytes ``data`` (a decoded view, an extracted text) with the
        same basename and extension. ``has_long_line`` is recomputed for derived data."""
        raise NotImplementedError

    def release(self) -> None:
        """Drop every cached buffer."""
        raise NotImplementedError


class TempArea:
    """Contract 3.5 and S16. A private directory ``<tmpdir>/aitransit_<random>`` (mode 0700) holding every temporary
    file of the run: text views for the helper scripts, the generated gitleaks config, tool output captured to disk.
    Names are unpredictable and files are mode 0600 and created with ``O_EXCL``. ``cleanup`` removes everything and is
    idempotent. ``pipeline.main`` calls it in a ``finally`` and registers it with ``atexit`` and the signal handlers, so it
    runs on every exit path, including an abort and SIGTERM."""

    def __init__(self, tmpdir: str) -> None:
        raise NotImplementedError

    @property
    def path(self) -> str:
        raise NotImplementedError

    def new_file(self, suffix: str = "") -> str:
        """Create an empty file (0600) and return its path. ``suffix`` is a constant chosen by the caller, never repository text."""
        raise NotImplementedError

    def new_dir(self) -> str:
        """Create a sub-directory (0700) and return its path."""
        raise NotImplementedError

    def cleanup(self) -> None:
        raise NotImplementedError

    def __enter__(self) -> "TempArea":
        raise NotImplementedError

    def __exit__(self, *exc: object) -> None:
        raise NotImplementedError


def prepare_work_dirs(work_dir: str) -> None:
    """Create ``WORK_DIR/reports``, ``WORK_DIR/quarantine`` (mode 0700) and ``WORK_DIR/approved`` with parents (``mkdir -p``;
    D-027: created although unused). Raises ``OSError`` if that is impossible; ``pipeline`` then aborts with exit 1."""
    raise NotImplementedError


def read_repo_config_file(scan_dir: str, name: str, *, max_bytes: int = 1 << 20) -> "tuple[bytes | None, str | None]":
    """Read ``scan_dir/name`` (``.transit-allow.json`` or ``.transitignore``; ``name`` has no separator, else ``ValueError``) as
    repository configuration, S15 / D-036: it must be a REGULAR file that is NOT a symlink (``lstat``) and at most ``max_bytes``. Returns
    ``(bytes, None)``; ``(None, None)`` if there is no such entry; ``(None, note)`` if it exists but is refused or unreadable (a symlink,
    a FIFO, too large, a permission error): the note is for the console and the file is treated as absent, so a refusal can only
    REMOVE exceptions, never add them. Never follows a link, never opens a device or a FIFO (an ``open`` on a FIFO blocks forever)."""
    raise NotImplementedError


def contained_path(scan_dir: str, path: str) -> "str | None":
    """For a wrapper that must map a path reported by a tool (absolute, or relative to ``scan_dir``) to the recorded path: the
    ``os.path.abspath``-normalised path if it lies at or below ``os.path.abspath(scan_dir)``, else None. Textual only (no file
    system access, no symlink resolution): the result is a dictionary key, never a path the engine opens. A None means "not a file
    of this repository" and the wrapper records the finding against ``scan_dir`` itself."""
    raise NotImplementedError


def glob_match(pattern: str, text: str) -> bool:
    """``fnmatch(3)`` without FNM_PATHNAME, as ``find -path`` applies it: ``*`` matches any string INCLUDING ``/``; ``?`` any
    one character; ``[...]`` a set with ``!`` or ``^`` negation and ranges; ``\\x`` the character x. Iterative, one saved
    star position, so it is O(len(pattern) * len(text)). Pure."""
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class Exclusions:
    """Contract 8.2 to 8.4 (D-001/D-002 closed). ``dir_names``: the 14 built-in names, which prune a DIRECTORY with that
    basename at any depth below the scan root. ``patterns``: the ``.transitignore`` lines, each used as a ``find -path`` glob:
    an entry (file or directory) whose path below the root matches the glob, or any suffix of it that starts after a ``/``,
    is excluded and, if a directory, not entered. Blank lines and lines starting ``#`` are not patterns."""
    dir_names: tuple[str, ...]
    patterns: tuple[str, ...]

    def excludes(self, rel: str, *, is_dir: bool) -> bool:
        """True if the entry at ``rel`` (path below the scan root, no leading slash) is excluded."""
        raise NotImplementedError

    def semgrep_dirs(self) -> tuple[str, ...]:
        """Names given to Semgrep / ClamAV as ``--exclude-dir`` (built-ins then patterns, contract 8.1)."""
        raise NotImplementedError


def load_exclusions(scan_dir: str, *, cfg: Config) -> "tuple[Exclusions, tuple[str, ...]]":
    """Read ``scan_dir/.transitignore`` through ``read_repo_config_file`` and return the exclusions plus the console notes.
    Bash behaviour (D-003 ``proposed``, so copied): a last line without a newline is DROPPED, a line keeps a trailing CR
    (so a CRLF file never matches). With switch ``D-003`` the last line is read and one trailing CR is removed. A file that
    cannot be read or decoded yields no patterns and a note (S15: never a crash, never an exclusion that was not read).
    With switch ``D-004`` the second result carries the WARN text ``transitignore:exclusions_applied(<n> pattern(s))``
    for the pipeline to record on ``__global__``."""
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class DiffSelection:
    """Contract 8.6. ``active``: ``.diff_files`` exists in WORK_DIR AND ``SINCE_COMMIT`` is non-empty. ``keys``: the
    surviving entries as comparison keys (see ``load_diff_selection``). ``stale_ignored``: the file exists but SINCE_COMMIT
    is empty (a console WARN, nothing in the report)."""
    active: bool
    keys: frozenset[str]
    stale_ignored: bool


def load_diff_selection(work_dir: str, since_commit: str, scan_dir: str) -> DiffSelection:
    """Parse ``WORK_DIR/.diff_files``: entries are terminated by ``:``; the text after the last ``:`` (including a trailing
    newline) is dropped; an entry is kept only if it names an existing regular file. Comparison key of a path (D-019, always
    on): ``os.path.abspath`` of it, applied to both the entries here and to ``FileEntry.path`` in ``files_for_scan``, so a
    relative scan directory no longer matches nothing. With diff mode active and an empty set nothing is scanned and the
    run is PASS with L4 and L5 ``ran`` (golden ``diff_mode_zero_files``)."""
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class ScanList:
    """The files of the per-file layers, sorted by the bytes of ``rel``, plus the directories that could not be listed
    (``errors`` holds ``rel`` paths; ``layers.run_file_layers`` records ONE WARN ``engine:unreadable_directories(<n>)`` and
    ``note_incomplete`` on L4 and L5; bash lists with ``2>/dev/null`` and loses them silently)."""
    entries: tuple[FileEntry, ...]
    errors: tuple[str, ...]


def files_for_scan(scan_dir: str, exclusions: Exclusions, diff: DiffSelection) -> ScanList:
    """Contract 8.5: regular files only (``lstat``; symlinks to files and to directories are neither listed nor followed),
    hidden files included, pruned by ``exclusions``, restricted to ``diff.keys`` when ``diff.active``, ``.manifest_sha256.txt``
    skipped. The scan root itself is never tested against the exclusions (D-001). Deterministic order."""
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class SourceHashes:
    """``sha256``: contract 4 ``source.sha256``; ``repo_hash``: contract 4 ``repo_hash``."""
    sha256: str
    repo_hash: str


def compute_hashes(scan_dir: str) -> SourceHashes:
    """``source.sha256`` = SHA-256 of the lines ``<hex>  ./<rel>`` (two spaces, LF) of EVERY regular file under ``scan_dir``
    (no exclusion applies; symlinks excluded), sorted by the BYTES of the whole ``./<rel>`` string (``LC_ALL=C sort -z``,
    so ``a.b`` sorts before ``a/b``). A name containing a backslash or LF is written in ``sha256sum``'s escaped form
    (``\\<hex>  <name with \\\\ and \\n escaped>``). If any file cannot be read, ``sha256`` falls back to ``repo_hash`` (what the
    bash pipeline does). ``repo_hash`` = SHA-256 of ``scan_dir/<rel>`` lines of the same files sorted bytewise (bash sorts
    by locale; the value depends on the location and the normaliser drops it). Reads in 1 MiB chunks."""
    raise NotImplementedError
