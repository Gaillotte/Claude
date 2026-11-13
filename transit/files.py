"""The file system side of a run: which files are scanned, how one file is read, temporary files, and the content hashes.

Owner of: contract 2 (``WORK_DIR`` sub-directories), 3.5 and S16 (temporary files), 4 (``source.sha256``, ``repo_hash``),
8.2 to 8.6 (default exclusions, ``.transitignore``, what ``find`` lists, diff mode), S14 (nothing is written under the scan
directory), S15 (hostile ``.transitignore``), and the bounded read of one file (S12).

Layering: depends on ``transit.config``, ``transit.findings`` (only ``join_scan_path``, a pure function), ``transit.rules`` (only for
the ``Target`` type) and ``transit.rx``. NO regular expressions are compiled here: ``.transitignore`` is repository text, so its globs
are matched by ``glob_match``, an iterative matcher whose cost is O(len(pattern) * len(path)) and cannot backtrack exponentially.

All paths are ``str`` decoded with ``surrogateescape`` (what ``os.scandir`` returns for a ``str`` argument). A path that
is recorded in a report is ``scan_dir + "/" + rel`` (``findings.join_scan_path``).

PATH_MAX (review log R-09). A path string longer than the kernel's PATH_MAX (4096 bytes) cannot be passed to ``open``, ``lstat`` or
``scandir``; 17 nested directories of 255 characters are enough, and GNU ``find`` (which walks with directory descriptors) lists
such a file while bash then fails to open it and passes the repository. So this module NEVER walks or opens a repository file by
its path string: ``files_for_scan`` lists each directory through a descriptor opened relative to its parent, and ``open_beneath`` opens
a file component by component (``dir_fd=``, ``O_NOFOLLOW``). The recorded ``path`` is only a dictionary key. A side benefit: a
symlink swapped into the tree during the run is never followed.

What this module does NOT do (review log R-01): it skips no file because of its NAME. Bash skipped every file called
``.manifest_sha256.txt`` at any depth, which let a hostile repository hide any payload under that name inside the approved archive
(``ai_transit.sh`` excludes only the root-level one from the ZIP).
"""
from __future__ import annotations

import dataclasses
from typing import Iterator, Mapping, Sequence

from transit.config import Config, Limits
from transit.rules import Target

#: Deepest directory nesting below the scan root that ``files_for_scan`` enters. A deeper directory is reported as unreadable
#: (reason ``too_deep``), never skipped silently. 512 is far beyond any real project; the cost of opening a directory is O(depth), so
#: the whole walk is bounded by O(directories * 512).
MAX_WALK_DEPTH = 512

#: ``.transitignore`` limits (review log R-15, S12/S15). A pattern is a GLOB if it contains one of ``GLOB_METACHARS``; otherwise it is a
#: LITERAL, kept in a set and tested by lookup (O(depth) per entry however many there are). More than ``MAX_GLOB_PATTERNS`` globs, or
#: any pattern longer than ``MAX_PATTERN_CHARS``, makes ``load_exclusions`` REFUSE THE WHOLE FILE: no exclusion is applied and a
#: console note says why. Refusing can only make the scan examine MORE, so it is the fail-safe direction.
MAX_GLOB_PATTERNS = 64
MAX_PATTERN_CHARS = 256
GLOB_METACHARS = "*?[\\"


class FileReadError(Exception):
    """A file that was listed could not be read. ``reason`` is an engine-generated word (``vanished``, ``too_large``,
    ``permission``, ``io``), safe to put in a message; the path and the OS error text are not."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class FileEntry:
    """One regular file chosen for the per-file layers. ``path`` is the recorded string (``scan_dir/rel``); ``rel`` is the
    path below the scan directory; ``size`` is the ``lstat`` size at listing time (``layers`` scales the per-file deadline with it)."""
    path: str
    rel: str
    size: int


def open_beneath(scan_dir: str, rel: str) -> int:
    """Open the regular file ``rel`` below ``scan_dir`` for reading and return the descriptor (the caller closes it). The root is opened
    with ``O_DIRECTORY``; every further component is opened relative to the previous descriptor with ``O_NOFOLLOW`` (so no symlink is
    followed at any level, and the length of the whole path does not matter); the last one is opened ``O_RDONLY | O_NOFOLLOW |
    O_NONBLOCK`` (a FIFO swapped in after listing must not block the engine) and checked with ``fstat`` to be a regular file.
    ``rel`` is split on ``/``; a component that is empty, ``.`` or ``..`` raises ``ValueError`` (a programming error: ``rel`` comes
    from ``files_for_scan``, never from a tool). Raises ``FileReadError``: ``vanished`` (ENOENT, ENOTDIR, ELOOP, or not a regular
    file any more), ``permission`` (EACCES, EPERM), ``io`` (anything else). Costs O(number of components) system calls."""
    raise NotImplementedError


class FileView:
    """One file, read at most once. Created by ``layers.run_file_layers`` for each ``FileEntry``, shared by the universal
    layer and the family scanner, and released (``release()``) before the next file so a 500 MB repository never holds
    more than one file in memory.

    ``data()`` reads the whole file as ``bytes`` (the engine matches on bytes, like ``grep`` in the C locale) through ``open_beneath``. A
    file that is no longer a regular file when its turn comes is bash's ``[[ -f ]] || continue``: ``data()`` raises
    ``FileReadError("vanished")`` and the caller skips it silently. Any other failure is raised as ``FileReadError`` and
    becomes a FAIL ``engine:file_unreadable:<reason>`` (bash greps with ``2>/dev/null`` and reads an unreadable file as
    clean; the Python engine must not).

    Memory (review log R-04): the bytes of one file, plus at most ONE derived copy of the same size alive at a time (the folded
    ``flat()`` view, or the NUL-to-LF copy that ``binary="grep"`` makes). No method of this class or of ``rules`` may split the whole
    buffer into a list of lines (``bytes.split``, ``splitlines``, ``rx.lines_over``, ``rx.after_context``): that costs about 19 times
    the file size for a file of short lines (measured: 28 MB of ``ab\\n`` peaked at 576 MB). The test suite reads 90 MB of 2-byte lines
    and asserts the peak resident size stays under 3 times the file."""

    def __init__(self, scan_dir: str, rel: str, limits: Limits) -> None:
        """``scan_dir`` as given (trailing slashes removed); ``rel`` below it. ``path`` is ``findings.join_scan_path(scan_dir, rel)``."""
        raise NotImplementedError

    @property
    def path(self) -> str:
        """The recorded string ``scan_dir/rel`` (a dictionary key; never opened)."""
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
        """Whole content, cached. Raises ``FileReadError`` (``too_large`` above ``Limits.max_file_bytes``, checked with ``fstat``
        before reading and again against what was read, so a file that grows is not read past the cap)."""
        raise NotImplementedError

    def head(self, n: int = 8192) -> bytes:
        """The first ``n`` bytes without reading the rest when ``data()`` has not been called (sniffing: RTF, Flat OPC)."""
        raise NotImplementedError

    def first_line(self) -> bytes:
        """The bytes before the first LF (the whole file if there is none) with NUL bytes removed, as bash ``read -r``
        delivers them. Used for shebang routing; reads through ``data()``, so there is no length cap to evade."""
        raise NotImplementedError

    def has_long_line(self) -> bool:
        """True if any line (a run of bytes between LFs, or after the last LF) is longer than ``Limits.long_line_bytes`` (L). Computed once
        per file. Decides between the backtracking and the linear matcher (design section 9.2).

        Algorithm, O(1) extra memory and about 0.2 s per GiB: let ``h = (L + 1) // 2`` and walk the aligned blocks ``[k*h, (k+1)*h)``.
        A run of L + 1 bytes without an LF always contains one whole aligned block, so a block with ``data.count(b"\\n", s, s + h) == 0``
        is a CANDIDATE; for a candidate find the real line with ``data.rfind(b"\\n", 0, s) + 1`` and ``data.find(b"\\n", s + h)`` (end of
        data if none) and compare its length with L. Every ``count`` runs at C speed, so a file of two-byte lines costs one call per ``h``
        bytes, not one per line. FORBIDDEN here: ``rx.lines_over``, ``bytes.split``, ``splitlines``, a Python loop over lines, ``re``.
        The unit test compares it with ``any(len(x) > L for x in data.split(b"\\n"))`` on random buffers for L in 1..20."""
        raise NotImplementedError

    def flat(self) -> bytes:
        """The file with CR, LF and TAB folded to spaces (``rx.flat_view(data(), cap=len(data()))``), cached, WITHOUT a size cap
        (review log R-08, D-039): bash's ``grep_flat`` returned "no match" for a file over 5 MiB, which let a hostile XML pad itself
        past the cap and hide an external entity. The folded view is one line, so every flat rule on a file over ``long_line_bytes`` runs
        on the linear matcher; its cost is covered by the per-file deadline. One extra copy of the file lives while a flat rule runs."""
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
    runs on every exit path, including an abort and SIGTERM.

    The constructor raises ``OSError`` if ``tmpdir`` is not writable; ``pipeline`` is already inside the D-028 handler by then (the
    ``Verdict`` exists), so that becomes a FAIL ``engine:internal_error:OSError`` report (review log R-05)."""

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
    D-027: created although unused). Raises ``OSError`` if that is impossible; ``pipeline`` then prints one ``Console.error`` line and
    returns 1: no verdict line, no report, no sidecar (contract 3.2 "Aborted after validation")."""
    raise NotImplementedError


def read_repo_config_file(scan_dir: str, name: str, *, max_bytes: int = 1 << 20) -> "tuple[bytes | None, str | None]":
    """Read ``scan_dir/name`` (``.transit-allow.json`` or ``.transitignore``; ``name`` has no separator, else ``ValueError``) as
    repository configuration, S15 / D-036: it must be a REGULAR file that is NOT a symlink (``lstat``) and at most ``max_bytes``. Returns
    ``(bytes, None)``; ``(None, None)`` if there is no such entry; ``(None, note)`` if it exists but is refused or unreadable (a symlink,
    a FIFO, too large, a permission error): the note is for the console and the file is treated as absent, so a refusal can only
    REMOVE exceptions, never add them. Never follows a link, never opens a device or a FIFO (an ``open`` on a FIFO blocks forever:
    the file is opened ``O_NOFOLLOW | O_NONBLOCK`` and ``fstat`` must say regular). Never raises."""
    raise NotImplementedError


def contained_path(scan_dir: str, path: str) -> "str | None":
    """For a wrapper that must map a path reported by a tool (absolute, or relative to ``scan_dir``) to the RECORDED path.

    Textual only (no file system access, no symlink resolution): both ``path`` (taken relative to ``os.getcwd()`` if it is relative to
    nothing else) and ``scan_dir`` are normalised with ``os.path.abspath`` to decide CONTAINMENT; if ``path`` lies below
    ``abspath(scan_dir)`` the relation ``rel`` between the two normalised strings is computed and the result is
    ``findings.join_scan_path(scan_dir, rel)`` with the ORIGINAL ``scan_dir`` string, which is exactly the key under which the file's
    own ``file_results`` entry is stored (review log R-13: returning the normalised string put the finding under a different key
    whenever ``scan_dir`` was relative or contained ``//`` or ``..``). ``path`` equal to the directory itself gives ``scan_dir``. A
    path outside the directory gives None, meaning "not a file of this repository": the wrapper then records the finding against
    ``scan_dir`` itself. The result is a dictionary key, never a path the engine opens."""
    raise NotImplementedError


def glob_match(pattern: str, text: str) -> bool:
    """``fnmatch(3)`` without FNM_PATHNAME, as ``find -path`` applies it: ``*`` matches any string INCLUDING ``/``; ``?`` any
    one character; ``[...]`` a set with ``!`` or ``^`` negation and ranges; ``\\x`` the character x. Iterative, one saved
    star position, so it is O(len(pattern) * len(text)). Pure."""
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class Exclusions:
    """Contract 8.2 to 8.4 (D-001/D-002 closed). ``dir_names``: the 14 built-in names, which prune a DIRECTORY with that
    basename at any depth below the scan root. ``patterns``: the ``.transitignore`` lines that were accepted (at most
    ``MAX_GLOB_PATTERNS`` globs, each at most ``MAX_PATTERN_CHARS`` characters), each used as a ``find -path`` glob:
    an entry (file or directory) whose path below the root matches the glob, or any suffix of it that starts after a ``/``,
    is excluded and, if a directory, not entered. Blank lines and lines starting ``#`` are not patterns.

    Matching cost (review log R-15): a LITERAL pattern (no character of ``GLOB_METACHARS``) is looked up in a set against the entry's
    path and each of its suffixes after a ``/`` (O(depth) per entry however many literals there are); a glob that begins with ``*``
    needs only the whole path (any suffix match implies it); any other glob is tried on the suffixes whose first character is the
    glob's first character. The result is identical to testing every pattern against every suffix (the 24 pattern sets of F5)."""
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
    cannot be read or decoded yields no patterns and a note (S15: never a crash, never an exclusion that was not read). A file
    that breaks a limit (``MAX_GLOB_PATTERNS`` globs, ``MAX_PATTERN_CHARS`` per pattern) is refused as a whole with a note.
    The notes are console-only. Whether the patterns are REPORTED is not decided here: ``pipeline`` records the WARN
    ``transitignore:exclusions_applied(<n> pattern(s))`` on ``__global__`` whenever ``Exclusions.patterns`` is non-empty, with no
    switch (D-004 implemented, review log R-03; contract S15 requires it)."""
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class DiffSelection:
    """Contract 8.6. ``active``: ``.diff_files`` exists in WORK_DIR AND ``SINCE_COMMIT`` is non-empty. ``keys``: the
    surviving entries as comparison keys (see ``load_diff_selection``). ``stale_ignored``: the file exists but SINCE_COMMIT
    is empty (a console WARN, nothing in the report). ``unresolved``: how many entries looked like part of a file name and could
    not be resolved to a file (see ``load_diff_selection``); ``pipeline`` turns a non-zero count into the WARN
    ``engine:diff_entries_unresolved(<n>)`` and a ``partial`` note on L4 and L5."""
    active: bool
    keys: frozenset[str]
    stale_ignored: bool
    unresolved: int = 0


def load_diff_selection(work_dir: str, since_commit: str, scan_dir: str) -> DiffSelection:
    """Parse ``WORK_DIR/.diff_files``. Never raises. A ``.diff_files`` that exists but cannot be read (or is not a regular file) gives ``active`` with no keys and
    ``unresolved = 1``, so ``pipeline`` records the WARN ``engine:diff_entries_unresolved(1)`` and the ``partial`` notes: an unreadable list
    must not read as "nothing changed".

    Two formats, told apart by a NUL byte (review log R-07, D-042):
      * NUL-separated (the format ``fetch_repo.sh`` will write once it uses ``git diff -z --name-only``; names are never quoted and may
        hold ``:`` or a newline): every non-empty NUL-terminated item is an entry.
      * Legacy (what ``fetch_repo.sh`` writes today, from ``git diff --name-only | sed | tr '\\n' ':'``): entries are terminated by ``:``;
        the text after the last ``:`` (including a trailing newline) is dropped. That format cannot represent a name that contains ``:``
        (it is split in two) and git quotes a name with non-ASCII or special characters (``"\\303\\251.py"``). So, for each ``:``-separated
        piece: (1) a piece of the form ``<prefix>/"..."`` is C-unquoted (octal ``\\ooo``, ``\\n``, ``\\t``, ``\\"``, ``\\\\``); (2) the
        piece, and then the joins of it with the following 1 to 15 pieces (``a`` + ``:`` + ``b.py``), are each tested; every candidate that
        names an existing regular file becomes a key. Extra keys only cause extra files to be scanned. A piece that resolved to nothing,
        was not consumed by a resolved join, and does not start with the (absolute) scan directory as a path prefix is counted in
        ``unresolved``: it is a fragment of a name that could not be rebuilt (or a deleted file with a colon in its name, a rare false alarm).

    Comparison key of a path (D-019, always on): ``os.path.abspath`` of it, applied to both the entries here and to ``FileEntry.path`` in
    ``files_for_scan``, so a relative scan directory no longer matches nothing. With diff mode active and an empty set nothing is scanned and the
    run is PASS with L4 and L5 ``ran`` (golden ``diff_mode_zero_files``)."""
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class ScanList:
    """The files of the per-file layers, sorted by the bytes of ``rel``, plus what could not be listed and what was excluded.
    ``errors``: one ``(rel, reason)`` per directory that could not be listed, reason ``permission``, ``io`` or ``too_deep``
    (deeper than ``MAX_WALK_DEPTH``); ``layers.run_file_layers`` records one non-downgradable FAIL ``engine:directory_unreadable:<reason>``
    for each (the first 200, then one summary), because a directory is a whole subtree that was not examined (bash lists with
    ``2>/dev/null`` and loses it silently; review log R-09). ``excluded_by_patterns``: how many entries (files or directories; a pruned
    directory counts once) the ``.transitignore`` patterns removed; with an empty ``entries`` and a non-zero count ``layers.run_file_layers``
    records the FAIL ``engine:nothing_scanned:transitignore`` (review log R-03)."""
    entries: tuple[FileEntry, ...]
    errors: tuple[tuple[str, str], ...]
    excluded_by_patterns: int = 0


def files_for_scan(scan_dir: str, exclusions: Exclusions, diff: DiffSelection) -> ScanList:
    """Contract 8.5: regular files only (``lstat``; symlinks to files and to directories are neither listed nor followed),
    hidden files included, pruned by ``exclusions``, restricted to ``diff.keys`` when ``diff.active``. NO file is skipped for its name
    (review log R-01: bash skipped ``.manifest_sha256.txt`` at any depth). The scan root itself is never tested against the exclusions
    (D-001). Deterministic order (the bytes of ``rel``).

    The walk uses directory descriptors, not path strings (see the module docstring): the root is opened with ``O_DIRECTORY``, each
    sub-directory is listed with ``os.scandir(fd)`` after being opened relative to its parent with ``O_NOFOLLOW | O_DIRECTORY``, and the
    stack of directories to visit holds ``rel`` strings, not descriptors, so the number of open descriptors stays constant. A directory
    deeper than ``MAX_WALK_DEPTH`` is recorded in ``errors`` as ``too_deep`` and not entered. An entry that vanishes during the walk
    (ENOENT) is dropped silently, as bash's ``[[ -f ]] || continue``; any other ``OSError`` while opening or listing a directory is an
    ``errors`` item. Never raises for a hostile tree."""
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
    by locale; the value depends on the location and the normaliser drops it). Reads in 1 MiB chunks. Walks and opens files the same
    way as ``files_for_scan`` (directory descriptors, ``open_beneath``), so a file below PATH_MAX is hashed too (bash's
    ``find | xargs sha256sum`` could not open it and fell back to ``repo_hash``)."""
    raise NotImplementedError
