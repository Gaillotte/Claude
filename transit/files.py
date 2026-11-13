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

Behaviour of the HARDENED bash engine (2026-11-13) that the frozen interface did not mention, added here as ADDITIVE API (every addition
has a default, so code written against the frozen interface keeps working):

* the C locale. ``glob_match`` compares BYTES (``os.fsencode``), as ``LC_ALL=C find -path`` does: ``?`` is one byte, a byte above 127 is
  in no character class, and ``FileView.ext`` lower-cases A-Z only;
* ``.transitignore`` as the hardened script reads it: a last line without a newline is read, one trailing CR is removed from each line,
  NUL bytes are dropped (bash ``read`` drops them), blank lines and ``#`` lines are skipped (D-003, closed in bash: unconditional here);
* the three CONTROL FILES at the root (``CONTROL_FILE_NAMES``: ``.transitignore``, ``.transit-allow.json``, ``.manifest_sha256.txt``) are
  listed and scanned like any file, but do not count as "something was examined" (``ScanList.examined``, ``ScanList.nothing_scanned``,
  ``is_control_file``): ``engine:nothing_scanned`` is for ``.transitignore`` patterns that removed every file that counts;
* symlinks are reported (``ScanList.symlinks``): FAIL ``symlink:target_outside_the_scanned_directory`` when ``symlink_escapes`` says the
  target text is absolute or climbs above the scan root, else WARN ``symlink:not_followed_its_target_is_not_scanned_through_the_link``;
  the layer above records them, they are never followed here and never subject to the diff selection (bash does not filter them either);
* ``ScanList.listing_exit``: 1 when any directory could not be listed (what ``find`` exits with), for ``engine:file_listing_failed`` and
  the coverage text ``skipped:file listing failed (find exit N)``.
"""
from __future__ import annotations

import collections
import dataclasses
import errno
import hashlib
import os
import secrets
import shutil
import stat as _stat
from typing import Callable, Iterator

from transit import rx
from transit.config import DEFAULT_EXCLUDE_DIRS, Config, Limits
from transit.findings import join_scan_path
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

#: The three files the pipeline itself puts at the root of a scanned directory (hardened bash ``_is_control_file``): the repository's own
#: ``.transitignore`` and ``.transit-allow.json`` and the fetcher's ``.manifest_sha256.txt``. Scanned like any file, never counted as
#: "something was examined". Only the ROOT ones: a nested file of one of these names is an ordinary file.
CONTROL_FILE_NAMES = (".transitignore", ".transit-allow.json", ".manifest_sha256.txt")

#: Largest ``.diff_files`` the engine reads (a list of names of a 500 MB repository is far smaller); a larger one is "cannot be read".
_DIFF_FILES_CAP = 1 << 26
#: How many following pieces a legacy ``.diff_files`` entry may be joined with (a name with 15 colons has 16 pieces).
_MAX_JOIN_PIECES = 15
#: ``sha256sum`` reads in chunks of this size.
_HASH_CHUNK = 1 << 20

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_DIR = os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC
_O_DIR_NOFOLLOW = _O_DIR | _O_NOFOLLOW
_O_FILE = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC

#: ``bash ${x,,}`` in the C locale: A-Z only.
_ASCII_LOWER = {c: c + 32 for c in range(65, 91)}


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


# ── small helpers ──────────────────────────────────────────────────────────────────────────────────────────────────
def _fsb(text: str) -> bytes:
    """``os.fsencode`` that also takes a lone surrogate that is not an escaped byte (a path from a test or a tool, never from ``scandir``)."""
    try:
        return os.fsencode(text)
    except UnicodeEncodeError:
        return text.encode("utf-8", "surrogatepass")


def _close(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _open_reason(exc: OSError) -> str:
    """The word for a failed ``open`` of a file: gone (or not what it was), not allowed, or anything else."""
    number = exc.errno
    if number in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.ENXIO):
        return "vanished"
    if number in (errno.EACCES, errno.EPERM):
        return "permission"
    return "io"


def _walk_reason(exc: OSError) -> str:
    """The word for a directory that could not be opened or listed (``ScanList.errors``)."""
    return "permission" if exc.errno in (errno.EACCES, errno.EPERM) else "io"


def _check_rel(rel: str) -> "list[str]":
    parts = rel.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise ValueError("rel must be a path of plain names below the scan directory")
    return parts


def open_beneath(scan_dir: str, rel: str) -> int:
    """Open the regular file ``rel`` below ``scan_dir`` for reading and return the descriptor (the caller closes it). The root is opened
    with ``O_DIRECTORY``; every further component is opened relative to the previous descriptor with ``O_NOFOLLOW`` (so no symlink is
    followed at any level, and the length of the whole path does not matter); the last one is opened ``O_RDONLY | O_NOFOLLOW |
    O_NONBLOCK`` (a FIFO swapped in after listing must not block the engine) and checked with ``fstat`` to be a regular file.
    ``rel`` is split on ``/``; a component that is empty, ``.`` or ``..`` raises ``ValueError`` (a programming error: ``rel`` comes
    from ``files_for_scan``, never from a tool). Raises ``FileReadError``: ``vanished`` (ENOENT, ENOTDIR, ELOOP, or not a regular
    file any more), ``permission`` (EACCES, EPERM), ``io`` (anything else). Costs O(number of components) system calls."""
    parts = _check_rel(rel)
    try:
        current = os.open(scan_dir, _O_DIR)
    except OSError as exc:
        raise FileReadError(_open_reason(exc)) from None
    try:
        for part in parts[:-1]:
            following = os.open(part, _O_DIR_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
        fd = os.open(parts[-1], _O_FILE, dir_fd=current)
    except OSError as exc:
        _close(current)
        raise FileReadError(_open_reason(exc)) from None
    os.close(current)
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        _close(fd)
        raise FileReadError("io") from None
    if not _stat.S_ISREG(mode):
        _close(fd)
        raise FileReadError("vanished")
    return fd


def _read_fd(fd: int, size: int, cap: int) -> bytes:
    """The whole content of ``fd`` (a regular file whose ``fstat`` size is ``size``). One ``os.read`` of ``size + 1`` bytes in the common
    case, so the bytes object is the only copy; a file that is longer than it said (it grew, or ``fstat`` lied) is read on in pieces and
    refused above ``cap``. Raises ``FileReadError``."""
    try:
        first = os.read(fd, size + 1)
        if len(first) <= size:
            probe = os.read(fd, 1)
            if not probe:
                return first
            parts = [first, probe]
        else:
            parts = [first]
        total = sum(len(p) for p in parts)
        while True:
            if total > cap:
                raise FileReadError("too_large")
            chunk = os.read(fd, _HASH_CHUNK)
            if not chunk:
                break
            parts.append(chunk)
            total += len(chunk)
        if total > cap:
            raise FileReadError("too_large")
        return b"".join(parts)
    except OSError as exc:
        raise FileReadError("permission" if exc.errno in (errno.EACCES, errno.EPERM) else "io") from None


def _has_long_line(data: bytes, limit: int) -> bool:
    """True if some line of ``data`` is longer than ``limit`` bytes, in O(1) extra memory (see ``FileView.has_long_line``)."""
    size = len(data)
    if size <= limit:
        return False
    half = max(1, (limit + 1) // 2)
    count, rfind, find = data.count, data.rfind, data.find
    start = 0
    last = size - half
    while start <= last:
        if count(b"\n", start, start + half) == 0:
            line_start = rfind(b"\n", 0, start) + 1
            line_end = find(b"\n", start + half)
            if line_end < 0:
                line_end = size
            if line_end - line_start > limit:
                return True
            start = ((line_end + half) // half) * half
        else:
            start += half
    return False


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
        stripped = scan_dir.rstrip("/")
        self._scan_dir = stripped if stripped else scan_dir[:1]
        self._rel = rel
        self._limits = limits
        self._path = join_scan_path(self._scan_dir, rel)
        self._basename = rel.rpartition("/")[2]
        self._ext = self._path.rpartition(".")[2].translate(_ASCII_LOWER)
        self._data: "bytes | None" = None
        self._flat: "bytes | None" = None
        self._long: "bool | None" = None

    @property
    def path(self) -> str:
        """The recorded string ``scan_dir/rel`` (a dictionary key; never opened)."""
        return self._path

    @property
    def rel(self) -> str:
        return self._rel

    @property
    def basename(self) -> str:
        return self._basename

    @property
    def ext(self) -> str:
        """Lower-cased text after the LAST ``.`` of the FULL path (not the basename); a path with no dot gives the whole path
        (contract 8.8 rule 3). The leading dot is not included. Lower-casing is ASCII only, as bash's ``${x,,}`` is in the C locale."""
        return self._ext

    def data(self) -> bytes:
        """Whole content, cached. Raises ``FileReadError`` (``too_large`` above ``Limits.max_file_bytes``, checked with ``fstat``
        before reading and again against what was read, so a file that grows is not read past the cap)."""
        if self._data is None:
            fd = open_beneath(self._scan_dir, self._rel)
            try:
                try:
                    size = os.fstat(fd).st_size
                except OSError:
                    raise FileReadError("io") from None
                cap = self._limits.max_file_bytes
                if size > cap:
                    raise FileReadError("too_large")
                self._data = _read_fd(fd, size, cap)
            finally:
                _close(fd)
        return self._data

    def head(self, n: int = 8192) -> bytes:
        """The first ``n`` bytes without reading the rest when ``data()`` has not been called (sniffing: RTF, Flat OPC)."""
        if n <= 0:
            return b""
        if self._data is not None:
            return self._data[:n]
        fd = open_beneath(self._scan_dir, self._rel)
        try:
            parts: "list[bytes]" = []
            have = 0
            while have < n:
                chunk = os.read(fd, min(n - have, _HASH_CHUNK))
                if not chunk:
                    break
                parts.append(chunk)
                have += len(chunk)
            return b"".join(parts)
        except OSError as exc:
            raise FileReadError("permission" if exc.errno in (errno.EACCES, errno.EPERM) else "io") from None
        finally:
            _close(fd)

    def first_line(self) -> bytes:
        """The bytes before the first LF (the whole file if there is none) with NUL bytes removed, as bash ``read -r``
        delivers them. Used for shebang routing; reads through ``data()``, so there is no length cap to evade."""
        data = self.data()
        end = data.find(b"\n")
        line = data if end < 0 else data[:end]
        return line.replace(b"\0", b"") if b"\0" in line else line

    def has_long_line(self) -> bool:
        """True if any line (a run of bytes between LFs, or after the last LF) is longer than ``Limits.long_line_bytes`` (L). Computed once
        per file. Decides between the backtracking and the linear matcher (design section 9.2).

        Algorithm, O(1) extra memory and about 0.2 s per GiB: let ``h = (L + 1) // 2`` and walk the aligned blocks ``[k*h, (k+1)*h)``.
        A run of L + 1 bytes without an LF always contains one whole aligned block, so a block with ``data.count(b"\\n", s, s + h) == 0``
        is a CANDIDATE; for a candidate find the real line with ``data.rfind(b"\\n", 0, s) + 1`` and ``data.find(b"\\n", s + h)`` (end of
        data if none) and compare its length with L. Every ``count`` runs at C speed, so a file of two-byte lines costs one call per ``h``
        bytes, not one per line. FORBIDDEN here: ``rx.lines_over``, ``bytes.split``, ``splitlines``, a Python loop over lines, ``re``.
        The unit test compares it with ``any(len(x) > L for x in data.split(b"\\n"))`` on random buffers for L in 1..20."""
        if self._long is None:
            self._long = _has_long_line(self.data(), self._limits.long_line_bytes)
        return self._long

    def flat(self) -> bytes:
        """The file with CR, LF and TAB folded to spaces (``rx.flat_view(data(), cap=len(data()))``), cached, WITHOUT a size cap
        (review log R-08, D-039): bash's ``grep_flat`` returned "no match" for a file over 5 MiB, which let a hostile XML pad itself
        past the cap and hide an external entity. The folded view is one line, so every flat rule on a file over ``long_line_bytes`` runs
        on the linear matcher; its cost is covered by the per-file deadline. One extra copy of the file lives while a flat rule runs."""
        if self._flat is None:
            data = self.data()
            self._flat = rx.flat_view(data, cap=len(data))
        return self._flat

    def target(self, data: "bytes | None" = None) -> Target:
        """A ``rules.Target`` for this file, or for derived bytes ``data`` (a decoded view, an extracted text) with the
        same basename and extension. ``has_long_line`` is recomputed for derived data."""
        if data is None:
            return Target(data=self.data(), basename=self._basename, ext=self._ext, has_long_line=self.has_long_line(), flat=self.flat)
        folded: "list[bytes]" = []

        def flat() -> bytes:
            if not folded:
                folded.append(rx.flat_view(data, cap=len(data)))
            return folded[0]

        return Target(data=data, basename=self._basename, ext=self._ext,
                      has_long_line=_has_long_line(data, self._limits.long_line_bytes), flat=flat)

    def release(self) -> None:
        """Drop every cached buffer."""
        self._data = None
        self._flat = None
        self._long = None


class TempArea:
    """Contract 3.5 and S16. A private directory ``<tmpdir>/aitransit_<random>`` (mode 0700) holding every temporary
    file of the run: text views for the helper scripts, the generated gitleaks config, tool output captured to disk.
    Names are unpredictable and files are mode 0600 and created with ``O_EXCL``. ``cleanup`` removes everything and is
    idempotent. ``pipeline.main`` calls it in a ``finally`` and registers it with ``atexit`` and the signal handlers, so it
    runs on every exit path, including an abort and SIGTERM.

    The constructor raises ``OSError`` if ``tmpdir`` is not writable; ``pipeline`` is already inside the D-028 handler by then (the
    ``Verdict`` exists), so that becomes a FAIL ``engine:internal_error:OSError`` report (review log R-05)."""

    def __init__(self, tmpdir: str) -> None:
        parent = os.path.abspath(tmpdir)
        for _attempt in range(100):
            path = os.path.join(parent, "aitransit_" + secrets.token_hex(8))
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                continue
            os.chmod(path, 0o700)
            self._path = path
            return
        raise FileExistsError(errno.EEXIST, "no unused temporary directory name")

    @property
    def path(self) -> str:
        return self._path

    def new_file(self, suffix: str = "") -> str:
        """Create an empty file (0600) and return its path. ``suffix`` is a constant chosen by the caller, never repository text."""
        for _attempt in range(100):
            path = os.path.join(self._path, secrets.token_hex(8) + suffix)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o600)
            except FileExistsError:
                continue
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            return path
        raise FileExistsError(errno.EEXIST, "no unused temporary file name")

    def new_dir(self) -> str:
        """Create a sub-directory (0700) and return its path."""
        for _attempt in range(100):
            path = os.path.join(self._path, secrets.token_hex(8))
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                continue
            os.chmod(path, 0o700)
            return path
        raise FileExistsError(errno.EEXIST, "no unused temporary directory name")

    def cleanup(self) -> None:
        shutil.rmtree(self._path, ignore_errors=True)
        if os.path.lexists(self._path):
            # A directory the run made unreadable (a tool's own, say): give the owner back the rights, then try again.
            for top, dirs, _names in os.walk(self._path):
                for name in dirs:
                    try:
                        os.chmod(os.path.join(top, name), 0o700)
                    except OSError:
                        pass
            try:
                os.chmod(self._path, 0o700)
            except OSError:
                pass
            shutil.rmtree(self._path, ignore_errors=True)

    def __enter__(self) -> "TempArea":
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()


def prepare_work_dirs(work_dir: str) -> None:
    """Create ``WORK_DIR/reports``, ``WORK_DIR/quarantine`` (mode 0700) and ``WORK_DIR/approved`` with parents (``mkdir -p``;
    D-027: created although unused). Raises ``OSError`` if that is impossible; ``pipeline`` then prints one ``Console.error`` line and
    returns 1: no verdict line, no report, no sidecar (contract 3.2 "Aborted after validation")."""
    os.makedirs(os.path.join(work_dir, "reports"), exist_ok=True)
    quarantine = os.path.join(work_dir, "quarantine")
    os.makedirs(quarantine, mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(work_dir, "approved"), exist_ok=True)
    os.chmod(quarantine, 0o700)


def _read_limited(fd: int, limit: int) -> "bytes | None":
    """Everything from ``fd`` up to ``limit`` bytes, or None if there is more."""
    parts = []
    total = 0
    while True:
        chunk = os.read(fd, min(_HASH_CHUNK, limit + 1 - total))
        if not chunk:
            return b"".join(parts)
        parts.append(chunk)
        total += len(chunk)
        if total > limit:
            return None


def read_repo_config_file(scan_dir: str, name: str, *, max_bytes: int = 1 << 20) -> "tuple[bytes | None, str | None]":
    """Read ``scan_dir/name`` (``.transit-allow.json`` or ``.transitignore``; ``name`` has no separator, else ``ValueError``) as
    repository configuration, S15 / D-036: it must be a REGULAR file that is NOT a symlink (``lstat``) and at most ``max_bytes``. Returns
    ``(bytes, None)``; ``(None, None)`` if there is no such entry; ``(None, note)`` if it exists but is refused or unreadable (a symlink,
    a FIFO, too large, a permission error): the note is for the console and the file is treated as absent, so a refusal can only
    REMOVE exceptions, never add them. Never follows a link, never opens a device or a FIFO (an ``open`` on a FIFO blocks forever:
    the file is opened ``O_NOFOLLOW | O_NONBLOCK`` and ``fstat`` must say regular). Never raises."""
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise ValueError("name must be a plain file name")
    try:
        dir_fd = os.open(scan_dir, _O_DIR)
    except (FileNotFoundError, NotADirectoryError):
        return None, None
    except OSError as exc:
        return None, "%s could not be read: the scan directory cannot be opened (%s)" % (name, exc.strerror or "error")
    except ValueError:
        return None, "%s could not be read: the scan directory name is not usable" % name
    try:
        try:
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None, None
        except OSError as exc:
            return None, "%s could not be examined (%s): ignored" % (name, exc.strerror or "error")
        if _stat.S_ISLNK(info.st_mode):
            return None, "%s is a symbolic link: ignored (a repository configuration file must be a regular file)" % name
        if not _stat.S_ISREG(info.st_mode):
            return None, "%s is not a regular file: ignored" % name
        if info.st_size > max_bytes:
            return None, "%s is larger than %d bytes: ignored" % (name, max_bytes)
        try:
            fd = os.open(name, _O_FILE, dir_fd=dir_fd)
        except OSError as exc:
            return None, "%s could not be opened (%s): ignored" % (name, exc.strerror or "error")
        try:
            try:
                opened = os.fstat(fd)
                if not _stat.S_ISREG(opened.st_mode):
                    return None, "%s is not a regular file: ignored" % name
                if opened.st_size > max_bytes:
                    return None, "%s is larger than %d bytes: ignored" % (name, max_bytes)
                data = _read_limited(fd, max_bytes)
            except OSError as exc:
                return None, "%s could not be read (%s): ignored" % (name, exc.strerror or "error")
            if data is None:
                return None, "%s is larger than %d bytes: ignored" % (name, max_bytes)
            return data, None
        finally:
            _close(fd)
    finally:
        _close(dir_fd)


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
    base = os.path.abspath(scan_dir)
    target = os.path.abspath(path)
    if target == base:
        return scan_dir
    prefix = base if base.endswith("/") else base + "/"
    if target.startswith(prefix):
        return join_scan_path(scan_dir, target[len(prefix):])
    return None


# ── glob matching: fnmatch(3) in the C locale, without FNM_PATHNAME, as ``find -path`` calls it ────────────────────
_CLASS_MAX_LENGTH = 256


def _in_class(name: bytes, byte: int) -> "bool | None":
    """Is ``byte`` in the POSIX class ``name`` of the C locale? None if the class does not exist. Bytes above 127 are in no class."""
    if name == b"alpha":
        return 65 <= byte <= 90 or 97 <= byte <= 122
    if name == b"digit":
        return 48 <= byte <= 57
    if name == b"alnum":
        return 48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122
    if name == b"upper":
        return 65 <= byte <= 90
    if name == b"lower":
        return 97 <= byte <= 122
    if name == b"space":
        return byte == 32 or 9 <= byte <= 13
    if name == b"blank":
        return byte in (9, 32)
    if name == b"punct":
        return 33 <= byte <= 47 or 58 <= byte <= 64 or 91 <= byte <= 96 or 123 <= byte <= 126
    if name == b"print":
        return 32 <= byte <= 126
    if name == b"graph":
        return 33 <= byte <= 126
    if name == b"cntrl":
        return byte < 32 or byte == 127
    if name == b"xdigit":
        return 48 <= byte <= 57 or 65 <= byte <= 70 or 97 <= byte <= 102
    return None


def _skip_rest(p: bytes, pos: int) -> int:
    """After a bracket expression has matched: the index after its closing ``]`` (glibc reads the rest with rules of its own), -2 if
    the expression is not terminated (the ``[`` is then an ordinary character), -1 if the rest is malformed."""
    size = len(p)

    def at(i: int) -> int:
        return p[i] if i < size else 0

    while True:
        ch = at(pos)
        pos += 1
        if ch == 0x5D:
            return pos
        if ch == 0:
            return -2
        if ch == 0x5C:
            if at(pos) == 0:
                return -1
            pos += 1
        elif ch == 0x5B and at(pos) == 0x3A:
            start = pos
            length = 0
            valid = True
            while True:
                pos += 1
                c = at(pos)
                length += 1
                if length == _CLASS_MAX_LENGTH:
                    return -1
                if c == 0x3A and at(pos + 1) == 0x5D:
                    break
                if c < 0x61 or c >= 0x7A:
                    valid = False
                    break
            if valid:
                pos += 2
            else:
                pos = start
        elif ch == 0x5B and at(pos) == 0x3D:
            pos += 1
            if at(pos) == 0:
                return -1
            pos += 1
            if at(pos) != 0x3D or at(pos + 1) != 0x5D:
                return -1
            pos += 2
        elif ch == 0x5B and at(pos) == 0x2E:
            while True:
                pos += 1
                c = at(pos)
                if c == 0:
                    return -1
                if c == 0x2E and at(pos + 1) == 0x5D:
                    break
            pos += 2


def _bracket(p: bytes, index: int, byte: int) -> int:
    """The ``[`` case of glibc's ``fnmatch`` for the C locale and no flags, for ``p[index] == '['`` and the text byte ``byte``. Returns the index
    after the closing ``]`` when ``byte`` matches, -1 when it does not, and -2 when the bracket expression is not terminated (the ``[`` is
    then an ordinary character, even when ``byte`` is in the part that was read: ``[[`` matches the text ``[[``). Ported from the behaviour
    of the real function, which a differential test pins (329,056 pairs of short patterns and texts, plus random ones with classes): a class
    name is letters ``a`` to ``y`` only, a trailing backslash or an unknown class loses, ``]`` first is a member, ``-`` last is a member,
    ``[.x.]`` and ``[=x=]`` are the single character x."""
    size = len(p)

    def at(i: int) -> int:
        return p[i] if i < size else 0

    pos = index + 1
    negated = at(pos) in (0x21, 0x5E)
    if negated:
        pos += 1
    ch = at(pos)
    pos += 1
    matched = False
    while True:
        plain = False
        if ch == 0x5C:
            if at(pos) == 0:
                return -1
            ch = at(pos)
            pos += 1
            literal = True
        elif ch == 0x5B and at(pos) == 0x3A:
            start = pos
            name = bytearray()
            invalid = False
            while True:
                if len(name) == _CLASS_MAX_LENGTH:
                    return -1
                pos += 1
                c = at(pos)
                if c == 0x3A and at(pos + 1) == 0x5D:
                    pos += 2
                    break
                if c < 0x61 or c >= 0x7A:
                    invalid = True
                    break
                name.append(c)
            if invalid:
                pos = start
                ch = 0x5B
                literal = True
            else:
                member = _in_class(bytes(name), byte)
                if member is None:
                    return -1
                if member:
                    matched = True
                    break
                ch = at(pos)
                pos += 1
                literal = False
        elif ch == 0:
            return -2
        else:
            literal = True
            plain = True
        if literal:
            cold = ch
            if plain and ch == 0x5B and at(pos) in (0x2E, 0x3D):
                delimiter = at(pos)
                start = pos
                while True:
                    pos += 1
                    c = at(pos)
                    if c == delimiter and at(pos + 1) == 0x5D:
                        pos += 2
                        break
                    if c == 0:
                        return -1
                if pos - start - 3 != 1:
                    return -1
                cold = at(start + 1)
                is_range = delimiter == 0x2E and at(pos) == 0x2D and at(pos + 1) not in (0, 0x5D)
                if not is_range and cold == byte:
                    matched = True
                    break
                ch = at(pos)
                pos += 1
            else:
                is_range = at(pos) == 0x2D and at(pos + 1) not in (0, 0x5D)
                if not is_range and ch == byte:
                    matched = True
                    break
                cold = ch
                ch = at(pos)
                pos += 1
            if ch == 0x2D and at(pos) != 0x5D:
                end = at(pos)
                pos += 1
                if end == 0x5C:
                    end = at(pos)
                    pos += 1
                if end == 0:
                    return -1
                if cold <= byte <= end:
                    matched = True
                    break
                ch = at(pos)
                pos += 1
        if ch == 0x5D:
            break
    if matched:
        after = _skip_rest(p, pos)
        if after < 0:
            return after
        return -1 if negated else after
    return pos if negated else -1


def _match_one(p: bytes, index: int, byte: int) -> int:
    """Match the single pattern element at ``p[index]`` against the text byte ``byte``: the index after the element, or -1."""
    c = p[index]
    if c == 0x3F:
        return index + 1
    if c == 0x5C:
        if index + 1 >= len(p):
            return -1
        return index + 2 if p[index + 1] == byte else -1
    if c == 0x5B:
        result = _bracket(p, index, byte)
        if result == -2:
            return index + 1 if byte == 0x5B else -1
        return result
    return index + 1 if c == byte else -1


def _fnmatch(p: bytes, t: bytes, start: int = 0) -> bool:
    """``fnmatch(p, t[start:], 0)`` with one saved star position: O(len(p) * len(t))."""
    pn = len(p)
    tn = len(t)
    pi = 0
    ti = start
    star_pi = -1
    star_ti = 0
    while True:
        if pi < pn:
            c = p[pi]
            if c == 0x2A:
                pi += 1
                while pi < pn and p[pi] == 0x2A:
                    pi += 1
                star_pi = pi
                star_ti = ti
                continue
            if ti < tn:
                following = _match_one(p, pi, t[ti])
                if following >= 0:
                    pi = following
                    ti += 1
                    continue
        elif ti == tn:
            return True
        if star_pi < 0 or star_ti >= tn:
            return False
        star_ti += 1
        ti = star_ti
        pi = star_pi


def glob_match(pattern: str, text: str) -> bool:
    """``fnmatch(3)`` without FNM_PATHNAME, as ``find -path`` applies it: ``*`` matches any string INCLUDING ``/``; ``?`` any
    one character; ``[...]`` a set with ``!`` or ``^`` negation and ranges; ``\\x`` the character x. Iterative, one saved
    star position, so it is O(len(pattern) * len(text)). Pure. A "character" is a BYTE, as in the C locale ``find`` runs in (the
    hardened script sets ``LC_ALL=C``): both strings are encoded with ``os.fsencode`` first."""
    return _fnmatch(_fsb(pattern).partition(b"\0")[0], _fsb(text))


# ── exclusions ─────────────────────────────────────────────────────────────────────────────────────────────────────
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
    glob's first character. The result is identical to testing every pattern against every suffix (the 24 pattern sets of F5).

    One more form, found by a differential fuzz against ``find`` (the design called the script's ``D/*`` forms redundant): a glob that ends
    in an odd number of backslashes never matches by itself, but the script's ``root/D/*`` turns the last backslash into an escaped slash, so
    ``D\\`` also excludes every entry directly inside a directory matching ``D`` (``a\\`` excludes ``a/x`` and keeps ``a``)."""
    dir_names: tuple[str, ...]
    patterns: tuple[str, ...]

    def __post_init__(self) -> None:
        literals = set()
        globs = []
        for pattern in self.patterns:
            raw = _fsb(pattern).partition(b"\0")[0]
            if any(c in pattern for c in GLOB_METACHARS):
                forms = [raw]
                if (len(raw) - len(raw.rstrip(b"\\"))) % 2:
                    # The script also prunes ``root/D/*`` and ``root/*/D/*``. Those are redundant once the directories that match ``D`` are pruned,
                    # except when ``D`` ends in a backslash: ``D\`` never matches (a trailing backslash loses), but ``D\/*`` is ``D`` followed
                    # by an escaped slash, so every CHILD of a directory that matches ``D`` without its backslash is excluded.
                    forms.append(raw + b"/*")
                for form in forms:
                    first = form[0] if form and form[0] not in b"*?[\\" else -1
                    globs.append((form, first, bool(form) and form[0] == 0x2A))
            else:
                literals.add(raw)
        object.__setattr__(self, "_dirs", frozenset(self.dir_names))
        object.__setattr__(self, "_literals", frozenset(literals))
        object.__setattr__(self, "_globs", tuple(globs))

    def _pattern_hit(self, rel: str) -> bool:
        """Does a pattern match ``rel`` or one of its suffixes that start after a ``/``?"""
        literals = self._literals
        globs = self._globs
        raw = _fsb(rel)
        start = 0
        while True:
            if literals and (raw if start == 0 else raw[start:]) in literals:
                return True
            for pattern, first, whole_only in globs:
                if whole_only and start:
                    continue
                if first >= 0 and (start >= len(raw) or raw[start] != first):
                    continue
                if _fnmatch(pattern, raw, start):
                    return True
            start = raw.find(b"/", start) + 1
            if start == 0:
                return False

    def _classify(self, rel: str, is_dir: bool) -> int:
        """0: not excluded; 1: a built-in directory name; 2: a ``.transitignore`` pattern."""
        if is_dir and rel.rpartition("/")[2] in self._dirs:
            return 1
        if (self._literals or self._globs) and self._pattern_hit(rel):
            return 2
        return 0

    def excludes(self, rel: str, *, is_dir: bool) -> bool:
        """True if the entry at ``rel`` (path below the scan root, no leading slash) is excluded."""
        return self._classify(rel, is_dir) != 0

    def semgrep_dirs(self) -> tuple[str, ...]:
        """Names given to Semgrep / ClamAV as ``--exclude-dir`` (built-ins then patterns, contract 8.1)."""
        return tuple(self.dir_names) + tuple(self.patterns)


def load_exclusions(scan_dir: str, *, cfg: Config) -> "tuple[Exclusions, tuple[str, ...]]":
    """Read ``scan_dir/.transitignore`` through ``read_repo_config_file`` and return the exclusions plus the console notes.
    Bash behaviour (D-003 ``proposed``, so copied): a last line without a newline is DROPPED, a line keeps a trailing CR
    (so a CRLF file never matches). With switch ``D-003`` the last line is read and one trailing CR is removed. A file that
    cannot be read or decoded yields no patterns and a note (S15: never a crash, never an exclusion that was not read). A file
    that breaks a limit (``MAX_GLOB_PATTERNS`` globs, ``MAX_PATTERN_CHARS`` per pattern) is refused as a whole with a note.
    The notes are console-only. Whether the patterns are REPORTED is not decided here: ``pipeline`` records the WARN
    ``transitignore:exclusions_applied(<n> pattern(s))`` on ``__global__`` whenever ``Exclusions.patterns`` is non-empty, with no
    switch (D-004 implemented, review log R-03; contract S15 requires it).

    AMENDED by the hardened bash engine (D-003 is closed there, so it is not a switch any more and ``cfg`` is not consulted): the last line
    is read, one trailing CR is removed from each line, NUL bytes are dropped as bash ``read`` drops them."""
    notes = []
    raw, note = read_repo_config_file(scan_dir, ".transitignore")
    if note:
        notes.append(note)
    patterns: "list[str]" = []
    if raw is not None:
        text = os.fsdecode(raw.replace(b"\0", b""))
        start = 0
        size = len(text)
        while start < size:
            end = text.find("\n", start)
            if end < 0:
                end = size
            line = text[start:end]
            start = end + 1
            if line.endswith("\r"):
                line = line[:-1]
            if line and not line.startswith("#"):
                patterns.append(line)
        globs = sum(1 for p in patterns if any(c in p for c in GLOB_METACHARS))
        if globs > MAX_GLOB_PATTERNS:
            notes.append(".transitignore has %d glob patterns (the limit is %d): the whole file is ignored, no exclusion is applied"
                         % (globs, MAX_GLOB_PATTERNS))
            patterns = []
        elif any(len(p) > MAX_PATTERN_CHARS for p in patterns):
            notes.append(".transitignore has a pattern longer than %d characters: the whole file is ignored, no exclusion is applied"
                         % MAX_PATTERN_CHARS)
            patterns = []
    return Exclusions(dir_names=tuple(DEFAULT_EXCLUDE_DIRS), patterns=tuple(patterns)), tuple(notes)


# ── diff mode ──────────────────────────────────────────────────────────────────────────────────────────────────────
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


_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}
_OCTAL = "01234567"


def _c_unquote(body: str) -> "str | None":
    """The inside of a git-quoted name (``\\303\\251.py``, ``a\\tb``) as text, or None if it is not a well-formed quoted body."""
    out = bytearray()
    i = 0
    size = len(body)
    while i < size:
        ch = body[i]
        if ch == '"':
            return None
        if ch != "\\":
            out += _fsb(ch)
            i += 1
            continue
        i += 1
        if i >= size:
            return None
        esc = body[i]
        if esc in _OCTAL:
            j = i
            while j < size and j < i + 3 and body[j] in _OCTAL:
                j += 1
            value = int(body[i:j], 8)
            if value > 255:
                return None
            out.append(value)
            i = j
        elif esc in _C_ESCAPES:
            out.append(_C_ESCAPES[esc])
            i += 1
        else:
            return None
    return os.fsdecode(bytes(out))


def _git_unquote(candidate: str) -> str:
    """``<prefix>/"..."`` with a C-quoted name is rebuilt as ``<prefix>/<name>``; anything else is returned as it is."""
    at = candidate.find('/"')
    tries = 0
    while at >= 0 and tries < 3:
        tail = candidate[at + 2:]
        if tail.endswith('"'):
            body = _c_unquote(tail[:-1])
            if body is not None:
                return candidate[:at + 1] + body
        at = candidate.find('/"', at + 1)
        tries += 1
    return candidate


class _RegularFileProbe:
    """Does ``<scan dir>/<rel>`` name a regular file (not a symlink)? Answered by walking descriptors, so a name below PATH_MAX is found too.
    The directory of the last question is kept open, because a diff list comes sorted and most names share their directory."""

    def __init__(self, base: str) -> None:
        self._base = base
        self._prefix = base if base.endswith("/") else base + "/"
        self._root = -2
        self._dir_rel: "str | None" = None
        self._dir_fd = -1

    def _open_root(self) -> int:
        if self._root == -2:
            try:
                self._root = os.open(self._base, _O_DIR)
            except OSError:
                self._root = -1
        return self._root

    def _directory(self, parent: str) -> int:
        if self._dir_rel == parent and self._dir_fd >= 0:
            return self._dir_fd
        self._forget()
        root = self._open_root()
        if root < 0:
            return -1
        current = os.open(".", _O_DIR, dir_fd=root)
        try:
            if parent:
                for part in parent.split("/"):
                    following = os.open(part, _O_DIR_NOFOLLOW, dir_fd=current)
                    os.close(current)
                    current = following
        except OSError:
            os.close(current)
            return -1
        self._dir_rel = parent
        self._dir_fd = current
        return current

    def _forget(self) -> None:
        if self._dir_fd >= 0:
            _close(self._dir_fd)
        self._dir_fd = -1
        self._dir_rel = None

    def is_regular(self, absolute: str) -> bool:
        if not absolute.startswith(self._prefix):
            return False
        rel = absolute[len(self._prefix):]
        parent, _sep, name = rel.rpartition("/")
        if not name or name in (".", "..") or any(part in ("", ".", "..") for part in parent.split("/") if parent):
            return False
        try:
            fd = self._directory(parent)
            if fd < 0:
                return False
            return _stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode)
        except (OSError, ValueError):
            return False

    def close(self) -> None:
        self._forget()
        if self._root >= 0:
            _close(self._root)
        self._root = -2


def _nul_keys(data: bytes, scan_dir: str, probe: _RegularFileProbe) -> "set[str]":
    keys = set()
    size = len(data)
    start = 0
    while start < size:
        end = data.find(b"\0", start)
        if end < 0:
            end = size
        item = data[start:end]
        start = end + 1
        if not item:
            continue
        absolute = os.path.abspath(join_scan_path(scan_dir, os.fsdecode(item)))
        if absolute not in keys and probe.is_regular(absolute):
            keys.add(absolute)
    return keys


def _legacy_keys(data: bytes, scan_dir: str, probe: _RegularFileProbe, prefix: str) -> "tuple[set[str], int]":
    """The colon list. Streamed: a window of ``_MAX_JOIN_PIECES + 1`` pieces is all the memory it needs, whatever the size of the file."""
    def pieces() -> Iterator[bytes]:
        start = 0
        while True:
            end = data.find(b":", start)
            if end < 0:
                return                      # the text after the last colon (a newline, say) is dropped, as in bash
            yield data[start:end]
            start = end + 1

    window: "collections.deque[list]" = collections.deque()        # [text, is_head, consumed]
    source = pieces()
    keys: "set[str]" = set()
    unresolved = 0
    while True:
        while len(window) <= _MAX_JOIN_PIECES:
            raw = next(source, None)
            if raw is None:
                break
            text = os.fsdecode(raw)
            window.append([text, text.startswith("/") and os.path.abspath(text).startswith(prefix), False])
        if not window:
            break
        head = window[0]
        if head[1]:
            for extra in range(len(window)):
                if extra and window[extra][1]:
                    break
                joined = head[0] if not extra else ":".join(window[j][0] for j in range(extra + 1))
                absolute = os.path.abspath(_git_unquote(joined))
                if probe.is_regular(absolute):
                    keys.add(absolute)
                    for j in range(extra + 1):
                        window[j][2] = True
        window.popleft()
        if not head[1] and not head[2]:
            unresolved += 1
    return keys, unresolved


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
    run is PASS with L4 and L5 ``ran`` (golden ``diff_mode_zero_files``).

    AMENDED by the hardened bash engine (golden ``diff_mode_nul_names``): the names of the NUL format are RELATIVE to the scan directory
    (``git diff -z --name-only`` prints them so; the script joins them with ``SCAN_DIR/``) and a last item without its terminating NUL is read.
    Only the pieces that start with the scan directory (the heads of entries) are joined with the pieces that follow them, up to the next such
    piece: the producer writes ``<DEST>/`` in front of every name, so a fragment can never begin a name, and this keeps the work linear."""
    path = os.path.join(work_dir, ".diff_files")
    if not os.path.lexists(path):
        return DiffSelection(active=False, keys=frozenset(), stale_ignored=False, unresolved=0)
    if not since_commit:
        return DiffSelection(active=False, keys=frozenset(), stale_ignored=True, unresolved=0)
    try:
        info = os.stat(path)
        if not _stat.S_ISREG(info.st_mode) or info.st_size > _DIFF_FILES_CAP:
            raise OSError(errno.EIO, "not a readable list")
        with open(path, "rb") as handle:
            data = handle.read(_DIFF_FILES_CAP + 1)
        if len(data) > _DIFF_FILES_CAP:
            raise OSError(errno.EFBIG, "too large")
    except (OSError, ValueError):
        return DiffSelection(active=True, keys=frozenset(), stale_ignored=False, unresolved=1)
    base = os.path.abspath(scan_dir)
    prefix = base if base.endswith("/") else base + "/"
    probe = _RegularFileProbe(base)
    try:
        if b"\0" in data:
            keys, unresolved = _nul_keys(data, scan_dir, probe), 0
        else:
            keys, unresolved = _legacy_keys(data, scan_dir, probe, prefix)
    finally:
        probe.close()
    return DiffSelection(active=True, keys=frozenset(keys), stale_ignored=False, unresolved=unresolved)


# ── the walk ───────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclasses.dataclass(frozen=True)
class SymlinkEntry:
    """A symbolic link found below the scan root (ADDITIVE API, hardened bash ``find -type l``). ``path`` is the recorded string,
    ``rel`` the path below the scan directory, ``target`` the link text (hostile: only compared, never followed), ``escapes`` the
    answer of ``symlink_escapes``. The layer above records FAIL ``symlink:target_outside_the_scanned_directory`` when ``escapes``
    and WARN ``symlink:not_followed_its_target_is_not_scanned_through_the_link`` otherwise."""
    path: str
    rel: str
    target: str
    escapes: bool


@dataclasses.dataclass(frozen=True)
class ScanList:
    """The files of the per-file layers, sorted by the bytes of ``rel``, plus what could not be listed and what was excluded.
    ``errors``: one ``(rel, reason)`` per directory that could not be listed, reason ``permission``, ``io`` or ``too_deep``
    (deeper than ``MAX_WALK_DEPTH``); ``layers.run_file_layers`` records one non-downgradable FAIL ``engine:directory_unreadable:<reason>``
    for each (the first 200, then one summary), because a directory is a whole subtree that was not examined (bash lists with
    ``2>/dev/null`` and loses it silently; review log R-09). ``excluded_by_patterns``: how many entries (files or directories; a pruned
    directory counts once) the ``.transitignore`` patterns removed; with an empty ``entries`` and a non-zero count ``layers.run_file_layers``
    records the FAIL ``engine:nothing_scanned:transitignore`` (review log R-03).

    ADDITIVE fields (the hardened bash engine, every one has a default): ``symlinks`` (``SymlinkEntry``, sorted by the bytes of ``rel``);
    ``examined``: how many of ``entries`` are not control files (``is_control_file``); ``nothing_scanned``: True exactly when the hardened
    script records ``engine:nothing_scanned``, that is when ``.transitignore`` patterns exist, no entry that counts was selected, and a
    file that counts (not a control file, selected by the diff when it is active) exists that the patterns removed; ``layers`` must use
    this flag and not the test "empty ``entries`` and a non-zero count", which cannot see that a repository whose only listed file is its
    own ``.transitignore`` has been emptied; ``listing_exit``: 1 if any directory could not be listed (the status ``find`` exits with),
    else 0, the number of ``engine:file_listing_failed`` / ``skipped:file listing failed (find exit N)``. An unopenable root is one error
    ``(".", reason)``."""
    entries: tuple[FileEntry, ...]
    errors: tuple[tuple[str, str], ...]
    excluded_by_patterns: int = 0
    symlinks: tuple[SymlinkEntry, ...] = ()
    examined: int = 0
    nothing_scanned: bool = False
    listing_exit: int = 0


def is_control_file(rel: str) -> bool:
    """True for the three files of ``CONTROL_FILE_NAMES`` at the ROOT of the scan (``rel`` has no ``/``)."""
    return rel in CONTROL_FILE_NAMES


def symlink_escapes(rel: str, target: str) -> bool:
    """Hardened bash ``_symlink_escapes``: does the link at ``rel`` (below the scan root) point out of the scanned directory? The target text is
    read, never followed: an absolute target escapes, and so does a relative one whose ``..`` climbs above the root."""
    if target.startswith("/"):
        return True
    depth = rel.rpartition("/")[0].count("/") + 1 if "/" in rel else 0
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


class _Walk:
    """What one pass over the tree found."""

    def __init__(self) -> None:
        self.files: "list[tuple[str, int]]" = []
        self.symlinks: "list[SymlinkEntry]" = []
        self.errors: "list[tuple[str, str]]" = []
        self.excluded = 0
        self.found = False


def _open_chain(root_fd: int, parts: "list[str]") -> int:
    """A new descriptor for the directory ``parts`` below the directory ``root_fd``, opened one component at a time (``O_NOFOLLOW``)."""
    current = os.open(".", _O_DIR, dir_fd=root_fd)
    try:
        for part in parts:
            following = os.open(part, _O_DIR_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
    except BaseException:
        os.close(current)
        raise
    return current


def _walk(scan_dir: str, exclusions: Exclusions, keep: "Callable[[str], bool] | None" = None, first_only: bool = False,
          want_symlinks: bool = False) -> _Walk:
    """Walk the tree below ``scan_dir`` through directory descriptors only. ``keep(rel)`` selects regular files (None: all); with ``first_only``
    the walk stops at the first selected file (``found``). Never raises for a hostile tree: what cannot be listed is in ``errors``."""
    result = _Walk()
    try:
        root = os.open(scan_dir, _O_DIR)
    except OSError as exc:
        result.errors.append((".", _walk_reason(exc)))
        return result
    try:
        stack = [("", 0)]
        while stack:
            rel_dir, depth = stack.pop()
            try:
                dir_fd = _open_chain(root, rel_dir.split("/") if rel_dir else [])
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    result.errors.append((rel_dir or ".", _walk_reason(exc)))
                continue
            try:
                with os.scandir(dir_fd) as listing:
                    for entry in listing:
                        rel = rel_dir + "/" + entry.name if rel_dir else entry.name
                        try:
                            is_dir = entry.is_dir(follow_symlinks=False)
                            why = exclusions._classify(rel, is_dir)
                            if why:
                                if why == 2:
                                    result.excluded += 1
                                continue
                            if is_dir:
                                if depth + 1 > MAX_WALK_DEPTH:
                                    result.errors.append((rel, "too_deep"))
                                else:
                                    stack.append((rel, depth + 1))
                                continue
                            if entry.is_symlink():
                                if want_symlinks:
                                    try:
                                        target = os.readlink(entry.name, dir_fd=dir_fd)
                                        escapes = symlink_escapes(rel, target)
                                    except FileNotFoundError:
                                        continue
                                    except OSError:
                                        target, escapes = "", True
                                    result.symlinks.append(SymlinkEntry(path=join_scan_path(scan_dir, rel), rel=rel, target=target,
                                                                        escapes=escapes))
                                continue
                            info = entry.stat(follow_symlinks=False)
                            if not _stat.S_ISREG(info.st_mode):
                                continue
                            if keep is not None and not keep(rel):
                                continue
                            result.files.append((rel, info.st_size))
                            if first_only:
                                result.found = True
                                return result
                        except OSError as exc:
                            if exc.errno != errno.ENOENT:
                                result.errors.append((rel, _walk_reason(exc)))
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    result.errors.append((rel_dir or ".", _walk_reason(exc)))
            finally:
                _close(dir_fd)
    finally:
        _close(root)
    return result


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
    if diff.active:
        base = os.path.abspath(scan_dir)
        key_prefix = base if base.endswith("/") else base + "/"
        keys = diff.keys

        def selected(rel: str) -> bool:
            return (key_prefix + rel) in keys
    else:
        selected = None
    walk = _walk(scan_dir, exclusions, keep=selected, want_symlinks=True)
    ordered = sorted(walk.files, key=lambda item: _fsb(item[0]))
    entries = tuple(FileEntry(path=join_scan_path(scan_dir, rel), rel=rel, size=size) for rel, size in ordered)
    examined = sum(1 for e in entries if not is_control_file(e.rel))
    nothing_scanned = False
    if examined == 0 and exclusions.patterns:
        def counts(rel: str) -> bool:
            return not is_control_file(rel) and (selected is None or selected(rel))
        probe = _walk(scan_dir, Exclusions(dir_names=exclusions.dir_names, patterns=()), keep=counts, first_only=True)
        nothing_scanned = probe.found
    errors = tuple(sorted(walk.errors, key=lambda item: _fsb(item[0])))
    symlinks = tuple(sorted(walk.symlinks, key=lambda item: _fsb(item.rel)))
    return ScanList(entries=entries, errors=errors, excluded_by_patterns=walk.excluded, symlinks=symlinks, examined=examined,
                    nothing_scanned=nothing_scanned, listing_exit=1 if errors else 0)


# ── hashes ─────────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclasses.dataclass(frozen=True)
class SourceHashes:
    """``sha256``: contract 4 ``source.sha256``; ``repo_hash``: contract 4 ``repo_hash``."""
    sha256: str
    repo_hash: str


#: What ``sha256sum`` (coreutils 9.4) escapes in a file name: a backslash, a newline and a carriage return.
_SHA256SUM_ESCAPES = ((b"\\", b"\\\\"), (b"\n", b"\\n"), (b"\r", b"\\r"))


def _sha256sum_line(digest: str, name: bytes) -> bytes:
    """One line of ``sha256sum`` output for the file ``name`` (``./<rel>``): ``<hex>  <name>``, or ``\\<hex>  <escaped name>``."""
    if b"\\" in name or b"\n" in name or b"\r" in name:
        for raw, escaped in _SHA256SUM_ESCAPES:
            name = name.replace(raw, escaped)
        return b"\\" + digest.encode("ascii") + b"  " + name + b"\n"
    return digest.encode("ascii") + b"  " + name + b"\n"


def compute_hashes(scan_dir: str) -> SourceHashes:
    """``source.sha256`` = SHA-256 of the lines ``<hex>  ./<rel>`` (two spaces, LF) of EVERY regular file under ``scan_dir``
    (no exclusion applies; symlinks excluded), sorted by the BYTES of the whole ``./<rel>`` string (``LC_ALL=C sort -z``,
    so ``a.b`` sorts before ``a/b``). A name containing a backslash or LF is written in ``sha256sum``'s escaped form
    (``\\<hex>  <name with \\\\ and \\n escaped>``). If any file cannot be read, ``sha256`` falls back to ``repo_hash`` (what the
    bash pipeline does). ``repo_hash`` = SHA-256 of ``scan_dir/<rel>`` lines of the same files sorted bytewise (bash sorts
    by locale; the value depends on the location and the normaliser drops it). Reads in 1 MiB chunks. Walks and opens files the same
    way as ``files_for_scan`` (directory descriptors, ``open_beneath``), so a file below PATH_MAX is hashed too (bash's
    ``find | xargs sha256sum`` could not open it and fell back to ``repo_hash``).

    Also escaped, as coreutils 9.4 does: a carriage return (``\\r``). An unlistable directory counts as "a file cannot be read"."""
    walk = _walk(scan_dir, Exclusions(dir_names=(), patterns=()))
    names = sorted((_fsb(rel) for rel, _size in walk.files))
    repo = hashlib.sha256()
    for raw in names:
        repo.update(_fsb(join_scan_path(scan_dir, os.fsdecode(raw))) + b"\n")
    repo_hash = repo.hexdigest()
    if walk.errors:
        return SourceHashes(sha256=repo_hash, repo_hash=repo_hash)
    outer = hashlib.sha256()
    for raw in names:
        rel = os.fsdecode(raw)
        try:
            fd = open_beneath(scan_dir, rel)
        except (FileReadError, ValueError):
            return SourceHashes(sha256=repo_hash, repo_hash=repo_hash)
        inner = hashlib.sha256()
        try:
            while True:
                chunk = os.read(fd, _HASH_CHUNK)
                if not chunk:
                    break
                inner.update(chunk)
        except OSError:
            return SourceHashes(sha256=repo_hash, repo_hash=repo_hash)
        finally:
            _close(fd)
        outer.update(_sha256sum_line(inner.hexdigest(), b"./" + raw))
    return SourceHashes(sha256=outer.hexdigest(), repo_hash=repo_hash)
