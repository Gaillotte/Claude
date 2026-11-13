"""Console output: the only module that writes to stdout or stderr.

Owner of: contract 3.1 (channels), 3.2 (the verdict line), S1 (console is control-free), S2 (backslash text is
data), D-017 (bidi controls) and the ``VERBOSITY=quiet`` rule of contract 2.

Layering: a LEAF module (standard library only). ``scan_pipeline.py`` and every other module print through a
``Console``; a lint (tests/engine/test_lints.py) forbids ``print(`` and ``sys.stdout``/``sys.stderr`` writes anywhere
else under ``transit/``. Text that comes from the scanned repository (file names, archive entry names, finding
messages, tool output, exception text) MUST reach a Console method as-is: sanitising happens HERE, once, so no
caller can forget it.

What ``sanitise`` replaces by ``?``: C0 controls (U+0000-U+001F, so LF, CR, TAB and ESC too), DEL, C1 controls
(U+0080-U+009F), the bidi controls of ``BIDI_CONTROLS`` (U+202A-U+202E and U+2066-U+2069 as contract S1 requires, plus the
marks U+061C, U+200E and U+200F, review log R-14), and every undecodable byte (a lone surrogate left by ``os.fsdecode``). The line terminator is added by the Console after sanitising. A literal
backslash sequence such as the four characters ``\\033`` is printed as those four characters (S2).

A C1 control is one character (U+009B) whether it arrived as such or, with a file system encoding that is not UTF-8, as the two
lone surrogates of its bytes ``C2 9B``: either way it becomes ONE ``?``, as in the bash console (``_san``, since the hardening).

Output is written as UTF-8 bytes to ``sys.stdout.buffer`` / ``sys.stderr.buffer`` (never through the text layer, so
the locale cannot change what is written; a process stream that has no ``buffer``, such as a ``StringIO``, is written as text, and a
process without a stream writes nothing). Every message is ONE ``write`` followed by a ``flush``. A ``BrokenPipeError`` or
``OSError`` while writing is swallowed: a closed pipe must not stop a scan that still has to write its report and sidecars. A closed pipe
(or a closed stream) is final for that stream, which stays quiet from then on; on the process's own stream its descriptor is pointed at
``/dev/null`` so that the interpreter's flush at exit does not fail and turn exit status 0 into 120.

The progress line is state: ``progress`` draws it (a terminal, not quiet) and remembers that it did, and the next message of any kind
erases it first (``clear_progress``). Nothing is written to erase a line that was never drawn.
"""
from __future__ import annotations

import os
import sys
import traceback
from typing import BinaryIO

#: ANSI colours used by bash (not contract, but kept so a human sees the same output; S1 strips them in its test).
COLOUR_INFO = "\x1b[34m"
COLOUR_WARN = "\x1b[33m"
COLOUR_OK = "\x1b[32m"
COLOUR_FAIL = "\x1b[31m"
COLOUR_RESET = "\x1b[0m"

#: Characters that reorder or hide the text around them (D-017). ``sanitise`` replaces them on the console and
#: ``report.html_escape`` writes them as character references, so a file name cannot make a path read differently from what it is.
BIDI_CONTROLS = frozenset(
    ["\u061c", "\u200e", "\u200f"] + [chr(c) for c in range(0x202A, 0x202F)] + [chr(c) for c in range(0x2066, 0x206A)])


def _forbidden_table() -> "dict[int, str]":
    """Code point -> ``?`` for every character ``sanitise`` replaces (ranges of the module docstring)."""
    table = {c: "?" for c in range(0x20)}                    # C0, LF CR TAB ESC included
    table[0x7F] = "?"                                        # DEL
    table.update({c: "?" for c in range(0x80, 0xA0)})        # C1: U+009B is a CSI to a UTF-8 terminal
    table.update({ord(ch): "?" for ch in BIDI_CONTROLS})     # D-017, R-14
    table.update({c: "?" for c in range(0xD800, 0xE000)})    # a lone surrogate is an undecodable byte left by os.fsdecode
    return table


_TABLE = _forbidden_table()

#: With a file system encoding that is not UTF-8 the two bytes ``C2 80`` .. ``C2 9F`` of a C1 control reach us as TWO lone surrogates
#: (``U+DCC2`` then ``U+DC80`` .. ``U+DC9F``). The bash console replaces the pair by ONE ``?`` (``_san``), so does this module.
_C1_LEAD = chr(0xDCC2)
_C1_PAIRS = tuple(_C1_LEAD + chr(0xDC00 + low) for low in range(0x80, 0xA0))


def sanitise(text: "str | bytes") -> str:
    """Return ``text`` with every character listed in the module docstring replaced by ``?``.

    ``bytes`` are decoded as UTF-8 with undecodable bytes replaced by ``?``. Pure; never raises; the result
    contains no character below U+0020, none of U+007F-U+009F and none of ``BIDI_CONTROLS``.
    """
    if isinstance(text, str):
        s = str.__str__(text)  # an exact ``str`` holding the text: a subclass cannot change what the methods below see or add
    elif isinstance(text, (bytes, bytearray, memoryview)):
        # surrogateescape: each undecodable BYTE becomes one lone surrogate and so one "?" (errors="replace" would fold a
        # truncated multi-byte sequence into a single U+FFFD, and U+FFFD itself is printable and must stay as it is)
        s = bytes(text).decode("utf-8", "surrogateescape")
    else:
        try:
            s = str(text)
        except Exception:  # noqa: BLE001  (an object whose __str__ raises must not stop a scan from reporting)
            s = "<%s>" % type(text).__name__
    if s.isascii() and s.isprintable():  # the common case: only 0x20..0x7E, nothing to replace
        return s
    if _C1_LEAD in s:
        for pair in _C1_PAIRS:
            s = s.replace(pair, "?")
    return s.translate(_TABLE)


_PREFIX_INFO = COLOUR_INFO + "[INFO]" + COLOUR_RESET + "  "
_PREFIX_OK = COLOUR_OK + "[OK]" + COLOUR_RESET + "    "
_PREFIX_WARN = COLOUR_WARN + "[WARN]" + COLOUR_RESET + "  "
_PREFIX_FAIL = COLOUR_FAIL + "[FAIL]" + COLOUR_RESET + "  "
_PREFIX_PROGRESS = COLOUR_INFO + "[L5]" + COLOUR_RESET + "  "
_CLEAR_LINE = "\r\x1b[K"            # bash _clr: carriage return, erase to the end of the line
_PROGRESS_NAME_CHARS = 80
_VERDICTS = ("PASS", "FAIL")
_CONTINUATION = "    "


def _redirect_to_devnull(stream: object) -> None:
    """After a closed pipe on one of the process's own streams: point its descriptor at ``/dev/null``. The buffer of ``sys.stdout`` still
    holds the bytes that could not be written, and the interpreter would flush them again at exit, print ``Exception ignored ... BrokenPipeError``
    and turn exit status 0 into 120 (the recipe of the Python documentation, "Note on SIGPIPE")."""
    try:
        fd = stream.fileno()  # type: ignore[attr-defined]
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, fd)
        finally:
            os.close(null)
    except (OSError, ValueError, AttributeError):
        pass


class _Sink:
    """One output stream. Messages are complete lines (str), written as ONE ``write`` followed by ``flush``. A closed pipe or a closed
    stream is final (the sink goes quiet, so a scan with a closed stdout is not slowed down by an exception per line); any other
    ``OSError`` costs the one message."""

    def __init__(self, stream: object, *, text: bool = False, front: object = None) -> None:
        self._stream = stream
        self._text = text
        self._front = front          # the text layer in front of a default binary stream: flushed first, so that order is kept
        self._dead = stream is None

    def isatty(self) -> bool:
        try:
            return bool(self._stream.isatty())  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001  (a stream that cannot say is not a terminal)
            return False

    def write(self, line: str) -> None:
        if self._dead:
            return
        stream = self._stream
        try:
            if self._front is not None:
                self._front.flush()  # type: ignore[attr-defined]
            if self._text:
                try:
                    stream.write(line)  # type: ignore[union-attr]
                except UnicodeEncodeError:
                    stream.write(line.encode("ascii", "replace").decode("ascii"))  # type: ignore[union-attr]
            else:
                stream.write(line.encode("utf-8"))  # type: ignore[union-attr]
            stream.flush()  # type: ignore[union-attr]
        except (BrokenPipeError, ValueError):
            self._dead = True
            if self._front is not None:
                _redirect_to_devnull(stream)
        except OSError:
            pass


def _default_sink(name: str) -> _Sink:
    """The process's own ``sys.stdout`` / ``sys.stderr``: its binary buffer (never the text layer, so the locale cannot change what is
    written), else the object itself written as text (a ``StringIO`` under test), else nothing (``sys.stdout`` is ``None`` when the
    process has no console)."""
    front = getattr(sys, name, None)
    if front is None:
        return _Sink(None)
    buffer = getattr(front, "buffer", None)
    if buffer is not None:
        return _Sink(buffer, front=front)
    return _Sink(front, text=True)


class Console:
    """Sanitised, channel-correct output (contract 3.1). One instance per run, created by ``pipeline.main``.

    ``verbosity`` is ``"quiet"`` or ``"normal"``. ``out`` / ``err`` default to the process's binary stdout and
    stderr; tests pass ``io.BytesIO``. ``err_is_tty`` decides whether the progress line is drawn (default:
    ``err.isatty()``).
    """

    def __init__(self, verbosity: str = "normal", *, out: "BinaryIO | None" = None,
                 err: "BinaryIO | None" = None, err_is_tty: "bool | None" = None) -> None:
        self._quiet = verbosity == "quiet"
        self._out = _Sink(out) if out is not None else _default_sink("stdout")
        self._err = _Sink(err) if err is not None else _default_sink("stderr")
        self._tty = self._err.isatty() if err_is_tty is None else bool(err_is_tty)
        self._drawn = False  # a progress line is on the screen and the next message must erase it first

    def info(self, text: str) -> None:
        """``[INFO]`` line on stdout; suppressed when quiet."""
        if self._quiet:
            return
        self.clear_progress()
        self._out.write(_PREFIX_INFO + sanitise(text) + "\n")

    def ok(self, text: str) -> None:
        """``[OK]`` line on stdout; suppressed when quiet."""
        if self._quiet:
            return
        self.clear_progress()
        self._out.write(_PREFIX_OK + sanitise(text) + "\n")

    def warn(self, text: str) -> None:
        """``[WARN]`` line on stderr; NEVER suppressed (contract 3.1)."""
        self.clear_progress()
        self._err.write(_PREFIX_WARN + sanitise(text) + "\n")

    def fail_line(self, text: str) -> None:
        """``[FAIL]`` line on stderr; never suppressed. Does not change the verdict (bash ``fail_f`` sets the verdict;
        here ``Verdict.record_fail`` does, and calls this to mirror the FAIL)."""
        self.clear_progress()
        self._err.write(_PREFIX_FAIL + sanitise(text) + "\n")

    def error(self, text: str) -> None:
        """``[FAIL]`` line on stderr for an abort; the caller decides the exit status (bash ``fail`` exits 1)."""
        self.clear_progress()
        self._err.write(_PREFIX_FAIL + sanitise(text) + "\n")

    def verdict(self, value: str) -> None:
        """Write exactly ``PASS`` or ``FAIL`` plus LF on stdout, even when quiet. It MUST be the last stdout write of a
        completed run (contract 3.2). Raises ``ValueError`` for any other value."""
        if not isinstance(value, str) or value not in _VERDICTS:
            raise ValueError("verdict must be exactly 'PASS' or 'FAIL' (got a %s)" % type(value).__name__)
        self.clear_progress()
        self._out.write("PASS\n" if value == "PASS" else "FAIL\n")

    def progress(self, current: int, total: int, rel_path: str) -> None:
        """Redraw the ``[L5]  [n/total] path`` line (stderr, only when it is a terminal and not quiet).

        ``rel_path`` is REPOSITORY TEXT and goes through ``sanitise`` like every other argument of this class, BEFORE it is cut
        to 80 characters (cutting first could leave half of an escape sequence's replacement; sanitising first cannot). Contract 3.1
        says "Sanitised: not needed" for this line; that row is wrong and is amended (review log R-10): the bash progress line
        printed the raw name, so a file called ``x<ESC>]0;PWNED<BEL>.py`` retitled the reviewer's terminal. The test draws the line
        with ``err_is_tty=True`` and the hostile names of S1, and asserts that every byte written is printable, LF, CR, or the
        engine's own ``ESC[...m`` / ``ESC[K`` sequences."""
        if self._quiet or not self._tty:
            return
        name = sanitise(rel_path)[:_PROGRESS_NAME_CHARS]
        counter = "[%*d/%d] " % (len(str(total)), current, total)
        self._err.write(_CLEAR_LINE + _PREFIX_PROGRESS + counter + name)
        self._drawn = True

    def clear_progress(self) -> None:
        """Erase the progress line. Every other method calls this first (bash ``_clr``)."""
        if self._drawn:
            self._drawn = False
            self._err.write(_CLEAR_LINE)

    def exception(self, where: str, exc: BaseException) -> None:
        """Print ``exc`` and its traceback on stderr, sanitised as one block, labelled ``where``. The traceback may
        contain repository text (a file name in a message), which is why it goes through ``sanitise``."""
        try:
            raw = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        except Exception:  # noqa: BLE001  (an exception that cannot be formatted is still reported by its class)
            raw = "%s: <could not be formatted>\n" % type(exc).__name__
        # One sanitise per line: sanitise turns LF into "?", and the block is meant to have lines. Every line after the first is
        # indented, so text inside a message cannot begin a line that looks like one of the engine's own (``[FAIL]``, ``PASS``).
        lines = [sanitise(line) for line in raw.rstrip("\n").split("\n")]
        block = _PREFIX_FAIL + sanitise(where) + "\n" + "".join(_CONTINUATION + line + "\n" for line in lines)
        self.clear_progress()
        self._err.write(block)
