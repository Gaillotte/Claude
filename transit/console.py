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

Output is written as UTF-8 bytes to ``sys.stdout.buffer`` / ``sys.stderr.buffer`` (never through the text layer, so
the locale cannot change what is written). A ``BrokenPipeError`` or ``OSError`` while writing is swallowed: a closed
pipe must not stop a scan that still has to write its report and sidecars.
"""
from __future__ import annotations

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


def sanitise(text: "str | bytes") -> str:
    """Return ``text`` with every character listed in the module docstring replaced by ``?``.

    ``bytes`` are decoded as UTF-8 with undecodable bytes replaced by ``?``. Pure; never raises; the result
    contains no character below U+0020, none of U+007F-U+009F and none of ``BIDI_CONTROLS``.
    """
    raise NotImplementedError


class Console:
    """Sanitised, channel-correct output (contract 3.1). One instance per run, created by ``pipeline.main``.

    ``verbosity`` is ``"quiet"`` or ``"normal"``. ``out`` / ``err`` default to the process's binary stdout and
    stderr; tests pass ``io.BytesIO``. ``err_is_tty`` decides whether the progress line is drawn (default:
    ``err.isatty()``).
    """

    def __init__(self, verbosity: str = "normal", *, out: "BinaryIO | None" = None,
                 err: "BinaryIO | None" = None, err_is_tty: "bool | None" = None) -> None:
        raise NotImplementedError

    def info(self, text: str) -> None:
        """``[INFO]`` line on stdout; suppressed when quiet."""
        raise NotImplementedError

    def ok(self, text: str) -> None:
        """``[OK]`` line on stdout; suppressed when quiet."""
        raise NotImplementedError

    def warn(self, text: str) -> None:
        """``[WARN]`` line on stderr; NEVER suppressed (contract 3.1)."""
        raise NotImplementedError

    def fail_line(self, text: str) -> None:
        """``[FAIL]`` line on stderr; never suppressed. Does not change the verdict (bash ``fail_f`` sets the verdict;
        here ``Verdict.record_fail`` does, and calls this to mirror the FAIL)."""
        raise NotImplementedError

    def error(self, text: str) -> None:
        """``[FAIL]`` line on stderr for an abort; the caller decides the exit status (bash ``fail`` exits 1)."""
        raise NotImplementedError

    def verdict(self, value: str) -> None:
        """Write exactly ``PASS`` or ``FAIL`` plus LF on stdout, even when quiet. It MUST be the last stdout write of a
        completed run (contract 3.2). Raises ``ValueError`` for any other value."""
        raise NotImplementedError

    def progress(self, current: int, total: int, rel_path: str) -> None:
        """Redraw the ``[L5]  [n/total] path`` line (stderr, only when it is a terminal and not quiet).

        ``rel_path`` is REPOSITORY TEXT and goes through ``sanitise`` like every other argument of this class, BEFORE it is cut
        to 80 characters (cutting first could leave half of an escape sequence's replacement; sanitising first cannot). Contract 3.1
        says "Sanitised: not needed" for this line; that row is wrong and is amended (review log R-10): the bash progress line
        printed the raw name, so a file called ``x<ESC>]0;PWNED<BEL>.py`` retitled the reviewer's terminal. The test draws the line
        with ``err_is_tty=True`` and the hostile names of S1, and asserts that every byte written is printable, LF, CR, or the
        engine's own ``ESC[...m`` / ``ESC[K`` sequences."""
        raise NotImplementedError

    def clear_progress(self) -> None:
        """Erase the progress line. Every other method calls this first (bash ``_clr``)."""
        raise NotImplementedError

    def exception(self, where: str, exc: BaseException) -> None:
        """Print ``exc`` and its traceback on stderr, sanitised as one block, labelled ``where``. The traceback may
        contain repository text (a file name in a message), which is why it goes through ``sanitise``."""
        raise NotImplementedError
