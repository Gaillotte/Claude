"""Command line: ``scan_pipeline.py <directory_to_scan> [directory_for_report] [scanning_name]`` (contract 1).

Owner of: contract 1.1 (options do not exist), 1.2 (the four checks, in order), 1.3 (trailing slashes),
1.4 (scanning_name rules), 1.5 (empty strings), and the exit status 1 for a refused argument (3.2).

Layering: a LEAF module (standard library only). Parsing performs only ``os.path.isdir`` checks; it creates nothing
(contract 1.2: every refusal happens before the first write, ``WORK_DIR`` is not created).

Arguments arrive as ``str`` decoded by the interpreter with ``surrogateescape`` (``sys.argv``). They are kept in that
form everywhere; ``os.fsencode`` gives the original bytes back.
"""
from __future__ import annotations

import dataclasses
from typing import Sequence

#: Contract 1.4.
SCANNING_NAME_MAX_CHARS = 150


class UsageError(Exception):
    """A refused command line. ``message`` is for stderr (the wording is not contract, the exit status 1 is); the
    pipeline prints it through ``Console.error`` and exits 1 with empty stdout and no file written."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclasses.dataclass(frozen=True)
class Args:
    """The parsed command line. ``scan_dir`` has its trailing slashes removed (a lone ``/`` is kept) and is
    otherwise exactly as given (not resolved, ``..`` not collapsed). ``report_dir`` is ``None`` when positional 2
    is absent or empty. ``scanning_name`` is ``None`` when positional 3 is absent or empty (the run timestamp is
    used, contract 1.4)."""
    scan_dir: str
    report_dir: "str | None"
    scanning_name: "str | None"


def positional_words(argv: Sequence[str]) -> list[str]:
    """Contract 1.1: drop every word that begins with ``--`` (including a lone ``--``), keep the order, keep
    positionals beyond the third (they are ignored later). A word with a single leading dash is a positional."""
    raise NotImplementedError


def scanning_name_error(name: str) -> "str | None":
    """Contract 1.4. Return the refusal text, or ``None`` if ``name`` is acceptable: it must not contain ``/``, must
    not start with ``.``, must not contain a control character (Unicode category Cc: C0, DEL, C1), and is limited
    to 150 CHARACTERS. The empty string is acceptable (it means "use the timestamp")."""
    raise NotImplementedError


def parse_args(argv: Sequence[str], *, prog: str = "scan_pipeline.py") -> Args:
    """Parse ``argv`` (WITHOUT the program name) and run the four checks of contract 1.2 in order:
    (1) no positional -> usage; (2) positional 1 is not an existing directory (``os.path.isdir``: a symlink to a
    directory counts, a file or the empty string does not); (3) positional 2 non-empty and not a directory;
    (4) positional 3 refused by ``scanning_name_error``. Raises ``UsageError`` for the first one that fails.
    Never creates anything."""
    raise NotImplementedError
