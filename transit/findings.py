"""Messages, severity, the structured finding record and the allowlist: everything that is a pure function of a
finding message (contract 5, 6.2 step 2, 6.3).

Owner of: contract 5.3 (``_emit_finding``: the record derived from a message), 6.3 (``_classify_severity``, the ONE
classification), the allowlist file format and token matching of 6.2 (D-010 behind a switch), S7 (severity is never
read from repository text; the neutraliser used by container scanners), the JSON-safe string rule of S4 / A23 / D-023.

Layering: a LEAF module (standard library only). Pure functions, no I/O, no state, NO REGULAR EXPRESSIONS: messages can
contain repository text, so every parse here uses ``str.find`` / ``str.partition`` and a digit scan (a lint forbids
``import re`` outside ``transit/rx.py`` and the bash engine's helper scripts).

Severity vocabulary: ``INFO`` and ``LOW`` have number 1, ``MEDIUM`` 2, ``HIGH`` 3, ``CRITICAL`` 4 (contract 6.3).
"""
from __future__ import annotations

import dataclasses
from typing import Mapping

SEVERITY_NUMBER: Mapping[str, int] = {"INFO": 1, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CATEGORIES = ("security", "sast", "secret", "malware", "ioc", "cwe", "owasp")
#: Messages starting with this prefix are engine notes (design section 8). They are never allowlisted and never
#: downgraded by ``--min-severity``: an internal error must not be something a repository can configure away.
ENGINE_PREFIX = "engine:"


@dataclasses.dataclass(frozen=True)
class Severity:
    """A severity as the classifier returns it: ``name`` is one of ``SEVERITY_NUMBER``, ``number`` its value."""
    name: str
    number: int


@dataclasses.dataclass(frozen=True)
class FindingRecord:
    """One element of the report's ``findings`` array: all ten fields of contract section 4, always present.
    ``line`` is an int >= 0 or None; ``column`` is always None. ``file`` is relative to the scan directory, ``.`` for a
    whole-directory finding, and unchanged if the file does not sit under ``scan_dir/`` (E7)."""
    tool: str
    category: str
    severity: str
    rule_id: str
    rule_name: str
    file: str
    line: "int | None"
    column: "int | None"
    message: str
    references: tuple[str, ...]

    def to_json(self) -> dict:
        """The record as a ``dict`` ready for ``json.dumps``: every string passed through ``json_safe``,
        ``references`` as a list. Key set and types exactly as docs/report.schema.json."""
        raise NotImplementedError


def classify_severity(message: str) -> Severity:
    """The one classifier (contract 6.3). First match wins:
      1. a message starting ``gitleaks:`` or ``clamav:`` -> CRITICAL;
      2. a message starting ``semgrep[`` -> classified ONLY from the fixed position
         ``semgrep[<ruleset>]:<rule>:line<N>:<WORD>:`` (``ERROR``/``HIGH`` 3, ``WARNING`` 2, ``INFO`` 1,
         ``CRITICAL`` 4, an unknown word HIGH); text after that position is never read;
      3. any other message is searched, case-insensitively and anywhere, for ``:INFO:``, then ``:LOW:``, then
         ``:WARNING:``/``:MEDIUM:``, then ``:ERROR:``/``:HIGH:``, then ``:CRITICAL:`` in that order, first hit wins
         (``x:LOW:and:CRITICAL:`` is LOW);
      4. no marker -> HIGH. Brackets are not markers; a space after the colon is not one (``bandit:Severity: MEDIUM:B602``
         is HIGH, A16).
    Pure, total, linear time."""
    raise NotImplementedError


def relative_to_scan_dir(file: str, scan_dir: str) -> str:
    """Bash ``${file#"$SCAN_DIR/"}``: ``file`` with a leading ``scan_dir + "/"`` removed, otherwise unchanged. For a
    whole-directory finding (``file == scan_dir``) the result is ``scan_dir`` itself. This is the ``rel_path`` of
    contract 6.2 step 1, the allowlist key's second half."""
    raise NotImplementedError


def join_scan_path(scan_dir: str, rel: str) -> str:
    """The path string under which a file is recorded: ``scan_dir + "/" + rel``, except that for ``scan_dir == "/"`` it
    is ``"/" + rel`` (what ``find /`` prints). Used by ``files.py`` and by tool wrappers that receive relative paths."""
    raise NotImplementedError


def allowlist_tokens(message: str) -> tuple[str, str]:
    """The two rule tokens tried, in order, for the allowlist (contract 6.2 step 2): the text before the first ``:`` and
    the text between the first and the second ``:``. For a message with no colon both are the whole message."""
    raise NotImplementedError


def build_record(file: str, message: str, scan_dir: str, *, severity: "str | None" = None) -> FindingRecord:
    """Derive the structured record from a FAIL message (contract 5.3), first matching row wins:
    ``semgrep[`` -> tool ``semgrep``/``sast``, rule id between ``]:`` and the next ``:``; ``detect-secrets:``;
    ``clamav:``; ``gitleaks:``; ``yara:``; ``bandit:`` (rule id after the SECOND colon); ``cppcheck:`` /
    ``shellcheck:``; ``CWE-*:*`` -> ``grep-pattern``/``cwe``, references ``[CWE-n]``; ``OWASP-*:*`` -> ``grep-pattern``/
    ``owasp``; ``<[a-z][a-z0-9_-]{1,30}>:<non-colon text>`` -> that prefix as tool, category ``security``; anything
    else -> tool ``unknown`` (e.g. ``CVE-2021-44228:...``). ``line`` is the integer after the first ``:line``.
    ``severity`` overrides the classifier ONLY when a producer carries the severity as a field (D-016); the default
    ``None`` classifies the message, which is what keeps the threshold check and the record identical.
    Messages starting ``engine:`` get tool ``engine``, category ``security``, rule id the second segment."""
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class Allowlist:
    """``.transit-allow.json`` after parsing: ``(rule, path) -> reason``. Immutable."""
    entries: Mapping[tuple[str, str], str]

    def __len__(self) -> int:
        raise NotImplementedError

    def lookup(self, message: str, rel_path: str) -> "str | None":
        """The reason of the first entry that matches (contract 6.2 step 2): for each token of
        ``allowlist_tokens(message)`` in order, the entry ``(token, rel_path)`` with a NON-EMPTY reason. Matching is
        exact string equality (case-sensitive, no glob, no ``./``). A message starting ``engine:`` never matches."""
        raise NotImplementedError


def parse_allowlist(raw: bytes, *, strict: bool = False) -> tuple[Allowlist, tuple[str, ...]]:
    """Parse the bytes of ``.transit-allow.json`` (contract 6.2, A10, S15). Returns the allowlist and the notes to print
    on stderr (never recorded in the report). Fails CLOSED: any failure yields fewer entries, never more.

    ``strict=False`` (default; reproduces bash, D-010 as ``copy``): not UTF-8, not JSON or not a list -> empty. Entries
    are visited in order: a non-object entry is skipped; an entry whose ``rule``, ``path`` or ``reason`` is present and
    not a string STOPS the loop (that entry and every later one are dropped); a missing member is ``""``; an entry
    with an empty ``rule`` is skipped; a ``reason`` is cut at its first newline; a ``rule`` or ``path`` that contains
    the character U+0001 is dropped (bash splits on it).
    ``strict=True`` (switch ``D-010``): only the malformed entry is skipped (note names its index and why), a reason is
    kept whole. An entry with no non-empty string ``reason`` is never honoured in either mode."""
    raise NotImplementedError


def json_safe(text: str) -> str:
    """Make ``text`` encodable as strict UTF-8: each undecodable byte (a lone surrogate from ``os.fsdecode``) becomes
    U+FFFD, exactly as ``os.fsencode(text).decode("utf-8", "replace")`` (golden ``hostile_non_utf8_name``, D-023).
    Two distinct invalid names can collide on one key; that is the documented bash behaviour (A23)."""
    raise NotImplementedError


def neutralise_detail(detail: str, *, max_chars: int) -> str:
    """S7, for container scanners that put an archive entry name or part name in a message: non-printable characters
    and ``|`` become ``?``; a colon that closes a word in {info, low, warning, medium, error, high, critical}
    (case-insensitive) becomes ``?`` so the text cannot be read as a severity marker; the result is cut to
    ``max_chars`` (110 for jar, 120 for office). The caller keeps at most 6 distinct details."""
    raise NotImplementedError
