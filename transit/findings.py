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
import json
import types
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
        return {
            "tool": json_safe(self.tool),
            "category": json_safe(self.category),
            "severity": json_safe(self.severity),
            "rule_id": json_safe(self.rule_id),
            "rule_name": json_safe(self.rule_name),
            "file": json_safe(self.file),
            "line": self.line,
            "column": self.column,
            "message": json_safe(self.message),
            "references": [json_safe(ref) for ref in self.references],
        }


#: Private tables. Names are keys of ``SEVERITY_NUMBER``; the words are what a producer or a Semgrep field may say.
_SEVERITIES: Mapping[str, Severity] = {name: Severity(name, number) for name, number in SEVERITY_NUMBER.items()}
_HIGH = _SEVERITIES["HIGH"]
_CRITICAL = _SEVERITIES["CRITICAL"]
_WORD_TO_NAME: Mapping[str, str] = {
    "INFO": "INFO", "LOW": "LOW", "WARNING": "MEDIUM", "MEDIUM": "MEDIUM", "ERROR": "HIGH", "HIGH": "HIGH",
    "CRITICAL": "CRITICAL"}
#: Markers searched in a message, in the order of contract 6.3 (the WARNING/MEDIUM and ERROR/HIGH pairs share a rank).
_MARKERS = ((":info:", "INFO"), (":low:", "LOW"), (":warning:", "MEDIUM"), (":medium:", "MEDIUM"),
            (":error:", "HIGH"), (":high:", "HIGH"), (":critical:", "CRITICAL"))
#: ``str.translate`` tables that fold ASCII letters only (``str.lower`` also folds other scripts; ``grep -i`` in the C
#: locale does not, and a severity marker is ASCII).
_ASCII_LOWER = {c: c + 32 for c in range(65, 91)}
_ASCII_UPPER = {c: c - 32 for c in range(97, 123)}


def _ascii_lower(text: str) -> str:
    return text.translate(_ASCII_LOWER)


def _ascii_upper(text: str) -> str:
    return text.translate(_ASCII_UPPER)


def _is_ascii_letter(char: str) -> bool:
    return "a" <= char <= "z" or "A" <= char <= "Z"


def _is_ascii_digit(char: str) -> bool:
    return "0" <= char <= "9"


def _semgrep_word(message: str) -> str:
    """The ``<WORD>`` of ``semgrep[<ruleset>]:<rule>:line<N>:<WORD>:``, or ``""`` when the message does not have that
    shape. The bash regex is ``^semgrep\\[[^]]*\\]:[^:]*:line[0-9]*:([A-Za-z]+):``; every step below is deterministic
    (a class that excludes the next literal cannot backtrack), so this is one pass."""
    size = len(message)
    close = message.find("]", 8)                      # len("semgrep[") == 8
    if close < 0 or message[close + 1:close + 2] != ":":
        return ""
    colon = message.find(":", close + 2)
    if colon < 0 or not message.startswith(":line", colon):
        return ""
    pos = colon + 5
    while pos < size and _is_ascii_digit(message[pos]):
        pos += 1
    if message[pos:pos + 1] != ":":
        return ""
    start = pos + 1
    end = start
    while end < size and _is_ascii_letter(message[end]):
        end += 1
    if end == start or message[end:end + 1] != ":":
        return ""
    return message[start:end]


def _severity_from_name(name: object) -> "Severity | None":
    """A severity a producer states as a field. Unknown names are ignored by the callers (they classify the message)."""
    if not isinstance(name, str):
        return None
    mapped = _WORD_TO_NAME.get(_ascii_upper(name))
    return _SEVERITIES[mapped] if mapped else None


def _resolve_severity(message: str, override: "str | None" = None) -> Severity:
    """The ONE severity of a finding: the producer's field when it gave a known one, else the classifier. ``verdict``
    uses it for the ``--min-severity`` test and ``build_record`` for the record, so the two cannot differ."""
    if override is not None:
        stated = _severity_from_name(override)
        if stated is not None:
            return stated
    return classify_severity(message)


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
    if message.startswith(("gitleaks:", "clamav:")):
        return _CRITICAL
    if message.startswith("semgrep["):
        word = _semgrep_word(message)
        name = _WORD_TO_NAME.get(_ascii_upper(word)) if word else None
        return _SEVERITIES[name] if name else _HIGH
    folded = _ascii_lower(message)
    for marker, name in _MARKERS:
        if marker in folded:
            return _SEVERITIES[name]
    return _HIGH


def relative_to_scan_dir(file: str, scan_dir: str) -> str:
    """Bash ``${file#"$SCAN_DIR/"}``: ``file`` with a leading ``scan_dir + "/"`` removed, otherwise unchanged. For a
    whole-directory finding (``file == scan_dir``) the result is ``scan_dir`` itself. This is the ``rel_path`` of
    contract 6.2 step 1, the allowlist key's second half."""
    prefix = scan_dir + "/"
    return file[len(prefix):] if file.startswith(prefix) else file


def join_scan_path(scan_dir: str, rel: str) -> str:
    """The path string under which a file is recorded: ``scan_dir + "/" + rel``, except that for ``scan_dir == "/"`` it
    is ``"/" + rel`` (what ``find /`` prints). Used by ``files.py`` and by tool wrappers that receive relative paths."""
    return "/" + rel if scan_dir == "/" else scan_dir + "/" + rel


def allowlist_tokens(message: str) -> tuple[str, str]:
    """The two rule tokens tried, in order, for the allowlist (contract 6.2 step 2): the text before the first ``:`` and
    the text between the first and the second ``:``. For a message with no colon both are the whole message."""
    first, colon, rest = message.partition(":")
    if not colon:
        return (message, message)
    return (first, rest.partition(":")[0])


#: Longest run of digits taken for a line number (``int()`` refuses 4300 digits on Python 3.11+, and no file has 10**18 lines).
_MAX_LINE_DIGITS = 18
_PREFIX_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")


def _line_number(message: str) -> "int | None":
    """The integer after the first ``:line`` that is followed by a digit (bash ``=~ :line([0-9]+)``)."""
    size = len(message)
    pos = message.find(":line")
    while pos >= 0:
        start = pos + 5
        end = start
        while end < size and _is_ascii_digit(message[end]):
            end += 1
        if end > start:
            return int(message[start:end]) if end - start <= _MAX_LINE_DIGITS else None
        pos = message.find(":line", start)
    return None


def _generic_prefix(message: str) -> "tuple[str, str] | None":
    """``^([a-z][a-z0-9_-]{1,30}):([^:]+)`` -> (prefix, text up to the next colon), or None."""
    colon = message.find(":")
    if colon < 2 or colon > 31:
        return None
    prefix = message[:colon]
    if not ("a" <= prefix[0] <= "z") or not all(c in _PREFIX_CHARS for c in prefix):
        return None
    detail = message[colon + 1:].partition(":")[0]
    return (prefix, detail) if detail else None


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
    tool = ""
    category = "security"
    rule_id = ""
    rule_name = ""
    references: "tuple[str, ...]" = ()
    if message.startswith(ENGINE_PREFIX):
        tool = "engine"
        rule_id = message[len(ENGINE_PREFIX):].partition(":")[0]
    elif message.startswith("semgrep["):
        tool, category = "semgrep", "sast"
        cut = message.find("]:")
        rule_id = (message[cut + 2:] if cut >= 0 else message).partition(":")[0]
    elif message.startswith("detect-secrets:"):
        tool, category = "detect-secrets", "secret"
        rule_id, rule_name, references = "high_entropy_string", "High Entropy String", ("CWE-798",)
    elif message.startswith("clamav:"):
        tool, category = "clamav", "malware"
        rule_id, rule_name = message[len("clamav:"):], "Malware Detected"
    elif message.startswith("gitleaks:"):
        tool, category = "gitleaks", "secret"
        rule_id = message[len("gitleaks:"):].partition(":")[0]
        rule_name, references = "Secret Detected", ("CWE-798",)
    elif message.startswith("yara:"):
        tool, category = "yara", "ioc"
        rule_id, rule_name = message[len("yara:"):], "IOC Match"
    elif message.startswith("bandit:"):
        tool, category = "bandit", "sast"
        after = message[len("bandit:"):]
        second = after.find(":")
        rule_id = after[second + 1:] if second >= 0 else message       # bash ${msg#bandit:*:}, A16
        rule_name = "Bandit Finding"
    elif message.startswith("cppcheck:"):
        tool, category = "cppcheck", "sast"
        rule_id, rule_name = message[len("cppcheck:"):], "Cppcheck Finding"
    elif message.startswith("shellcheck:"):
        tool, category = "shellcheck", "sast"
        rule_id, rule_name = message[len("shellcheck:"):], "ShellCheck Finding"
    elif message.startswith("CWE-") and message.find(":", 4) >= 0:
        tool, category = "grep-pattern", "cwe"
        rule_id, _, rule_name = message.partition(":")
        references = (rule_id,)
    elif message.startswith("OWASP-") and message.find(":", 6) >= 0:
        tool, category = "grep-pattern", "owasp"
        rule_id, _, rule_name = message.partition(":")
    else:
        generic = _generic_prefix(message)
        if generic is not None:
            tool, rule_id = generic
    if not rule_name:
        rule_name = message
    if not tool:
        tool = "unknown"
    # A finding about the whole directory has no file: ".". Only the directory itself is that (bash also turned a file
    # called like the scan-directory string into "."; that file keeps its name here).
    rel = "." if file == scan_dir else relative_to_scan_dir(file, scan_dir)
    return FindingRecord(tool=tool, category=category, severity=_resolve_severity(message, severity).name,
                         rule_id=rule_id, rule_name=rule_name, file=rel, line=_line_number(message), column=None,
                         message=message, references=references)


@dataclasses.dataclass(frozen=True)
class Allowlist:
    """``.transit-allow.json`` after parsing: ``(rule, path) -> reason``. Immutable."""
    entries: Mapping[tuple[str, str], str]

    def __len__(self) -> int:
        return len(self.entries)

    def lookup(self, message: str, rel_path: str) -> "str | None":
        """The reason of the first entry that matches (contract 6.2 step 2): for each token of
        ``allowlist_tokens(message)`` in order, the entry ``(token, rel_path)`` with a NON-EMPTY reason. Matching is
        exact string equality (case-sensitive, no glob, no ``./``). A message starting ``engine:`` never matches."""
        if message.startswith(ENGINE_PREFIX):
            return None
        for token in allowlist_tokens(message):
            reason = self.entries.get((token, rel_path))
            if reason:
                return reason
        return None


_ALLOW_FILE = ".transit-allow.json"
_NO_ENTRIES: Mapping[tuple[str, str], str] = types.MappingProxyType({})
#: Characters bash's ``read`` splits an allowlist line on (U+0001, the field separator) and a line on (LF).
_FIELD_SEPARATOR = "\x01"


def _is_text(value: str) -> bool:
    """True if ``value`` can become a file name: a lone surrogate other than an escaped byte (U+DC80..U+DCFF) is what
    crashed the bash loader's ``print`` (and made it drop every later entry)."""
    try:
        value.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return False
    return True


def _entry_note(index: int, why: str) -> str:
    return "%s entry [%d] ignored: %s" % (_ALLOW_FILE, index, why)


def _store(entries: dict, rule: str, path: str, reason: str) -> None:
    """Last entry wins, as ``ALLOW_MAP[key]=...`` does in bash; an empty reason can only take an exception away."""
    if reason:
        entries[(rule, path)] = reason
    else:
        entries.pop((rule, path), None)


def _parse_allowlist(raw: bytes, strict: bool) -> "tuple[Allowlist, tuple[str, ...]]":
    notes: "list[str]" = []

    def nothing(why: str) -> "tuple[Allowlist, tuple[str, ...]]":
        return Allowlist(_NO_ENTRIES), ((("%s ignored: %s" % (_ALLOW_FILE, why)),) if strict else ())

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return nothing("not valid UTF-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return nothing("not valid JSON")
    if not isinstance(data, list):
        return nothing("not a JSON array")
    entries: dict = {}
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            if strict:
                notes.append(_entry_note(index, "not an object"))
            continue
        if strict:
            why = _strict_problem(item)
            if why is not None:
                notes.append(_entry_note(index, why[0]))
                if why[1]:                                  # an entry that states no reason takes its key away
                    entries.pop((item["rule"], item["path"]), None)
                continue
            _store(entries, item["rule"], item["path"], item["reason"])
            continue
        rule, path, reason = item.get("rule", ""), item.get("path", ""), item.get("reason", "")
        if not (isinstance(rule, str) and isinstance(path, str) and isinstance(reason, str)
                and _is_text(rule) and _is_text(path) and _is_text(reason)):
            break                                           # bash: the print raised, this entry and the rest are lost
        if rule == "":
            continue
        if _FIELD_SEPARATOR in rule or _FIELD_SEPARATOR in path or "\n" in rule or "\n" in path:
            continue                                        # bash would split it into entries the file does not state
        _store(entries, rule, path, reason.partition("\n")[0])
    return Allowlist(types.MappingProxyType(entries)), tuple(notes)


def _strict_problem(item: dict) -> "tuple[str, bool] | None":
    """Why a strict-mode entry is not usable, and whether it should still revoke an earlier entry for its key."""
    for member in ("rule", "path", "reason"):
        if member in item and not isinstance(item[member], str):
            return ("%s is not a string" % member, False)
    if not item.get("rule"):
        return ("rule is missing or empty", False)
    if "path" not in item:
        return ("path is missing", False)
    for member in ("rule", "path", "reason"):
        if member in item and not _is_text(item[member]):
            return ("%s is not valid text" % member, False)
    if not item.get("reason"):
        return ("reason is missing or empty", True)
    return None


def parse_allowlist(raw: bytes, *, strict: bool = False) -> tuple[Allowlist, tuple[str, ...]]:
    """Parse the bytes of ``.transit-allow.json`` (contract 6.2, A10, S15). Returns the allowlist and the notes to print
    on stderr (never recorded in the report). Fails CLOSED: any failure yields fewer entries, never more.

    NEVER RAISES. The whole body runs under ``except Exception``, not ``except ValueError``: ``json.loads`` of a 400 KB
    ``[[[[...`` raises ``RecursionError`` (a ``RuntimeError``, measured on Python 3.10 to 3.13) and a huge document can raise
    ``MemoryError``; either would otherwise escape the pipeline's step 7 (review log R-05). Such a file yields an empty
    allowlist and the note ``.transit-allow.json ignored: <exception class name>`` (the class name only).

    ``strict=False`` (default; reproduces bash, D-010 as ``copy``): not UTF-8, not JSON or not a list -> empty. Entries
    are visited in order: a non-object entry is skipped; an entry whose ``rule``, ``path`` or ``reason`` is present and
    not a string STOPS the loop (that entry and every later one are dropped); a missing member is ``""``; an entry
    with an empty ``rule`` is skipped; a ``reason`` is cut at its first newline; a ``rule`` or ``path`` that contains
    the character U+0001 is dropped (bash splits on it).
    ``strict=True`` (switch ``D-010``): only the malformed entry is skipped (note names its index and why), a reason is
    kept whole. An entry with no non-empty string ``reason`` is never honoured in either mode."""
    try:
        return _parse_allowlist(raw, strict)
    except Exception as exc:                      # RecursionError and MemoryError are not ValueErrors (F16, R-05)
        return Allowlist(_NO_ENTRIES), ("%s ignored: %s" % (_ALLOW_FILE, type(exc).__name__),)


def json_safe(text: str) -> str:
    """Make ``text`` encodable as strict UTF-8: each undecodable byte (a lone surrogate from ``os.fsdecode``) becomes
    U+FFFD, exactly as ``os.fsencode(text).decode("utf-8", "replace")`` (golden ``hostile_non_utf8_name``, D-023).
    Two distinct invalid names can collide on one key; that is the documented bash behaviour (A23). ``report.build_report`` MERGES
    the colliding entries (worst status wins, messages concatenated; review log R-12), so a clean file cannot overwrite the FAIL of
    a malicious one."""
    try:
        data = text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:                    # a surrogate that is not an escaped byte: os.fsencode would raise
        data = "".join("\ufffd" if "\ud800" <= c <= "\udfff" and not "\udc80" <= c <= "\udcff" else c
                       for c in text).encode("utf-8", "surrogateescape")
    return data.decode("utf-8", "replace")


_MARKER_WORDS = ("info", "low", "warning", "medium", "error", "high", "critical")
#: ``str.translate`` table: C0 controls, DEL and "|" become "?" (everything non-ASCII is handled by the ascii codec).
_UNPRINTABLE = {c: "?" for c in list(range(0, 32)) + [0x7F, ord("|")]}


def neutralise_detail(detail: str, *, max_chars: int) -> str:
    """S7, for container scanners that put an archive entry name or part name in a message: non-printable characters
    and ``|`` become ``?``; a colon that closes a word in {info, low, warning, medium, error, high, critical}
    (case-insensitive) becomes ``?`` so the text cannot be read as a severity marker; the result is cut to
    ``max_chars`` (110 for jar, 120 for office). The caller keeps at most 6 distinct details."""
    if max_chars <= 0:
        return ""
    # one output character per input character: ASCII printable stays, everything else (control, non-ASCII, a lone
    # surrogate) and "|" become "?"; the cut comes first because it cannot change which colons close a marker
    text = detail[:max_chars].encode("ascii", "replace").decode("ascii").translate(_UNPRINTABLE)
    if ":" not in text:
        return text
    folded = text.lower()                         # ASCII only at this point
    closers = []
    for word in _MARKER_WORDS:
        needle = word + ":"
        found = folded.find(needle)
        while found >= 0:
            if found == 0 or not ("a" <= folded[found - 1] <= "z"):     # the word starts here: it is a whole word
                closers.append(found + len(word))
            found = folded.find(needle, found + 1)
    if not closers:
        return text
    chars = list(text)
    for index in closers:
        chars[index] = "?"
    return "".join(chars)
