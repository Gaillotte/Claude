"""File dispatch: which scanner a file goes to (bash ``classify_file``, contract 8.8).

Owner of: contract 8.8 rules 2 to 5 (basename arms, extension arms, the inline-rule extensions, the unknown fallback), the
sniffing probes (RTF head, Flat OPC head), the shebang routes of ``scan_unknown``, and the machine-readable route tables that
``build_pdf_filetypes.py --check`` is retargeted at when the bash engine is retired.

Layering: depends on ``transit.files`` only (for ``FileView``); the scanners are reached through the ``run`` callback, so this
module imports no scanner and no registry. The universal layer (contract 8.8 rule 1) is NOT here: ``layers.run_file_layers``
runs it before calling ``classify_file``.

The tables are DATA and are already final (verified against ``build_pdf_filetypes.routed_patterns()``: 109 extensions and 7
basename arms, and against the 34 family keys of ``FAMILIES``): a Phase 3 package never edits them; it registers a scanner
for an id that is already routed.
"""
from __future__ import annotations

import fnmatch
from typing import Callable, Mapping

from transit.files import FileView

#: Contract 8.8 rule 2, in this order, case-sensitive ``fnmatch.fnmatchcase`` on the BASENAME. One tuple per ``case`` arm of
#: ``classify_file``: (patterns of the arm, scanner id). They end the dispatch.
BASENAME_ROUTES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("Dockerfile*",), "docker"),
    (("Makefile*", "makefile*", "GNUmakefile*"), "makefile"),
    (("CMakeLists.txt", "CMakeLists.*.txt"), "cmake"),
    (("package.json", "composer.json"), "manifest.package_json"),
    (("requirements*.txt", "constraints*.txt"), "manifest.requirements"),
    (("gradle.properties", "gradle-wrapper.properties", "*.gradle", "*.gradle.kts"), "gradle"),
    (("setup.py", "conanfile.py"), "setuppy"),
)

#: Contract 8.8 rule 3: lower-cased extension with its dot -> scanner id (109 extensions).
EXT_ROUTES: Mapping[str, str] = {
    ".py": "python",
    **{e: "js" for e in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")},
    ".java": "java", ".php": "php", ".rb": "ruby", ".go": "go",
    **{e: "c" for e in (".c", ".cpp", ".h", ".hpp", ".cc")},
    **{e: "shell" for e in (".sh", ".bash", ".zsh", ".ksh")},
    **{e: "powershell.text" for e in (".ps1", ".psm1", ".psd1", ".pssc", ".psrc")},
    **{e: "powershell.xml" for e in (".ps1xml", ".psc1", ".cdxml")},
    **{e: "batch" for e in (".bat", ".cmd")},
    ".rs": "rust", ".kt": "kotlin", ".kts": "kotlin", ".cs": "csharp",
    ".xml": "xml", ".pom": "xml", ".yml": "yaml", ".yaml": "yaml",
    **{e: "terraform" for e in (".tf", ".tfvars", ".hcl")},
    **{e: "binary" for e in (".so", ".dll", ".dylib", ".exe", ".elf", ".bin")},
    **{e: "archive" for e in (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz")},
    **{e: "jar" for e in (".jar", ".war", ".ear", ".aar")},
    **{e: "ooxml" for e in (".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xlsb", ".xltx", ".xltm", ".xlam",
                           ".pptx", ".pptm", ".ppsx", ".ppsm", ".potx", ".potm", ".ppam")},
    **{e: "legacy_office" for e in (".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot", ".pps", ".ppa")},
    **{e: "odf" for e in (".odt", ".ods", ".odp", ".odg", ".ott", ".ots", ".otp", ".otg", ".fodt", ".fods", ".fodp", ".fodg")},
    ".rtf": "rtf", ".pdf": "pdf",
    **{e: "makefile" for e in (".mk", ".mak", ".make")},
    **{e: "html" for e in (".html", ".htm", ".xhtml")},
    ".cmake": "cmake", ".sql": "sql", ".json": "json",
    **{e: "docs" for e in (".md", ".txt", ".rst")},
}

#: Extensions whose files are sniffed for an RTF header before the ``docs`` rule runs (contract 8.8 / 8.7).
RTF_SNIFFED_EXTS = frozenset({".md", ".txt", ".rst"})

#: ``scan_unknown``: first line -> scanner id, ``fnmatch.fnmatchcase`` on the WHOLE first line, first match wins. Note the
#: quirk (D-031): ``#!/bin/bash -e`` matches nothing, because the pattern must END in ``/bash``. Copied from bash; switch D-031
#: matches on the first word instead.
SHEBANG_ROUTES: tuple[tuple[str, str], ...] = (
    ("#!*python*", "python"),
    ("#!*/bash", "shell"), ("#!*/sh", "shell"), ("#!*env bash", "shell"), ("#!*env sh", "shell"),
    ("#!*/zsh", "shell"), ("#!*/ksh", "shell"),
    ("#!*ruby*", "ruby"), ("#!*node*", "js"), ("#!*php*", "php"),
    ("#!*pwsh*", "powershell.text"), ("#!*powershell*", "powershell.text"),
)

#: Callback given to ``classify_file``: ``run(scanner_id, sniffed) -> handled``. The layer supplies it (it builds the
#: ``ScanContext`` and calls ``scanners.invoke``), so dispatch stays free of the registry.
RunScanner = Callable[[str, bool], bool]

#: ``bash ${x,,}`` in the C locale (the hardened script runs with ``LC_ALL=C``): A-Z only. ``str.lower`` would also fold the Kelvin sign
#: and other characters outside ASCII, so ``x.<KELVIN>t`` would reach the Kotlin scanner here and the unknown scanner in bash.
_ASCII_LOWER = {c: c + 32 for c in range(65, 91)}
#: ``[:space:]`` in the C locale: what bash's ``${h#"${h%%[![:space:]]*}"}`` removes from the front of the head.
_BASH_SPACE = b" \t\n\r\x0b\x0c"
_RTF_MARKER = b"{\\rtf"
#: ``read -N 16`` and ``read -N 8192``: bash reads that many characters that are not NUL (a NUL byte is dropped and does not count).
_RTF_HEAD_CHARS = 16
_FLAT_HEAD_CHARS = 8192
_FLAT_OFFICE_MARKERS = (b"schemas.microsoft.com/office/2006/xmlPackage", b"schemas.microsoft.com/office/word/2003/wordml",
                        b"urn:schemas-microsoft-com:office:spreadsheet")
#: ``_shebang_interpreter_line`` looks at ``${1:0:1024}``.
_SHEBANG_WINDOW = 1024
_SHEBANG_GLOB_CHARS = frozenset("?[\\")


def lower_ext(path: str) -> str:
    """``${f##*.}`` lower-cased, with the dot: the text after the last ``.`` of the FULL path (``"." + whole path`` when
    there is no dot, which routes nowhere). Only A-Z are lowered: the hardened bash engine runs in the C locale (``LC_ALL=C``)."""
    # ``str.lower`` would also fold the Kelvin sign and other characters outside ASCII (``_ASCII_LOWER``); ``FileView.ext`` does the same.
    return "." + path.rpartition(".")[2].translate(_ASCII_LOWER)


def _first_chars_without_nul(view: FileView, count: int) -> bytes:
    """The first ``count`` bytes of the file that are not NUL, as bash ``read -N count`` delivers them: a NUL byte is dropped and is not
    counted, so a file that starts with NULs (or is UTF-16, a NUL between every two letters) is read through them. The file is read in
    growing windows, never past what is needed; a file of nothing but NULs costs one pass."""
    window = count
    while True:
        chunk = view.head(window)
        kept = chunk.replace(b"\0", b"") if b"\0" in chunk else chunk
        if len(kept) >= count or len(chunk) < window:
            return kept[:count]
        window *= 4


def rtf_head(view: FileView) -> bool:
    """Bash ``_rtf_head``: the first 16 bytes, leading whitespace removed, start with ``{\\rtf``."""
    # Like bash, the 16 are the first 16 bytes that are not NUL, and the whitespace is part of the 16 (a head that is all whitespace
    # is not an RTF): ``read -N 16`` then ``${h#"${h%%[![:space:]]*}"}`` then ``[[ $h == '{\\rtf'* ]]``.
    head = _first_chars_without_nul(view, _RTF_HEAD_CHARS).lstrip(_BASH_SPACE)
    return head.startswith(_RTF_MARKER)


def flat_office_head(view: FileView) -> bool:
    """Bash ``_flat_office_head``: the first 8192 bytes contain ``schemas.microsoft.com/office/2006/xmlPackage``,
    ``schemas.microsoft.com/office/word/2003/wordml`` or ``urn:schemas-microsoft-com:office:spreadsheet``."""
    # The 8192 are bytes that are not NUL, as for ``_rtf_head``: a UTF-16 Flat OPC package (Word opens it) reads as its ASCII text.
    head = _first_chars_without_nul(view, _FLAT_HEAD_CHARS)
    return any(marker in head for marker in _FLAT_OFFICE_MARKERS)


def shebang_scanner(first_line: bytes, *, first_word_only: bool = False) -> "str | None":
    """The scanner id for a first line (``FileView.first_line``) by ``SHEBANG_ROUTES`` (decoded as latin-1), or None.
    ``first_word_only`` is the D-031 behaviour (``scanners.unknown`` passes ``ctx.cfg.fix("D-031")``): only the text up to the first
    space after ``#!`` plus the interpreter word is matched, so ``#!/bin/bash -e`` is routed."""
    line = _one_line(first_line)
    subject = _interpreter_line(line) if first_word_only else line
    for pattern, scanner_id in SHEBANG_ROUTES:
        if _glob(pattern, subject):
            return scanner_id
    return None


def _one_line(first_line: bytes) -> bytes:
    """What ``IFS= read -r`` delivers from the head of a file: the bytes before the first LF, with NUL bytes dropped (``FileView.first_line``
    already does both; doing it again is free and makes a raw head safe to pass)."""
    end = first_line.find(b"\n")
    if end >= 0:
        first_line = first_line[:end]
    return first_line.replace(b"\0", b"") if b"\0" in first_line else first_line


def _glob(pattern: str, subject: bytes) -> bool:
    """``case`` pattern matching of ``subject``. Every pattern of ``SHEBANG_ROUTES`` has ``*`` as its only wildcard, so it is matched with
    ``bytes`` searches (linear in the line, no copy: the first line of a file with no LF can be the whole file); a pattern with another
    wildcard goes through ``fnmatch.fnmatchcase`` on the Latin-1 text of the line."""
    if _SHEBANG_GLOB_CHARS.intersection(pattern):
        return fnmatch.fnmatchcase(subject.decode("latin-1"), pattern)
    return _star_glob(pattern.encode("latin-1"), subject)


def _star_glob(pattern: bytes, subject: bytes) -> bool:
    """Glob match of ``subject`` by ``pattern`` whose only wildcard is ``*`` (any run of bytes, empty included): the first piece is a prefix,
    the last a suffix, the pieces between them occur in order and do not overlap."""
    pieces = pattern.split(b"*")
    if len(pieces) == 1:
        return subject == pattern
    first, last = pieces[0], pieces[-1]
    if len(subject) < len(first) + len(last) or not subject.startswith(first) or not subject.endswith(last):
        return False
    position, stop = len(first), len(subject) - len(last)
    for piece in pieces[1:-1]:
        if not piece:
            continue
        found = subject.find(piece, position, stop)
        if found < 0:
            return False
        position = found + len(piece)
    return True


def _split_words(text: str) -> "list[str]":
    """``IFS=$' \\t' read -r -a``: words separated by runs of spaces and tabs, nothing else (no other white space, no quote, no backslash)."""
    return [word for word in text.replace("\t", " ").split(" ") if word]


def _interpreter_line(line: bytes) -> bytes:
    """Bash ``_shebang_interpreter_line`` (hardened, D-031): a shebang line reduced to the interpreter it names, so that the patterns of
    ``SHEBANG_ROUTES`` (which end at ``/bash``, ``env bash`` ...) see ``#!/bin/bash -e`` as ``#!/bin/bash``::

        #!/bin/bash -e                    -> #!/bin/bash
        #!/usr/bin/env python3 -u         -> #!/usr/bin/env python3
        #!/usr/bin/env -S python3 -u      -> #!/usr/bin/env python3     (env options and NAME=value words are skipped)

    Only the first 1024 bytes are read; one CR at the end of them is not part of the last word. A line that is not a shebang, or names no
    interpreter in those 1024 bytes, is returned as it is (so ``#!`` plus 1100 blanks plus ``python`` is still a Python script, as in
    bash). The line is hostile text: it is split into words and compared, never run, expanded or globbed."""
    window = line[:_SHEBANG_WINDOW].decode("latin-1")
    if not window.startswith("#!"):
        return line
    if window.endswith("\r"):
        window = window[:-1]
    words = _split_words(window[2:])
    if not words:
        return line
    interpreter = words[0]
    reduced = "#!" + interpreter
    if interpreter.rpartition("/")[2] == "env":
        command = _env_command(words)
        if command:
            reduced = reduced + " " + command
    return reduced.encode("latin-1")


def _env_command(words: "list[str]") -> str:
    """The command ``env`` runs, from the words of ``#!<env> ...`` (``words[0]`` is the ``env`` word itself). Walks ``words[1:]`` by index,
    because ``-S`` hands ``env`` a string that ``env`` splits again: the interpreter is often written inside the option (``-Spython3 -u``,
    ``--split-string=python3``, ``-iSbash``) and the words of that string replace the option in the list. Each replacement removes at least
    the two characters of ``-S``, so a line of 1024 bytes cannot loop for long. Returns "" when no command is found."""
    words = list(words)
    skip = False
    index = 1
    command = ""
    while index < len(words):
        word = words[index]
        index += 1
        if skip:
            skip = False
            continue
        more: "list[str]" = []
        if word.startswith("--split-string="):
            more = _split_words(word[len("--split-string="):])
        elif word in ("-u", "-C", "--unset", "--chdir"):
            skip = True                                   # an option that takes a value
            continue
        elif word.startswith(("--unset=", "--chdir=")) or word.startswith("--"):
            continue
        elif len(word) >= 2 and word[0] == "-":
            # A cluster of short options (-i, -v, -0, -S ...). The first of S, u, C ends it: it takes the rest of the word as its
            # value, or the next word when nothing follows.
            options = word[1:]
            for position, letter in enumerate(options):
                if letter == "S":
                    more = _split_words(options[position + 1:])
                    break
                if letter in "uC":
                    skip = position + 1 == len(options)
                    break
            if not more:
                continue
        elif word == "-" or "=" in word:
            continue                                      # a bare dash, or a NAME=value assignment
        else:
            command = word
            break
        if more:
            words[index:index] = more                      # the split string stands where the option stood
    if command[:1] in ("'", '"'):
        command = command[1:]
    if command[-1:] in ("'", '"'):
        command = command[:-1]
    return command


def classify_file(view: FileView, run: RunScanner) -> None:
    """Contract 8.8 rules 2 to 5 for one file (the universal layer has already run). Control flow, exactly bash's. (There is no switch
    parameter: shebang routing, where D-031 matters, lives in ``scanners.unknown`` and reads ``ctx.cfg.fix("D-031")`` there; review log R-25.)
      1. basename arms, in order; a hit calls ``run(id, False)`` and ends;
      2. ``ext = lower_ext(view.path)``; ``id = EXT_ROUTES.get(ext)``;
      3. ``xml`` (``.xml``, ``.pom``): ``run("xml", False)``, then, if ``flat_office_head(view)``, ``run("ooxml", True)`` whatever it
         returns;
      4. ``docs`` (``.md``, ``.txt``, ``.rst``): if ``rtf_head(view)`` and ``run("rtf", True)`` returns True, stop; otherwise
         ``run("docs", False)``;
      5. any other routed extension: ``run(id, False)``;
      6. no route: if ``rtf_head(view)`` and ``run("rtf", True)`` returns True, stop; otherwise ``run("unknown", False)``.
    ``run`` for a scanner that is not ported records a WARN and returns True, so a sniffed RTF is never read as plain text."""
    # bash: base=$(basename "$f"): a command substitution drops trailing newlines, so a file called ``setup.py<LF>`` still meets the
    # ``setup.py`` arm there (the extension, ${f##*.}, keeps the newline and routes nowhere). Same here.
    base = view.basename.rstrip("\n")
    for patterns, scanner_id in BASENAME_ROUTES:
        if any(fnmatch.fnmatchcase(base, pattern) for pattern in patterns):
            run(scanner_id, False)
            return
    ext = lower_ext(view.path)
    scanner_id = EXT_ROUTES.get(ext)
    if scanner_id == "xml":
        # Word and Excel open a Flat OPC package or a 2003 XML document from a .xml: the answer of the office scanner is ignored
        run("xml", False)
        if flat_office_head(view):
            run("ooxml", True)
        return
    if ext in RTF_SNIFFED_EXTS:
        # Word opens an RTF whatever it is called; the docs scanner reads what the office scanner does not take
        if rtf_head(view) and run("rtf", True):
            return
        run("docs", False)
        return
    if scanner_id is not None:
        run(scanner_id, False)
        return
    if rtf_head(view) and run("rtf", True):
        return
    run("unknown", False)


def routed_patterns() -> "tuple[set[str], set[str]]":
    """(extension set, basename-arm set) in the shape of ``build_pdf_filetypes.routed_patterns()``: extensions with their dot, and
    each basename arm as its patterns joined by ``|`` (``'Makefile*|makefile*|GNUmakefile*'``). A test asserts equality with it."""
    return set(EXT_ROUTES), {"|".join(patterns) for patterns, _ in BASENAME_ROUTES}
