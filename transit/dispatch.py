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


def lower_ext(path: str) -> str:
    """``${f##*.}`` lower-cased, with the dot: the text after the last ``.`` of the FULL path (``"." + whole path`` when
    there is no dot, which routes nowhere). ``str.lower`` (matches bash in a UTF-8 locale)."""
    raise NotImplementedError


def rtf_head(view: FileView) -> bool:
    """Bash ``_rtf_head``: the first 16 bytes, leading whitespace removed, start with ``{\\rtf``."""
    raise NotImplementedError


def flat_office_head(view: FileView) -> bool:
    """Bash ``_flat_office_head``: the first 8192 bytes contain ``schemas.microsoft.com/office/2006/xmlPackage``,
    ``schemas.microsoft.com/office/word/2003/wordml`` or ``urn:schemas-microsoft-com:office:spreadsheet``."""
    raise NotImplementedError


def shebang_scanner(first_line: bytes, *, first_word_only: bool = False) -> "str | None":
    """The scanner id for a first line (``FileView.first_line``) by ``SHEBANG_ROUTES`` (decoded as latin-1), or None.
    ``first_word_only`` is the D-031 behaviour (``scanners.unknown`` passes ``ctx.cfg.fix("D-031")``): only the text up to the first
    space after ``#!`` plus the interpreter word is matched, so ``#!/bin/bash -e`` is routed."""
    raise NotImplementedError


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
    raise NotImplementedError


def routed_patterns() -> "tuple[set[str], set[str]]":
    """(extension set, basename-arm set) in the shape of ``build_pdf_filetypes.routed_patterns()``: extensions with their dot, and
    each basename arm as its patterns joined by ``|`` (``'Makefile*|makefile*|GNUmakefile*'``). A test asserts equality with it."""
    raise NotImplementedError
