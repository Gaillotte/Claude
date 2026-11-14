"""The two families that ``classify_file`` handles with ONE inline rule each: ``docs`` (``.md .txt .rst``) and ``json`` (``.json``).

Scanner ids ``docs`` and ``json``. (``package.json`` and ``composer.json`` are routed by basename to ``manifest.package_json`` before
the extension is looked at.)

``docs`` (bash ``classify_file`` arm ``.md|.txt|.rst``): dispatch has already tried the RTF sniff, so by the time ``scan_docs`` runs the
file is not an RTF. Rule (FAIL ``CWE-798:hardcoded_credential_in_doc``)::

    (password|secret|api_key)\\s*[:=]\\s*[^${[:space:]][^[:space:]]{4,}        # patterns.json id classify_file:54a7fdd9

then ``ctx.finish(fired)``. ``json``: FAIL ``CWE-798:hardcoded_credential_in_JSON`` for::

    (password|secret|token|api_key|private_key)\\s*"?\\s*:\\s*"[^"${[:space:]]{4,}   # patterns.json id classify_file:df96137c

then ``ctx.finish(fired)``. Both are ``line`` rules, case-sensitive, ``binary="text"``. A README that quotes an attack string fails;
that is what ``.transit-allow.json`` is for (CLAUDE.md).
Acceptance fixture: tests/fixtures/clean/README.md (PASS); golden ``rules_corpus`` entries for ``*.md``/``*.json`` fixtures.

Implementation notes (WP-10).
  * Each scanner is one ``RuleSet`` of one row (ids ``docs/01-hardcoded-credential-in-doc``, ``json/01-hardcoded-credential-in-json``) and the
    function is ``outcome = ctx.run_rules(TABLE); ctx.finish(outcome.fired or outcome.incomplete)``. ``fired`` stays true when the allowlist or
    ``--min-severity`` turned the FAIL into a WARN (bash does not record a PASS then). ``incomplete`` is true when the engine itself recorded a
    FAIL for the file (``engine:scan_incomplete``, ``engine:regex_timeout``, ``engine:search_incomplete``): such a file is not also counted as passed.
  * There is no RTF hand-off in this module: ``dispatch.classify_file`` offers a ``.md``/``.txt``/``.rst`` that starts with ``{\\rtf`` to the RTF
    scanner first and calls ``docs`` only when that scanner returns False.
  * The row is ``binary="text"`` (``grep -a``) while bash's ``grep_check`` has no ``-a``: on a file holding a NUL byte bash reads the NUL as a line
    break, so a match that runs ACROSS the NUL (``password=ab<NUL>cdef``) is found here and not by bash. Neither pattern is anchored, so this can only
    add findings, never hide one (``test_doc.OracleTests`` pins both halves).
"""
from __future__ import annotations

from transit.rules import Match, RuleSet, RuleSpec
from transit.scanners import ScanContext, ScannerSpec

_SOURCE = "classify_file"

#: ``.md .txt .rst`` (bash ``grep_check``, patterns.json id ``classify_file:54a7fdd9``). Case-sensitive, one line at a time, ``binary="text"``
#: (bash has no ``-a``: see the module docstring). The value class is ``[:space:]``, never ``\s``, because inside a bracket expression ``\s`` is the two
#: characters ``\`` and ``s`` (CLAUDE.md "The credential rule's bracket bug").
DOC_RULES: "RuleSet | None" = RuleSet("docs", (
    RuleSpec(id="docs/01-hardcoded-credential-in-doc", outcome="fail", message="CWE-798:hardcoded_credential_in_doc", source=_SOURCE,
             cond=Match(r"(password|secret|api_key)\s*[:=]\s*[^${[:space:]][^[:space:]]{4,}")),
))

#: ``.json`` that is not a package manifest (patterns.json id ``classify_file:df96137c``). Same flags; the semver exclusion of the manifest scanner
#: is deliberately absent here, as in bash.
JSON_RULES: "RuleSet | None" = RuleSet("json", (
    RuleSpec(id="json/01-hardcoded-credential-in-json", outcome="fail", message="CWE-798:hardcoded_credential_in_JSON", source=_SOURCE,
             cond=Match(r'(password|secret|token|api_key|private_key)\s*"?\s*:\s*"[^"${[:space:]]{4,}')),
))


def _scan(ctx: ScanContext, rules: RuleSet) -> bool:
    """The whole of both bash arms: ``if grep_check ...; then record_fail ...; else record_pass; fi``. ``fired`` is true when the rule matched whatever
    ``record_fail`` did with it (the allowlist and ``--min-severity`` turn a FAIL into a WARN, and bash does not then record a PASS). A search that could
    not finish (``engine:search_incomplete``) and a rule that was not evaluated before the file deadline (``engine:scan_incomplete``) are FAILs recorded
    by ``run_rules``; a file whose rules were not all evaluated is not also counted as passed."""
    outcome = ctx.run_rules(rules)
    ctx.finish(outcome.fired or outcome.incomplete)
    return True


def scan_docs(ctx: ScanContext) -> bool:
    """Scan a documentation or text file. Returns True after recording at least one event.

    ``dispatch.classify_file`` has already offered a file that starts with ``{\\rtf`` to the RTF scanner (and it is only here if that scanner did not
    take it), so there is no hand-off in this function."""
    return _scan(ctx, DOC_RULES)


def scan_json(ctx: ScanContext) -> bool:
    """Scan a ``.json`` file that is not a package manifest. Returns True after recording at least one event."""
    return _scan(ctx, JSON_RULES)


SCANNERS = (
    ScannerSpec(id="docs", family="docs", fn=scan_docs, bash_function="classify_file (.md|.txt|.rst arm)", ported=True),
    ScannerSpec(id="json", family="json", fn=scan_json, bash_function="classify_file (.json arm)", ported=True),
)
