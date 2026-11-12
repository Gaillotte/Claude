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
"""
from __future__ import annotations

from transit.rules import RuleSet
from transit.scanners import ScanContext, ScannerSpec

DOC_RULES: "RuleSet | None" = None
JSON_RULES: "RuleSet | None" = None


def scan_docs(ctx: ScanContext) -> bool:
    """Scan a documentation or text file. Returns True after recording at least one event."""
    raise NotImplementedError


def scan_json(ctx: ScanContext) -> bool:
    """Scan a ``.json`` file that is not a package manifest. Returns True after recording at least one event."""
    raise NotImplementedError


SCANNERS = (
    ScannerSpec(id="docs", family="docs", fn=scan_docs, bash_function="classify_file (.md|.txt|.rst arm)", ported=False),
    ScannerSpec(id="json", family="json", fn=scan_json, bash_function="classify_file (.json arm)", ported=False),
)
