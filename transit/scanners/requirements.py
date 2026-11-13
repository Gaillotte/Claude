"""pip requirement files (bash ``scan_requirements``): family ``manifest``, scanner id ``manifest.requirements``.

Routes here by basename: ``requirements*.txt`` and ``constraints*.txt`` (case-sensitive, before the ``.txt`` extension arm). The other
scanner of the family, ``manifest.package_json`` (``package.json``, ``composer.json``), is a Phase 3 module that runs
``transit/scanners/manifests.py`` as a program; it does not share code with this file.

Rules (bash order; all ``binary="text"``; patterns are tests/conformance/patterns.json ids ``scan_requirements:*``)::

    FAIL  CWE-319:pip_index_or_requirement_over_plaintext     line_i
    FAIL  CWE-798:pip_credentials_embedded_in_url              line
    WARN  pip:trusted_host_disables_tls_verification           line_i
    WARN  pip:extra_index_url_enables_dependency_confusion     line_i
    WARN  pip:vcs_requirement_not_pinned_to_a_commit           excl  (``git\\+(https|ssh)://`` and not ``@[0-9a-f]{7,40}([#[:space:]]|$)``;
                                                                     the row says ``binary="text"``: bash's NUL blindness is applied by
                                                                     ``SearchPolicy.excl_nul_blind``, switch D-029)

then ``ctx.finish(fired)``. Acceptance fixture: tests/fixtures/clean/requirements.txt (``requests==2.32.3``: PASS, no message).
"""
from __future__ import annotations

from transit.rules import RuleSet
from transit.scanners import ScanContext, ScannerSpec

RULES: "RuleSet | None" = None


def scan(ctx: ScanContext) -> bool:
    """Scan one requirements file. Returns True after recording at least one event."""
    raise NotImplementedError


SCANNERS = (ScannerSpec(id="manifest.requirements", family="manifest", fn=scan, bash_function="scan_requirements", ported=False),)
