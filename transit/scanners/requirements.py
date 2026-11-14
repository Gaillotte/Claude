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

Implementation notes (WP-10).
  * ``RULES`` is one table of five rows (ids ``manifest.requirements/NN-slug``), in bash order, which is also the order of the messages in a file's
    report entry; ``scan`` is ``ctx.finish(ctx.run_rules(RULES).fired or incomplete)``. ``fired`` stays true when the allowlist or ``--min-severity``
    turned a FAIL into a WARN (bash records no PASS then); ``incomplete`` is true when the engine recorded a FAIL for the file itself
    (``engine:scan_incomplete``, ``engine:regex_timeout``, ``engine:search_incomplete``), so such a file is not also counted as passed.
  * The fifth row is the ``excl`` rule. Its ``binary`` is ``text`` and whether a NUL byte blinds it is the ``SearchPolicy`` of the context
    (``excl_nul_blind``): D-029 is closed in bash (``grep_check_excl`` reads the file with ``-a``), so ``layers.search_policy`` passes False and the
    rule fires on a file that holds a NUL byte. Nothing in this module reads ``cfg.fix("D-029")``.
  * The rows are ``binary="text"`` (``grep -a``) while bash's ``grep_check``/``grep_check_i`` have no ``-a``: on a file holding a NUL byte bash reads
    the NUL as a line break, so (a) a ``^``-anchored row (1, 3 and 4) matches in bash a directive that follows a NUL on the same physical line, and
    not here (pip itself refuses such a line), and (b) the unanchored credential row (2) can find here a match that runs across the NUL, which bash
    cannot. ``test_requirements.NulTests`` pins both.
"""
from __future__ import annotations

from transit.rules import Match, RuleSet, RuleSpec
from transit.scanners import ScanContext, ScannerSpec

_SOURCE = "scan_requirements"

#: The five ``grep`` calls of ``scan_requirements``, in bash order. Patterns are the text bash hands to grep (tests/conformance/patterns.json, ids
#: ``scan_requirements:*``); ``ci=True`` is ``grep_check_i``, ``excl=`` is ``grep_check_excl`` (case-insensitive, one line at a time).
RULES: "RuleSet | None" = RuleSet("manifest.requirements", (
    # An index or a requirement over plaintext transport: whoever is on the path chooses the package, and pip then runs its setup. git:// is
    # unauthenticated.
    RuleSpec(id="manifest.requirements/01-plaintext-index-or-requirement", outcome="fail", source=_SOURCE,
             message="CWE-319:pip_index_or_requirement_over_plaintext",
             cond=Match(r"^[[:space:]]*((--index-url|-i|--extra-index-url|--find-links|-f)[[:space:]=]+http://|(-e[[:space:]]+)?(git\+http://|git://)|http://[^[:space:]]+\.(tar\.gz|tgz|zip|whl|tar\.bz2))",
                        ci=True)),
    # user:password@host inside a URL.
    RuleSpec(id="manifest.requirements/02-credentials-embedded-in-url", outcome="fail", source=_SOURCE,
             message="CWE-798:pip_credentials_embedded_in_url",
             cond=Match(r"(https?|git\+https?|ssh)://[^/[:space:]:@]+:[^/[:space:]@]+@")),
    RuleSpec(id="manifest.requirements/03-trusted-host", outcome="warn", source=_SOURCE,
             message="pip:trusted_host_disables_tls_verification",
             cond=Match(r"^[[:space:]]*--trusted-host", ci=True)),
    # A second index is the dependency-confusion vector: pip takes the highest version from ANY index, so a public package with the same name wins.
    RuleSpec(id="manifest.requirements/04-extra-index-url", outcome="warn", source=_SOURCE,
             message="pip:extra_index_url_enables_dependency_confusion",
             cond=Match(r"^[[:space:]]*--extra-index-url", ci=True)),
    # A VCS requirement not pinned to a commit follows a moving branch. A line that holds a 7 to 40 digit hex revision is excused whole.
    RuleSpec(id="manifest.requirements/05-vcs-not-pinned-to-a-commit", outcome="warn", source=_SOURCE,
             message="pip:vcs_requirement_not_pinned_to_a_commit",
             cond=Match(r"git\+(https|ssh)://", excl=r"@[0-9a-f]{7,40}([#[:space:]]|$)")),
))


def scan(ctx: ScanContext) -> bool:
    """Scan one requirements file. Returns True after recording at least one event."""
    outcome = ctx.run_rules(RULES)
    ctx.finish(outcome.fired or outcome.incomplete)         # bash: $failed || record_pass "$f"
    return True


SCANNERS = (ScannerSpec(id="manifest.requirements", family="manifest", fn=scan, bash_function="scan_requirements", ported=True),)
