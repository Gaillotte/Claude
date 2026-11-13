"""Layer 4: the universal pattern rules that run on EVERY file before its own scanner (bash ``scan_universal_patterns``).

Owner of: contract 8.8 rule 1, the rule messages of CLAUDE.md "Traversal and key material in the universal layer (L4)" and of the
CWE-798 / CWE-321 / CWE-22 / CWE-918 / CWE-327 / CWE-338 / OWASP-A02 / OWASP-A09 / ``crypto:public_certificate_embedded`` rules.

Layering: depends on ``transit.scanners`` (ScanContext), ``transit.rules`` and ``transit.scanners.credentials``. NOT a registered
scanner: ``layers.run_file_layers`` calls ``scan`` through ``scanners.guard("universal", scan, ctx, requires_outcome=False)``.

Order (bash order, which fixes the order of messages in a file's report entry):
  1. CWE-798 ``hardcoded_credential`` (FAIL, ``line``);
  2. CWE-321 ``hardcoded_private_key`` (FAIL) - the header search with 5 lines of context, CR/LF/TAB folded to spaces, then the
     header + body test, see ``private_key_present`` (which does NOT call ``rx.after_context``, review log R-18);
  3. the known credential formats and the JWT warning (``credentials.check_known_credentials``);
  4. ``crypto:public_certificate_embedded`` (WARN);
  5. CWE-22 ``path_traversal_encoded``, ``path_traversal_to_sensitive_path``, ``path_traversal_composed_with_input`` (FAIL, ``line_i``);
  6. WARN: CWE-918 ``potential_SSRF_unvalidated_URL``, CWE-327 ``weak_crypto_algorithm``, CWE-338 ``weak_PRNG_for_security``,
     OWASP-A02 ``debug_or_backdoor_comment``, OWASP-A09 ``logging_suppressed``.
It never calls ``record_pass``: a file's PASS belongs to its type scanner. All rules run with ``binary="text"``: a file holding a NUL byte or invalid
UTF-8 is still examined (E8); only the credential-format rules skip it.

Each row of ``RULES`` is one ``RuleSpec`` (id ``universal/NN-slug``); the patterns are those of tests/conformance/patterns.json whose id
starts with ``scan_universal_patterns:``.
"""
from __future__ import annotations

from transit.rules import Matcher, RuleSet
from transit.scanners import ScanContext

#: The table of steps 1, 4, 5 and 6. Steps 2 and 3 are code. Built at import by the implementation (compiles through rx).
RULES: "RuleSet | None" = None

#: Step 2's two patterns as registered ``Matcher``s (ids ``universal/key-header`` and ``universal/key-body``), so the hostile-line test and
#: the fuzz gate cover them like any table row. ``None`` in the stub; built at import by the implementation.
KEY_HEADER: "Matcher | None" = None
KEY_WITH_BODY: "Matcher | None" = None

#: Step 2. Header pattern and header-then-body pattern, as bash passes them to ``grep -E -A5`` and the second ``grep -E``.
PRIVATE_KEY_HEADER = "-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----"
PRIVATE_KEY_WITH_BODY = "-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.{0,200}[A-Za-z0-9+/]{60,}"


def private_key_present(ctx: ScanContext, data: "bytes | None" = None) -> bool:
    """CWE-321 test, in bash a pipeline: ``grep -E -A5 HEADER | tr '\\r\\n\\t' '   ' | grep -E HEADER.{0,200}[A-Za-z0-9+/]{60,}``. A header with
    no base64 body within five lines (a file-type SIGNATURE, a documentation placeholder) is not a key.

    Algorithm (review log R-18). ``rx.after_context`` is NOT used: it searches the whole buffer with no budget (a line of 281 KB that repeats
    ``PRIVATE KEY `` took 6.7 s, 4x per doubling, about 35 minutes for 5 MB) and splits the buffer into a list of lines (about 19x the memory).
    Instead: for each line returned by ``ctx.spans(KEY_HEADER, data=data)`` (budgeted, or linear when the buffer has an over-long line; the
    generator never materialises the lines), take the WINDOW from the start of that line to the end of the fifth line after it (five
    ``data.find(b"\\n", ...)`` calls; fewer at the end of the data), fold CR, LF and TAB to spaces (``bytes.translate``), and test the folded
    window with ``ctx.search(KEY_WITH_BODY.match, data=window)`` (one line, so a window over ``long_line_bytes`` is searched linearly).
    Return True at the first window that matches; call ``ctx.check_deadline()`` once per window.

    Difference from bash, stated: bash concatenates the windows of neighbouring headers (with ``--`` between non-adjacent groups) and
    runs the second ``grep`` on the whole text, so a match that needs text from TWO groups (a header without a body followed by a hostile
    header line that itself contains 60 base64 characters before its ``PRIVATE KEY``) is a bash match and is not one here. Every real
    key (header, then a body line within five lines) is found, and nothing is found here that bash would not find. Cost: at most six
    times the bytes of the header lines."""
    raise NotImplementedError


def scan(ctx: ScanContext) -> bool:
    """Run steps 1 to 6 on ``ctx``'s file. Returns True. Records FAIL/WARN only; the clean file records nothing."""
    raise NotImplementedError
