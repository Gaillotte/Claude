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

Implementation notes (WP-08).
  * ``RULES`` has ten rows (steps 1, 4, 5 and 6: 1 + 1 + 3 + 5). The other grep calls of the bash function are the two ``Matcher``s of step 2 and
    the 20 of ``credentials`` (the alternation, 18 providers, the JWT).
  * The bash order puts steps 2 and 3 between row 1 and the other nine, and ``ScanContext.run_rules`` evaluates and records a whole table at once,
    so ``scan`` applies the rows itself, one ``ctx.search`` and one ``record_*`` each, in two slices; the messages of a file keep bash's order.
  * Rows are ``binary="text"`` (``grep -a``) while bash's ``grep_check`` has no ``-a``. On a file with a NUL byte that finds a match which
    spans the NUL (``password = "ab<NUL>cdef"``) where bash, which turns the NUL into a line end, does not; never the other way round.
    The key test is ``grep -aE`` in bash too, so it is equal."""
from __future__ import annotations

from transit.rules import Match, Matcher, RuleSet, RuleSpec
from transit.scanners import ScanContext
from transit.scanners.credentials import check_known_credentials

#: Step 2. Header pattern and header-then-body pattern, as bash passes them to ``grep -E -A5`` and the second ``grep -E``.
PRIVATE_KEY_HEADER = "-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----"
PRIVATE_KEY_WITH_BODY = "-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.{0,200}[A-Za-z0-9+/]{60,}"

#: Step 2's two patterns as registered ``Matcher``s (ids ``universal/key-header`` and ``universal/key-body``), so the hostile-line test and
#: the fuzz gate cover them like any table row. Both read the file as text (bash ``grep -aE``): a NUL byte changes nothing.
KEY_HEADER: "Matcher | None" = Matcher("universal/key-header", Match(PRIVATE_KEY_HEADER))
KEY_WITH_BODY: "Matcher | None" = Matcher("universal/key-body", Match(PRIVATE_KEY_WITH_BODY))

_SOURCE = "scan_universal_patterns"

#: The table of steps 1, 4, 5 and 6, in bash order (the order of the grep calls of ``scan_universal_patterns``). Steps 2 and 3 are code.
#: The ten rows are ``grep_check`` (``Match``) and ``grep_check_i`` (``Match(ci=True)``) calls: ``binary="text"``, so a NUL byte or invalid
#: UTF-8 changes nothing (E8; bash's ``grep_check`` has no ``-a``, see the module notes on the one consequence).
RULES: "RuleSet | None" = RuleSet("universal", (
    # 1. CWE-798 / CWE-259. The value class is [:space:], not \s: inside a bracket expression \s is the characters \ and s.
    RuleSpec(id="universal/01-hardcoded-credential", outcome="fail", message="CWE-798:hardcoded_credential", source=_SOURCE,
             cond=Match(r"""(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["'][^${"'[:space:]]{4,}""")),
    # 4. Reported, not blocked: a certificate is the public half of the pair.
    RuleSpec(id="universal/02-public-certificate", outcome="warn", message="crypto:public_certificate_embedded", source=_SOURCE,
             cond=Match("-----BEGIN CERTIFICATE-----")),
    # 5. CWE-22. A literal "../" is a relative path, not an attack: only these three contexts are findings.
    RuleSpec(id="universal/03-path-traversal-encoded", outcome="fail", message="CWE-22:path_traversal_encoded", source=_SOURCE,
             cond=Match(r"(%2e%2e|%252e%252e|\.\.%2f|\.\.%5c|%2f\.\.|%5c\.\.)", ci=True)),
    RuleSpec(id="universal/04-path-traversal-sensitive-path", outcome="fail", message="CWE-22:path_traversal_to_sensitive_path", source=_SOURCE,
             cond=Match(r"""\.\.[/\\][^[:space:]"'`]*((etc/)?(passwd|shadow)|\.ssh/|\.aws/|id_rsa|system32|proc/self)""", ci=True)),
    RuleSpec(id="universal/05-path-traversal-composed", outcome="fail", message="CWE-22:path_traversal_composed_with_input", source=_SOURCE,
             cond=Match(r"""(["'`]\.\.[/\\]["'`][[:space:]]*[+.][[:space:]]*|[+.][[:space:]]*["'`]/?\.\.[/\\]|f["'][^"']*(\{[^}]*\}[^"']*\.\.[/\\]|\.\.[/\\][^"']*\{[^}]*\})|`[^`]*(\$\{[^}]*\}[^`]*\.\.[/\\]|\.\.[/\\][^`]*\$\{))""",
                        ci=True)),
    # 6. WARN rules.
    RuleSpec(id="universal/06-ssrf", outcome="warn", message="CWE-918:potential_SSRF_unvalidated_URL", source=_SOURCE,
             cond=Match(r"(requests\.get|urllib\.request|fetch|axios|http\.get)\s*\([^)]*\b(url|host|endpoint|target)\b")),
    RuleSpec(id="universal/07-weak-crypto", outcome="warn", message="CWE-327:weak_crypto_algorithm", source=_SOURCE,
             cond=Match(r"\b(md5|sha1|des|rc4|blowfish)\b")),
    RuleSpec(id="universal/08-weak-prng", outcome="warn", message="CWE-338:weak_PRNG_for_security", source=_SOURCE,
             cond=Match(r"\b(Math\.random|random\.random|rand\(\)|mt_rand)\b")),
    RuleSpec(id="universal/09-debug-or-backdoor-comment", outcome="warn", message="OWASP-A02:debug_or_backdoor_comment", source=_SOURCE,
             cond=Match(r"(TODO.*remove|FIXME.*auth|backdoor|test.*password|debug.*token|hardcoded.*key)")),
    RuleSpec(id="universal/10-logging-suppressed", outcome="warn", message="OWASP-A09:logging_suppressed", source=_SOURCE,
             cond=Match(r"(logging\.disable|log_level.*NOTSET|setLevel.*CRITICAL.*security|disableStdoutLogger)")),
))

#: Bash records step 1, then 2 and 3, then 4 to 6: the order of the messages of one file in the report. ``RULES`` is one table, so it is run
#: in these two slices (a ``RuleSet`` is evaluated as a whole by ``ScanContext.run_rules``; here each row is one ``ctx.search``).
_FIRST_ROWS = RULES.rules[:1]
_LATER_ROWS = RULES.rules[1:]

_KEY_MESSAGE = "CWE-321:hardcoded_private_key"
#: ``grep -A5``: five lines after each header line.
_CONTEXT_LINES = 5
#: ``tr '\r\n\t' '   '``.
_FOLD = bytes.maketrans(b"\r\n\t", b"   ")


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
    raw = ctx.view.data() if data is None else data
    size = len(raw)
    for start, end in ctx.spans(KEY_HEADER, data=data):
        ctx.check_deadline()
        stop = end                                       # the LF that ends the header line (or the end of the data)
        for _ in range(_CONTEXT_LINES):
            if stop >= size:
                break
            following = raw.find(b"\n", stop + 1)
            stop = size if following < 0 else following
        if ctx.search(KEY_WITH_BODY.match, data=raw[start:stop].translate(_FOLD)):
            return True
    return False


def scan(ctx: ScanContext) -> bool:
    """Run steps 1 to 6 on ``ctx``'s file. Returns True. Records FAIL/WARN only; the clean file records nothing."""
    for spec in _FIRST_ROWS:                             # 1. CWE-798 hardcoded_credential
        _apply(ctx, spec)
    if private_key_present(ctx):                         # 2. CWE-321 hardcoded_private_key
        ctx.record_fail(_KEY_MESSAGE)
    check_known_credentials(ctx)                         # 3. the 18 provider formats, then the JWT warning
    for spec in _LATER_ROWS:                             # 4. certificate, 5. CWE-22 (three rules), 6. the WARN rules
        _apply(ctx, spec)
    return True                                          # never record_pass: a file's PASS belongs to its type scanner


def _apply(ctx: ScanContext, spec: RuleSpec) -> None:
    """One row of ``RULES``: bash ``if grep_check ...; then record_fail|record_warn; fi``."""
    if ctx.search(spec.cond):
        if spec.outcome == "fail":
            ctx.record_fail(spec.message, severity=spec.severity)
        else:
            ctx.record_warn(spec.message)
