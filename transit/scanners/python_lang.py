"""Python source files (bash ``scan_python``): family ``python``, scanner id ``python``.

Routes here: ``.py`` (not ``setup.py``/``conanfile.py``, which go to ``setuppy``) and an extensionless file whose first line
matches ``#!*python*``. The module is named ``python_lang`` because ``python.py`` would be easy to confuse with the interpreter.

Behaviour (bash order, contract 5.1):
  1. Bandit. ``run = ctx.file_tool("bandit")``: ``missing`` -> ``record_warn("bandit missing")``; then ``fired = ctx.apply_tool_records(run)``
     (a no-op for ``missing`` and ``not_ported``, which is already noted; for ``ok`` and ``failed`` it records the wrapper's records in
     order: ``bandit:Severity: MEDIUM|HIGH:B<id>``, FAIL, the quirk that the space defeats the severity marker, A16, is copied: the severity
     is HIGH; and the WARN a ``failed`` run carries); a FAIL sets ``fired``.
  2. The rule table ``RULES`` (ids ``python/NN-slug``; patterns are tests/conformance/patterns.json ids ``scan_python:*``):
        FAIL  CWE-78:OS_command_injection_risk               a shell or process call (pattern: patterns.json scan_python:0c065ebc)
        FAIL  CWE-95:dynamic_code_execution_eval_exec         a dynamic-execution call            (scan_python:191a3086)
        FAIL  CWE-502:insecure_deserialization_pickle_yaml    pickle, marshal and yaml loading    (scan_python:6da7ee0a)
        FAIL  CWE-89:SQL_injection_query_built_by_string_interpolation   (scan_python:a01d004d)
        WARN  CWE-601:potential_open_redirect                                                    (scan_python:62aea149)
        FAIL  CWE-703:assert_used_for_security_check                                             (scan_python:de1efe6a)
     (Three alternatives are dead in bash - ``\\b`` after ``)`` can never match - and are copied: PYTHON_PORT_PLAN status block.)
  3. ``ctx.finish(fired)``: ``record_pass`` unless a FAIL rule fired (even one that the allowlist or ``--min-severity`` turned into a WARN).
Acceptance fixtures: tests/fixtures/rules/*python*, tests/fixtures/clean/src/app.py (PASS with only ``bandit missing``).

Implementation notes (WP-09).
  * ``RULES`` has six rows (ids ``python/01-os-command-injection`` to ``python/06-assert-security-check``), each one ``grep_check`` of ``scan_python``:
    ``Match(pattern)`` with the defaults (``line``, ``text``, case-sensitive). The patterns are those of tests/conformance/patterns.json whose
    id starts with ``scan_python:`` and whose helper is ``grep_check``; Bandit's own two ``grep`` calls on its output belong to the wrapper (WP-3G).
  * The order is bash's and is visible in a file's report entry: the tool (a ``bandit missing`` WARN, then the wrapper's records in order), then the
    six rows in table order. ``fired`` is the tool's FAIL or any FAIL row, whether or not the allowlist or ``--min-severity`` turned it into a
    WARN (``ALLOWED:`` / ``LOW_SEV(...)``): bash sets ``failed=true`` after ``record_fail`` regardless, so no PASS is recorded beside it.
  * A table that was not evaluated to the end (the per-file deadline passed between two rules, a search that could not finish) has already recorded
    its own non-downgradable ``engine:`` FAIL (``ScanContext.run_rules``); ``finish`` then records no PASS beside it either. bash has no such case.
  * ``bandit`` is a per-file tool (``tools.FILE_TOOLS``); a wrapper that raises is not a failed run: the exception reaches ``scanners.invoke``.
  * A file with a NUL byte is still examined (E8). The rows read it as text (``grep -a``) where bash's ``grep_check`` has no ``-a`` and reads a NUL as
    a line end: a match that spans a NUL is found here and not by bash, and the line-anchored ``assert`` row is found by bash after a NUL and not here
    (tests/engine/test_python_lang.py, ``OracleTests``, pins both). A Python source file cannot hold a NUL byte, so no running program is hidden.
"""
from __future__ import annotations

from transit.rules import Match, RuleSet, RuleSpec
from transit.scanners import ScanContext, ScannerSpec

_SOURCE = "scan_python"

#: The six ``grep_check`` calls of ``scan_python``, in bash order (the order of a file's messages in the report). Every row is ``Match(pattern)`` with the
#: defaults: ``line`` mode, case-sensitive, ``binary="text"`` (see the module notes on a NUL byte). One alternative is nearly dead in bash and is
#: copied: ``yaml.load(x)`` ends in ``\b`` after ``)``, so it matches only when a word character follows the closing parenthesis.
RULES: "RuleSet | None" = RuleSet("python", (
    # CWE-78: a shell or process call.
    RuleSpec(id="python/01-os-command-injection", outcome="fail", message="CWE-78:OS_command_injection_risk", source=_SOURCE,
             cond=Match(r"\b(os\.system|subprocess\.call|subprocess\.Popen|commands\.getoutput)\s*\(")),
    # CWE-95 / CWE-78: a dynamic-execution call.
    RuleSpec(id="python/02-dynamic-code-execution", outcome="fail", message="CWE-95:dynamic_code_execution_eval_exec", source=_SOURCE,
             cond=Match(r"\b(eval|exec)\s*\(")),
    # CWE-502: pickle, marshal and yaml loading.
    RuleSpec(id="python/03-insecure-deserialization", outcome="fail", message="CWE-502:insecure_deserialization_pickle_yaml", source=_SOURCE,
             cond=Match(r"\b(pickle\.loads|pickle\.load|marshal\.loads|yaml\.load\s*\([^,)]+\))\b")),
    # CWE-89: an f-string, a concatenation, a %-format or a .format() built into the query. The parameterised form execute("... = ?", (v,)) is not flagged.
    RuleSpec(id="python/04-sql-injection-built-query", outcome="fail", message="CWE-89:SQL_injection_query_built_by_string_interpolation", source=_SOURCE,
             cond=Match(r"""(execute|executemany)[[:space:]]*\([[:space:]]*(f["']|("[^"]*"|'[^']*')[[:space:]]*(\+|%|\.format\())""")),
    # CWE-601: reported, not blocked.
    RuleSpec(id="python/05-open-redirect", outcome="warn", message="CWE-601:potential_open_redirect", source=_SOURCE,
             cond=Match(r"(redirect|HttpResponseRedirect)\s*\(\s*request\.")),
    # CWE-703: an assert is stripped in an optimised build.
    RuleSpec(id="python/06-assert-security-check", outcome="fail", message="CWE-703:assert_used_for_security_check", source=_SOURCE,
             cond=Match(r"^\s*assert\s+(is_admin|is_authenticated|has_perm|user\.is)")),
))


def scan(ctx: ScanContext) -> bool:
    """Scan one Python file. Returns True after recording at least one event. See the module docstring."""
    run = ctx.file_tool("bandit")                        # bash: has_cmd bandit ... bandit -q -l -i "$f"
    if run.status == "missing":
        ctx.record_warn("bandit missing")                # recorded before everything else, as in bash (the file's first event)
    fired = ctx.apply_tool_records(run)                  # the wrapper's records in order, a failed run's WARN included; True after a FAIL
    outcome = ctx.run_rules(RULES)                       # the six grep_check calls, in table order
    # ``fired`` stays True after the allowlist or the threshold turned a FAIL into a WARN (bash ``failed=true``). A table that was not evaluated to the
    # end has recorded its engine FAIL already: no PASS is recorded beside it.
    ctx.finish(fired or outcome.fired or outcome.incomplete)
    return True


SCANNERS = (ScannerSpec(id="python", family="python", fn=scan, bash_function="scan_python", tools=("bandit",), ported=True),)
