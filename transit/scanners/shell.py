"""Shell scripts (bash ``scan_shell``): family ``shell``, scanner id ``shell``.

Routes here: ``.sh .bash .zsh .ksh``, and an extensionless file whose first line is exactly one of the shebangs of
``dispatch.SHEBANG_ROUTES`` (``#!/bin/bash`` yes, ``#!/bin/bash -e`` no: D-031).

Behaviour (bash order):
  1. ShellCheck. ``run = ctx.file_tool("shellcheck")``: ``missing`` -> ``record_warn("shellcheck missing")``; then
     ``fired = ctx.apply_tool_records(run)`` (a no-op for ``missing`` and ``not_ported``; otherwise the wrapper's records in order:
     ``shellcheck:warnings`` FAIL when ``shellcheck -S warning`` exits non-zero, or the WARN a ``failed`` run carries); a FAIL sets ``fired``.
  2. ``RULES``: FAIL CWE-78:remote_code_execution_curl_pipe_bash, FAIL CWE-88:eval_variable_injection, WARN CWE-426:PATH_starts_with_relative_directory,
     WARN CWE-377:predictable_temp_file_name, WARN shell:IFS_manipulation (patterns: tests/conformance/patterns.json ids ``scan_shell:*``).
  3. ``ctx.finish(fired)``.
Acceptance fixtures: tests/fixtures/clean/src/setup.sh (PASS with only ``shellcheck missing``), tests/fixtures/rules/*shell*.

Implementation notes (WP-09).
  * ``RULES`` has five rows (ids ``shell/01-curl-pipe-shell`` to ``shell/05-ifs-manipulation``), each one ``grep_check`` of ``scan_shell``:
    ``Match(pattern)`` with the defaults (``line``, ``text``, case-sensitive). The patterns are those of tests/conformance/patterns.json whose
    id starts with ``scan_shell:``. The first two are FAIL rows, the other three WARN rows, so a file with only those three still gets its PASS.
  * The order is bash's and is visible in a file's report entry: the tool (a ``shellcheck missing`` WARN, then the wrapper's records in order), then the
    five rows in table order. ``fired`` is the tool's FAIL or any FAIL row, whether or not the allowlist or ``--min-severity`` turned it into a
    WARN (``ALLOWED:`` / ``LOW_SEV(...)``): bash sets ``failed=true`` after ``record_fail`` regardless, so no PASS is recorded beside it.
  * A table that was not evaluated to the end (the per-file deadline passed between two rules, a search that could not finish) has already recorded
    its own non-downgradable ``engine:`` FAIL (``ScanContext.run_rules``); ``finish`` then records no PASS beside it either. bash has no such case.
  * ``shellcheck`` is a per-file tool (``tools.FILE_TOOLS``); a wrapper that raises is not a failed run: the exception reaches ``scanners.invoke``.
  * Routing is not decided here: ``dispatch`` (``.sh .bash .zsh .ksh``) and ``unknown`` (the shebang table, D-031) hand the file over.
  * A file with a NUL byte is still examined (E8). The rows read it as text (``grep -a``) where bash's ``grep_check`` has no ``-a`` and reads a NUL as
    a line end: a match that spans a NUL (``curl a<NUL>| sh``) is found here and not by bash. No shell row is anchored at the line start, so there is no
    match of bash's that is lost (tests/engine/test_shell.py, ``OracleTests``).
"""
from __future__ import annotations

from transit.rules import Match, RuleSet, RuleSpec
from transit.scanners import ScanContext, ScannerSpec

_SOURCE = "scan_shell"

#: The five ``grep_check`` calls of ``scan_shell``, in bash order (the order of a file's messages in the report). Every row is ``Match(pattern)`` with the
#: defaults: ``line`` mode, case-sensitive, ``binary="text"`` (see the module notes on a NUL byte). The bash patterns are copied with their weak spots
#: (``| shasum`` and ``| bashful`` are a pipe into a shell, a quoted absolute PATH starts with ``[^/]`` = the quote, ``OLDIFS=`` holds ``IFS=``).
RULES: "RuleSet | None" = RuleSet("shell", (
    # CWE-78: remote code execution by download and execute.
    RuleSpec(id="shell/01-curl-pipe-shell", outcome="fail", message="CWE-78:remote_code_execution_curl_pipe_bash", source=_SOURCE,
             cond=Match(r"curl\s+.*\|\s*(bash|sh)|wget\s+.*\|\s*(bash|sh)")),
    # CWE-88: eval with a variable (argument injection).
    RuleSpec(id="shell/02-eval-variable", outcome="fail", message="CWE-88:eval_variable_injection", source=_SOURCE,
             cond=Match(r"eval\s+\$")),
    # CWE-426: PATH hijacking (an unqualified directory first).
    RuleSpec(id="shell/03-path-relative-directory", outcome="warn", message="CWE-426:PATH_starts_with_relative_directory", source=_SOURCE,
             cond=Match(r"""export\s+PATH\s*=\s*['"]?[^/]""")),
    # CWE-377: a predictable temporary file name.
    RuleSpec(id="shell/04-predictable-temp-file", outcome="warn", message="CWE-377:predictable_temp_file_name", source=_SOURCE,
             cond=Match(r"/tmp/\$\$|/tmp/[a-z_]+[^/]*(tmp|temp)")),
    # IFS manipulation (a risk of word-splitting bypass).
    RuleSpec(id="shell/05-ifs-manipulation", outcome="warn", message="shell:IFS_manipulation", source=_SOURCE,
             cond=Match(r"""IFS\s*=\s*['"]?""")),
))


def scan(ctx: ScanContext) -> bool:
    """Scan one shell script. Returns True after recording at least one event."""
    run = ctx.file_tool("shellcheck")                    # bash: has_cmd shellcheck ... shellcheck -S warning "$f"
    if run.status == "missing":
        ctx.record_warn("shellcheck missing")            # recorded before everything else, as in bash (the file's first event)
    fired = ctx.apply_tool_records(run)                  # the wrapper's records in order, a failed run's WARN included; True after a FAIL
    outcome = ctx.run_rules(RULES)                       # the five grep_check calls, in table order
    # ``fired`` stays True after the allowlist or the threshold turned a FAIL into a WARN (bash ``failed=true``). A table that was not evaluated to the
    # end has recorded its engine FAIL already: no PASS is recorded beside it.
    ctx.finish(fired or outcome.fired or outcome.incomplete)
    return True


SCANNERS = (ScannerSpec(id="shell", family="shell", fn=scan, bash_function="scan_shell", tools=("shellcheck",), ported=True),)
