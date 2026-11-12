"""Shell scripts (bash ``scan_shell``): family ``shell``, scanner id ``shell``.

Routes here: ``.sh .bash .zsh .ksh``, and an extensionless file whose first line is exactly one of the shebangs of
``dispatch.SHEBANG_ROUTES`` (``#!/bin/bash`` yes, ``#!/bin/bash -e`` no: D-031).

Behaviour (bash order):
  1. ShellCheck. ``ctx.file_tool("shellcheck")``: ``missing`` -> ``record_warn("shellcheck missing")``; ``not_ported`` -> nothing more;
     ``ok`` -> the wrapper's records (``shellcheck:warnings`` FAIL when ``shellcheck -S warning`` exits non-zero); a FAIL sets ``fired``.
  2. ``RULES``: FAIL CWE-78:remote_code_execution_curl_pipe_bash, FAIL CWE-88:eval_variable_injection, WARN CWE-426:PATH_starts_with_relative_directory,
     WARN CWE-377:predictable_temp_file_name, WARN shell:IFS_manipulation (patterns: tests/conformance/patterns.json ids ``scan_shell:*``).
  3. ``ctx.finish(fired)``.
Acceptance fixtures: tests/fixtures/clean/src/setup.sh (PASS with only ``shellcheck missing``), tests/fixtures/rules/*shell*.
"""
from __future__ import annotations

from transit.rules import RuleSet
from transit.scanners import ScanContext, ScannerSpec

RULES: "RuleSet | None" = None


def scan(ctx: ScanContext) -> bool:
    """Scan one shell script. Returns True after recording at least one event."""
    raise NotImplementedError


SCANNERS = (ScannerSpec(id="shell", family="shell", fn=scan, bash_function="scan_shell", tools=("shellcheck",), ported=False),)
