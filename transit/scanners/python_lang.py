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
"""
from __future__ import annotations

from transit.rules import RuleSet
from transit.scanners import ScanContext, ScannerSpec

#: Built at import by the implementation; ``None`` in the stub.
RULES: "RuleSet | None" = None


def scan(ctx: ScanContext) -> bool:
    """Scan one Python file. Returns True after recording at least one event. See the module docstring."""
    raise NotImplementedError


SCANNERS = (ScannerSpec(id="python", family="python", fn=scan, bash_function="scan_python", tools=("bandit",), ported=False),)
