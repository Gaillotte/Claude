"""Files with no recognised extension or name (bash ``scan_unknown``): pseudo scanner id ``unknown`` (not one of the 34 families).

Behaviour, in bash order:
  1. Shebang routing. ``first = ctx.view.first_line()``; ``dispatch.shebang_scanner(first)`` names a scanner (python, shell, ruby, js, php,
     powershell.text): ``return ctx.delegate(that_id)``. (``#!/bin/bash -e`` is NOT routed, D-031; with that switch it is.)
  2. MIME check. ``ctx.file_tool("file")`` runs ``file --mime-type -b``: a type that starts with ``application/x-executable``,
     ``application/x-sharedlib`` or ``application/x-dosexec`` -> FAIL ``binary:unexpected_executable_mime:<mime>``, return True.
     ``missing`` (no ``file(1)``): bash passes the file silently (A22, D-022); here ``ctx.note_incomplete("file(1) is not installed: executable detection by MIME type
     was skipped")`` (a ``partial`` coverage note, visible, no per-file message) and the file is PASS. ``not_ported``: already noted; PASS.
  3. Otherwise ``record_pass``.
Acceptance: golden ``rules_corpus`` unknown-extension fixtures; a file with ``#!/usr/bin/env python3`` and no extension is scanned by ``python``.
"""
from __future__ import annotations

from transit.scanners import ScanContext, ScannerSpec


def scan(ctx: ScanContext) -> bool:
    """Scan one file of unknown type. Returns True after recording at least one event."""
    raise NotImplementedError


SCANNERS = (ScannerSpec(id="unknown", family="unknown", fn=scan, bash_function="scan_unknown", tools=("file",), ported=False),)
