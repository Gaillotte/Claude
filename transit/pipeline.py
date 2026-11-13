"""The run from ``argv`` to the exit status (bash: the top-level code of ``scan_pipeline.sh``).

Owner of: contract 3.2 (the last stdout line and the exit status), the order of the steps of a run, D-028 (an internal error
writes a FAIL, never a PASS), the signal behaviour (killed by a signal: no verdict, exit 128+n, temporary files removed), the removal of
stale sidecars (D-040), and the process-wide invariant that exactly one ``Verdict`` exists.

Layering: the TOP of the graph; nothing imports ``pipeline`` except ``scan_pipeline.py``. It holds no logic of its own that a lower
module could hold: every step below is a call.

THE STEPS OF A RUN (docs/python_engine_design.md section 6 numbers them and cites the contract section each satisfies):
  1. signals - SIGTERM, SIGHUP and SIGINT raise the private ``_Terminated(BaseException)`` carrying the signal number; SIGPIPE is ignored.
  2. ``cli.parse_args`` - refuse a bad command line (1.1-1.5); stderr message, exit 1, nothing written, WORK_DIR not created.
  3. ``config.load_config`` - environment (2); a ``ValueError`` (bad ``TRANSIT_FIXES``) is a refusal like step 2. Then the ``Console``
     (verbosity, 2 and 3.1) and the config notices (OFFLINE ignored, D-020).
  4. ``report.report_paths``, ``files.prepare_work_dirs`` - (2, 3.3, 3.4, D-027). An ``OSError`` here is an abort BEFORE a verdict can
     be written: one ``Console.error`` line, exit 1, NO verdict line (contract 3.2 "Aborted after validation").
  5. Remove ``.scan_verdict`` and ``.scan_report_json`` (D-040: a stale PASS from an earlier run must not survive any exit that does not
     reach step 14; if one cannot be removed it is overwritten with ``FAIL``, and if that fails too the run aborts as in step 4), then
     construct the ONE ``Verdict`` with an empty allowlist. FROM HERE ON every ``Exception`` and every ``BaseException`` other than the
     signal exception is an internal error (D-028).
  6. ``files.TempArea`` - (3.5, S16); cleanup registered for ``finally``, ``atexit`` and the signal path.
  7. ``findings.parse_allowlist`` (which never raises) and ``Verdict.set_allowlist`` - ``.transit-allow.json`` (6.2, S15).
  8. ``files.load_exclusions``, ``files.load_diff_selection`` - (8.2-8.6); the WARN ``transitignore:exclusions_applied(<n> pattern(s))`` on
     ``__global__`` when there is at least one pattern (D-004, unconditional); the WARN ``engine:diff_entries_unresolved(<n>)`` and the
     ``partial`` notes when ``DiffSelection.unresolved`` is non-zero (D-042).
  9. ``RunEnv`` (locator, wrappers, registry) and the info lines ``Starting scan`` and ``Standards``.
 10. ``files.files_for_scan`` - the list for layers 4 and 5 (8.5).
 11. ``layers.run_all`` - layers 1, 2, 3, then 4+5 per file, then 6 (7, 8.1, 8.8).
 12. ``files.compute_hashes`` - ``source.sha256``, ``repo_hash`` (4).
 13. ``report.build_report``, ``report.write_reports`` - JSON then HTML (3.4, 4, S3-S5).
 14. ``report.write_sidecars`` - ``.scan_verdict`` then ``.scan_report_json`` (3.3).
 15. ``Console.verdict`` then return 0 for PASS, 1 for FAIL (3.2). Nothing is written to stdout after the verdict.
D-028 (steps 6 to 14): any ``Exception``, and any ``BaseException`` that is not the signal exception (``SystemExit`` included: a stray
``sys.exit(0)`` must never turn into exit status 0), calls ``Verdict.abort``, then attempts steps 12-14 with the reports written if
possible, and in every case prints ``FAIL`` last and returns 1. If even that fails, ``FAIL`` is still printed and 1 returned. The exit
status is computed from one fact: it is 0 only if ``Console.verdict("PASS")`` was actually written by step 15 of a run that finished.
``PASS`` can only come out of step 15.
"""
from __future__ import annotations

from typing import BinaryIO, Mapping, Sequence


def main(argv: Sequence[str], environ: "Mapping[str, str] | None" = None, *, out: "BinaryIO | None" = None,
         err: "BinaryIO | None" = None) -> int:
    """Run the engine. ``argv`` is ``sys.argv[1:]``; ``environ`` defaults to ``os.environ``; ``out``/``err`` default to the process's
    binary stdout/stderr (tests pass ``io.BytesIO``). Returns the exit status: 0 only for a completed PASS, 1 for FAIL, for a
    refused argument, for an abort after validation (step 4) and for an internal error; 128+n when a signal ended the run (SIGTERM,
    SIGHUP, SIGINT are turned into the private ``_Terminated`` exception in the main thread so ``finally`` blocks run, and ``main``
    converts it to the return value; SIGPIPE is ignored; SIGALRM is left to ``rx.time_limit``).

    Never raises. ``SystemExit`` is NOT a way out: it is caught as an internal error (a scanner's is already contained per file by
    ``scanners.invoke``), because ``Exception`` does not catch it and an uncaught ``SystemExit(0)`` ends the process with status 0 and no
    verdict line, which contract 3.2 and every status-only caller read as PASS (review log R-06). The handlers installed by step 1 are
    restored on exit, so a second ``main`` call in the same process (the tests) starts clean."""
    raise NotImplementedError
