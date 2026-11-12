"""The run from ``argv`` to the exit status (bash: the top-level code of ``scan_pipeline.sh``).

Owner of: contract 3.2 (the last stdout line and the exit status), the order of the steps of a run, D-028 (an internal error
writes a FAIL, never a PASS), the signal behaviour (killed by a signal: no verdict, exit 128+n, temporary files removed), and
the process-wide invariant that exactly one ``Verdict`` exists.

Layering: the TOP of the graph; nothing imports ``pipeline`` except ``scan_pipeline.py``. It holds no logic of its own that a lower
module could hold: every step below is a call.

THE STEPS OF A RUN (docs/python_engine_design.md section 6 numbers them and cites the contract section each satisfies):
  1. ``cli.parse_args`` - refuse a bad command line (1.1-1.5); stderr message, exit 1, nothing written, WORK_DIR not created.
  2. ``config.load_config`` - environment (2); a ``ValueError`` (bad ``TRANSIT_FIXES``) is a refusal like step 1.
  3. ``Console`` - verbosity (2, 3.1); print the config notices (OFFLINE ignored, D-020).
  4. ``report.report_paths``, ``files.prepare_work_dirs`` - (2, 3.3, 3.4, D-027). An ``OSError`` here is an abort: print ``FAIL``, exit 1.
  5. ``files.TempArea`` - (3.5, S16); cleanup registered for ``finally``, ``atexit`` and the signal handlers.
  6. ``findings.parse_allowlist`` - ``.transit-allow.json`` (6.2, S15).
  7. ``files.load_exclusions``, ``files.load_diff_selection`` - (8.2-8.6).
  8. ``Verdict`` - the one run-state object (6.1, 7).
  9. ``files.files_for_scan`` - the list for layers 4 and 5 (8.5).
  10. ``layers.run_all`` - layers 1, 2, 3, then 4+5 per file, then 6 (7, 8.1, 8.8).
  11. ``files.compute_hashes`` - ``source.sha256``, ``repo_hash`` (4).
  12. ``report.build_report``, ``report.write_reports`` - JSON then HTML (3.4, 4, S3-S5).
  13. ``report.write_sidecars`` - ``.scan_verdict`` then ``.scan_report_json`` (3.3).
  14. ``Console.verdict`` then return 0 for PASS, 1 for FAIL (3.2). Nothing is written to stdout after the verdict.
D-028: any ``Exception`` after step 4 calls ``Verdict.abort``, then attempts steps 11-14 with the reports written if possible, and
in every case prints ``FAIL`` last and returns 1. If even that fails, ``FAIL`` is still printed and 1 returned. ``PASS`` can only
come out of step 14 of a run that finished.
"""
from __future__ import annotations

from typing import BinaryIO, Mapping, Sequence


def main(argv: Sequence[str], environ: "Mapping[str, str] | None" = None, *, out: "BinaryIO | None" = None,
         err: "BinaryIO | None" = None) -> int:
    """Run the engine. ``argv`` is ``sys.argv[1:]``; ``environ`` defaults to ``os.environ``; ``out``/``err`` default to the process's
    binary stdout/stderr (tests pass ``io.BytesIO``). Returns the exit status: 0 only for a completed PASS, 1 for FAIL, for a
    refused argument and for an internal error; 128+n when a signal ended the run (SIGTERM, SIGHUP, SIGINT are turned into an
    exception in the main thread so ``finally`` blocks run; SIGPIPE is ignored; SIGALRM is left to ``rx.time_limit``).
    Never raises (the one exception: ``SystemExit`` from the signal handler is converted to the return value)."""
    raise NotImplementedError
