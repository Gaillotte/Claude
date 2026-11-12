#!/usr/bin/env python3
"""AI Transit Pipeline - Python engine entry point.

    python3 scan_pipeline.py <directory_to_scan> [directory_for_report] [scanning_name]

Same arguments, environment variables, output files, verdict and exit status as ``scan_pipeline.sh`` (docs/engine_contract.md).
``TRANSIT_ENGINE=python scan_pipeline.sh ...`` runs this file. Standard library only; Python 3.10 or newer.

This file does three things and nothing else: it refuses a Python that is too old with a message that can be read (importing the
package under 3.9 would die on a syntax error), puts its own directory first on ``sys.path`` (the launcher runs it with ``-I``,
which does not add the script directory), and calls ``transit.pipeline.main``.
"""
import os
import sys

if sys.version_info < (3, 10):  # keep in step with transit.config.MIN_PYTHON
    sys.stderr.write("[ERROR] Python 3.10 or newer is required (this is %d.%d)\n" % sys.version_info[:2])
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from transit.pipeline import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], os.environ))
