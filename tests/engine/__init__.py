"""Unit tests of the Python engine, one file per module of ``transit/`` (docs/python_engine_design.md section 11).

    python3 -I -m unittest discover -s tests/engine            # the form the suite uses; no package import happens
    python3 -I -m unittest discover -s tests/engine -t .       # also valid; this file is then imported first

Plain ``unittest``, standard library only. ``-I`` removes the current directory from ``sys.path``, so EVERY test module starts with the same
three lines (copied from tests/conformance/test_rx.py) and does not depend on this file having run::

    ROOT = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(ROOT))
    from transit import ...
"""
import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parents[2])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
