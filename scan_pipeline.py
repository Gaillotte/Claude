#!/usr/bin/env python3
"""Python engine of the AI Transit Pipeline: not written yet.

The plan is docs/python_port_thin_plan.md: this file will mirror scan_pipeline.sh function by function and call the same
external tools. Until phase P1 lands it refuses to run, with no report and no sidecar, which every caller reads as FAIL.
"""
import sys

sys.stderr.write("[ERROR] the Python engine is not implemented yet; use the bash engine (TRANSIT_ENGINE=bash)\n")
sys.exit(1)
