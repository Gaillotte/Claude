#!/usr/bin/env python3
"""Run the bash engine and the Python engine on some fixtures and print what differs, file by file.

    python3 tests/conformance/family_diff.py 'tests/fixtures/rules/*.py' 'tests/fixtures/rules/safe.*'
    python3 tests/conformance/family_diff.py 'tests/fixtures/clean/**'
    python3 tests/conformance/family_diff.py                       # every file of tests/fixtures/rules
    python3 tests/conformance/family_diff.py --verbose 'tests/fixtures/rules/*.mk'

Globs are relative to the repository root. The files they match are copied into one temporary directory (a file keeps its path
below the part of its glob that has no wildcard, so `Makefile` and `composer.json` are still routed by basename and a
`.transit-allow.json` at the top of a fixture directory is still at the top), and both engines scan that directory with the same
environment. For every file the status, the messages (as a set) and the rule ids of its findings are compared; a difference is
printed, and so is the coverage block when it differs. `__global__` is not compared: it is the business of conformance.py.
A scanner the Python engine has not ported shows up as the WARN `python engine has not ported <scanner> yet`; the count of
differences that are only that is printed at the end. Exit status: 0 no difference, 1 differences, 2 usage error or an engine
that wrote no report. Standard library only.
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import conformance  # noqa: E402  (ENGINES, engine_env, normalize: an engine is run the way the harness runs it)

DEFAULT_GLOBS = ["tests/fixtures/rules/**"]
SKIP = {"__pycache__", ".DS_Store"}
NOT_PORTED = "[WARN] python engine has not ported "


def usage(message):
    sys.stderr.write("usage: %s\n" % _p(message))
    sys.exit(2)


def _p(text):
    """Repository text, made printable."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(text))


def _base(pattern):
    parts = []
    for part in pattern.split("/"):
        if re.search(r"[*?\[]", part):
            break
        parts.append(part)
    base = "/".join(parts)
    return base if os.path.isdir(ROOT / base) else os.path.dirname(base)


def collect(globs, dest):
    """Copy the files the globs match into dest. -> the number of files copied."""
    planned = {}
    for pattern in globs:
        base = _base(pattern)
        hits = glob.glob(pattern, root_dir=ROOT, recursive=True)
        if not hits:
            usage("no file matches %r" % pattern)
        for hit in sorted(hits):
            src = ROOT / hit
            files = [src] if src.is_file() else [p for p in sorted(src.rglob("*")) if p.is_file()]
            for p in files:
                if SKIP & set(p.parts):
                    continue
                rel = os.path.relpath(p, ROOT / base) if base else str(p.relative_to(ROOT))
                if rel in planned and planned[rel] != p:
                    usage("%s is matched by two different files" % rel)
                planned[rel] = p
    for rel, src in planned.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
    return len(planned)


def run_engine(engine, scan, base):
    work, reports = base / ("work_" + engine), base / ("reports_" + engine)
    work.mkdir()
    reports.mkdir()
    env = conformance.engine_env(engine, {}, work)
    proc = subprocess.run(conformance.ENGINES[engine] + [str(scan), str(reports), "fam"], env=env, capture_output=True, timeout=1800)
    found = sorted(reports.glob("report_scan_*.json"))
    if not found:
        sys.stderr.write("%s engine wrote no report (exit %d):\n%s\n" % (engine, proc.returncode, _p(proc.stderr.decode("utf-8", "replace")[-600:])))
        return None
    return conformance.normalize(json.loads(found[0].read_text(encoding="utf-8")), scan, work)


def per_file(report):
    ids = {}
    for rec in report["findings"]:
        ids.setdefault(rec["file"], set()).add(rec["rule_id"])
    return {path: (v["status"], set(v["messages"]), ids.get(path, set()))
            for path, v in report["file_results"].items() if path != "__global__"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("globs", nargs="*", help="globs relative to the repository root (default: tests/fixtures/rules/**)")
    ap.add_argument("--verbose", action="store_true", help="print both reports' entry for every file, not only the differing ones")
    args = ap.parse_args()
    base = Path(tempfile.mkdtemp(prefix="family_"))
    try:
        scan = base / "scan"
        scan.mkdir()
        count = collect(args.globs or DEFAULT_GLOBS, scan)
        reports = {e: run_engine(e, scan, base) for e in ("bash", "python")}
        if None in reports.values():
            return 2
        a, b = per_file(reports["bash"]), per_file(reports["python"])
        differ = unported = 0
        for path in sorted(set(a) | set(b)):
            ea, eb = a.get(path), b.get(path)
            if ea == eb and not args.verbose:
                continue
            if args.verbose:
                print("%s\n   bash   %s\n   python %s" % (_p(path), _p(ea), _p(eb)))
            if ea == eb:
                continue
            differ += 1
            if not args.verbose:
                print("DIFF %s" % _p(path))
            if ea is None or eb is None:
                print("   only in %s" % ("python" if ea is None else "bash"))
                continue
            if ea[0] != eb[0]:
                print("   status       bash=%s python=%s" % (ea[0], eb[0]))
            for label, only in (("bash", ea[1] - eb[1]), ("python", eb[1] - ea[1])):
                for m in sorted(only):
                    print("   only %-7s %s" % (label, _p(m)))
            for label, only in (("bash", ea[2] - eb[2]), ("python", eb[2] - ea[2])):
                for r in sorted(only):
                    print("   rule id only in %s: %s" % (label, _p(r)))
            if eb[1] - ea[1] and all(m.startswith(NOT_PORTED) for m in eb[1] - ea[1]):
                unported += 1
        ca, cb = reports["bash"]["coverage"], reports["python"]["coverage"]
        for layer in sorted(set(ca) | set(cb)):
            if ca.get(layer) != cb.get(layer):
                print("COVERAGE %s\n   bash   %s\n   python %s" % (layer, _p(ca.get(layer)), _p(cb.get(layer))))
        print("%d file(s) compared" % len(set(a) | set(b)))
        if not differ and ca == cb:
            print("no differences")
            return 0
        if unported:
            print("%d of the %d differing file(s) differ only because a scanner is not ported yet" % (unported, differ))
        return 1
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
