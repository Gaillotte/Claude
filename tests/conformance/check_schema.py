#!/usr/bin/env python3
"""Validate the raw JSON report of an engine against docs/report.schema.json.

    python3 -I tests/conformance/check_schema.py                  # self-test, then run the bash engine on 3 fixtures
    python3 -I tests/conformance/check_schema.py --engine python  # the same with scan_pipeline.py (once it exists)
    python3 -I tests/conformance/check_schema.py --report FILE    # validate one report that already exists
    python3 -I tests/conformance/check_schema.py --self-test      # only prove that the validator can reject

What it does
  1. Self-test: a valid sample report must pass, and every one of ~30 deliberate mutations (a removed key, a wrong
     type, a value outside an enum, a negative counter, an extra key, a broken invariant ...) must be rejected.
     A validator that has never been seen to fail proves nothing.
  2. For each of tests/fixtures/clean, vulnerable and allowlisted (copied to a temporary directory without
     __pycache__), run the engine with the three-argument usage and WORK_DIR in a temporary directory, then check
     the exit status, the last stdout line, the sidecars, the HTML report, and the JSON report against the schema
     and against the invariants that JSON Schema cannot express (docs/engine_contract.md section 4).
  3. A last check refuses an invalid scanning_name: exit status 1, no report, no sidecar.

The validator understands exactly the keywords docs/report.schema.json uses and nothing else: type (a name or a list
of names), properties, required, additionalProperties (a boolean or a schema), items, enum, pattern, minimum.
Annotation keywords are ignored. Any other keyword raises SchemaError, so the schema cannot quietly start relying on
something this file does not check. Standard library only, Python 3.10+. Exits 0 when everything holds, 1 otherwise.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "docs" / "report.schema.json"
FIXTURES = ROOT / "tests" / "fixtures"

ENGINES = {
    "bash": ["bash", str(ROOT / "scan_pipeline.sh")],
    "python": [sys.executable, str(ROOT / "scan_pipeline.py")],
}

# Fixture, scanning name, expected verdict and exit status (the reference environment has none of the external
# scanning tools; none of the three depends on one for its verdict).
CASES = [
    ("clean", "schema_clean", "PASS", 0),
    ("vulnerable", "schema_vulnerable", "FAIL", 1),
    ("allowlisted", "schema_allowlisted", "PASS", 0),
]

# Environment variables that change what an engine does. They are removed so that the run does not depend on the
# shell this is started from.
SCRUB = ["MIN_SEVERITY", "SINCE_COMMIT", "RUN_SCA", "RUN_SCANCODE", "OFFLINE", "VERBOSITY", "REPO_INPUT",
         "OFFLINE_CACHE", "SEMGREP_RULES_DIR", "TRIVY_CACHE_DIR", "CLAMAV_DB_DIR"]

# DEFAULT_EXCLUDE_DIRS of scan_pipeline.sh. The bash engine prunes any path that has one of these as a component,
# including the components ABOVE the scanned directory, so a scan under /tmp/build/x finds nothing and passes
# (docs/engine_contract.md section 11). The temporary directory used here must not contain one.
EXCLUDED_COMPONENTS = {"node_modules", ".git", "vendor", ".tox", "__pycache__", ".venv", "venv", "dist", "build",
                       ".next", ".nuxt", ".cache", "target", "coverage"}


# ── a validator for exactly the subset docs/report.schema.json uses ──────────────────────────────────────────────

class SchemaError(Exception):
    """The schema itself uses something this validator does not implement, or is malformed."""


SUPPORTED = {"type", "properties", "required", "additionalProperties", "items", "enum", "pattern", "minimum"}
ANNOTATIONS = {"$schema", "$id", "$comment", "title", "description"}


def _is_type(value, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "integer":          # bool is an int in Python and is not an integer in JSON
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise SchemaError("unknown type name %r" % name)


def _same(a, b) -> bool:
    """Equality for enum: True must not equal 1."""
    return type(a) is type(b) and a == b


def validate(instance, schema, path: str = "$") -> list[str]:
    """Return a list of readable violations, empty when the instance conforms."""
    if not isinstance(schema, dict):
        raise SchemaError("%s: a schema must be an object, got %s" % (path, type(schema).__name__))
    for key in schema:
        if key not in SUPPORTED and key not in ANNOTATIONS:
            raise SchemaError("%s: keyword %r is not in the supported subset %s"
                              % (path, key, sorted(SUPPORTED)))
    errors: list[str] = []

    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(instance, n) for n in names):
            errors.append("%s: expected %s, got %s (%s)" % (path, " or ".join(names), type(instance).__name__,
                                                            _short(instance)))
            return errors          # the keywords below assume the right type

    if "enum" in schema and not any(_same(instance, v) for v in schema["enum"]):
        errors.append("%s: %s is not one of %s" % (path, _short(instance), schema["enum"]))

    if "pattern" in schema and isinstance(instance, str):
        if not re.search(schema["pattern"], instance):
            errors.append("%s: %s does not match %s" % (path, _short(instance), schema["pattern"]))

    if "minimum" in schema and isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if instance < schema["minimum"]:
            errors.append("%s: %s is below the minimum %s" % (path, instance, schema["minimum"]))

    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in instance:
                errors.append("%s: required key %r is missing" % (path, name))
        for name, value in instance.items():
            sub = "%s.%s" % (path, name)
            if name in props:
                errors.extend(validate(value, props[name], sub))
            elif "additionalProperties" in schema:
                extra = schema["additionalProperties"]
                if extra is False:
                    errors.append("%s: unexpected key %r" % (path, name))
                elif extra is True:
                    pass
                else:
                    errors.extend(validate(value, extra, sub))

    if isinstance(instance, list) and "items" in schema:
        for i, value in enumerate(instance):
            errors.extend(validate(value, schema["items"], "%s[%d]" % (path, i)))

    return errors


def _short(value, limit: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ── invariants JSON Schema (in this subset) cannot express ───────────────────────────────────────────────────────

def check_invariants(report: dict) -> list[str]:
    """Cross-field rules of docs/engine_contract.md section 4. Assumes the schema check already passed."""
    errors: list[str] = []
    verdict = report["verdict"]
    if report["decision"] != ("APPROVED" if verdict == "PASS" else "REJECTED"):
        errors.append("decision %r does not follow verdict %r" % (report["decision"], verdict))
    colours = ("#198754", "#D1E7DD") if verdict == "PASS" else ("#B02A37", "#F8D7DA")
    if (report["status_color"], report["status_background"]) != colours:
        errors.append("status_color/status_background do not match verdict %s" % verdict)

    gaps = sorted(k for k, v in report["coverage"].items() if not v.startswith("ran"))
    if report["coverage_gaps"] != gaps:
        errors.append("coverage_gaps %s differs from the layers that did not run %s" % (report["coverage_gaps"], gaps))
    if report["coverage_complete"] != (not gaps):
        errors.append("coverage_complete is %r but %d layer(s) did not run" % (report["coverage_complete"], len(gaps)))

    if report["directory"] != report["source"]["directory"]:
        errors.append("directory and source.directory differ")
    if report["summary"]["fail"] != len(report["findings"]):
        errors.append("summary.fail is %d but there are %d finding records"
                      % (report["summary"]["fail"], len(report["findings"])))

    fr = report["file_results"]
    if verdict == "PASS":
        if report["findings"] or report["findings_by_file"]:
            errors.append("verdict is PASS but findings are present")
        for k, v in fr.items():
            if v["status"] == "FAIL":
                errors.append("verdict is PASS but %r has status FAIL" % k)
    elif not any(v["status"] == "FAIL" for v in fr.values()):
        # The bash engine can reach this state (a ScanCode finding that was allowlisted still fails the verdict).
        # Not an error for the schema, but worth saying, so it is only reported when asked for. See section 11.
        pass

    d = report["directory"]
    for k, v in fr.items():
        if k != "__global__" and k != d and not k.startswith(d + "/"):
            errors.append("file_results key %r is neither __global__, the directory, nor under it" % k)
        if v["status"] == "FAIL" and "[FAIL]" not in v["message"]:
            errors.append("%r has status FAIL but no [FAIL] message" % k)
        if v["status"] == "WARN" and "[WARN]" not in v["message"]:
            errors.append("%r has status WARN but no [WARN] message" % k)
    for k in report["findings_by_file"]:
        if k not in fr or fr[k]["status"] != "FAIL":
            errors.append("findings_by_file key %r is not a file with status FAIL" % k)
    for i, rec in enumerate(report["findings"]):
        key = d if rec["file"] == "." else d + "/" + rec["file"]
        if rec["message"] not in report["findings_by_file"].get(key, ""):
            errors.append("findings[%d].message is not in findings_by_file[%r]" % (i, key))
    return errors


def check_report(report, schema) -> list[str]:
    errors = validate(report, schema)
    if errors:
        return errors            # the invariants assume a conforming document
    return check_invariants(report)


# ── self-test: the validator has to be seen to fail ──────────────────────────────────────────────────────────────

def sample_report() -> dict:
    """A small report that conforms, in the shape the engine writes."""
    d = "/scan/repo"
    return {
        "verdict": "FAIL", "decision": "REJECTED", "status_color": "#B02A37", "status_background": "#F8D7DA",
        "scan_name": "n", "source": {"directory": d, "sha256": "a" * 64},
        "coverage": {"L1_secrets_gitleaks": "skipped:gitleaks not installed", "L1_secrets_entropy": "ran",
                     "L1_malware": "skipped:clamav not installed", "L1_ioc_yara": "skipped:yara or rules directory missing",
                     "L2_owasp_cwe": "partial:rulesets missing (secrets)", "L3_dependency_cve": "skipped:disabled (RUN_SCA is not true)",
                     "L4_patterns": "ran", "L5_per_language_sast": "ran", "L6_licence": "ran"},
        "coverage_complete": False,
        "coverage_gaps": ["L1_ioc_yara", "L1_malware", "L1_secrets_gitleaks", "L2_owasp_cwe", "L3_dependency_cve"],
        "timestamp": "2026-11-12T10:00:00Z", "repo_input": "", "directory": d, "repo_hash": "b" * 64,
        "standards": ["OWASP-Top10-2021", "CWE-Top25", "CERT-Secure-Coding", "PDF-Active-Content"],
        "summary": {"pass": 1, "warn": 2, "fail": 1},
        "findings": [{"tool": "grep-pattern", "category": "cwe", "severity": "HIGH", "rule_id": "CWE-89",
                      "rule_name": "SQL_injection", "file": "src/db.py", "line": None, "column": None,
                      "message": "CWE-89:SQL_injection", "references": ["CWE-89"]}],
        "findings_by_file": {d + "/src/db.py": "CWE-89:SQL_injection"},
        "file_results": {"__global__": {"status": "WARN", "message": "[WARN] gitleaks missing"},
                         d + "/README.md": {"status": "PASS", "message": ""},
                         d + "/src/db.py": {"status": "FAIL", "message": "[FAIL] CWE-89:SQL_injection | [WARN] bandit missing"}},
    }


def _set(path, value):
    def apply(r):
        cur = r
        for p in path[:-1]:
            cur = cur[p]
        cur[path[-1]] = value
    return apply


def _drop(path):
    def apply(r):
        cur = r
        for p in path[:-1]:
            cur = cur[p]
        del cur[path[-1]]
    return apply


def _pass_verdict(r):
    """Turn the sample into a self-consistent PASS (decision, colours) that still carries a finding."""
    r["verdict"], r["decision"] = "PASS", "APPROVED"
    r["status_color"], r["status_background"] = "#198754", "#D1E7DD"


# (what is broken, how to break it, a fragment the violation message must contain). The fragment makes the
# self-test check that the mutation is rejected for the intended reason and not by accident.
MUTATIONS = [
    ("required key verdict removed", _drop(["verdict"]), "required key 'verdict'"),
    ("required key coverage removed", _drop(["coverage"]), "required key 'coverage'"),
    ("required key summary.warn removed", _drop(["summary", "warn"]), "required key 'warn'"),
    ("required key findings[0].column removed", _drop(["findings", 0, "column"]), "required key 'column'"),
    ("required key file_results.status removed", _drop(["file_results", "__global__", "status"]), "required key 'status'"),
    ("required layer L4_patterns removed", _drop(["coverage", "L4_patterns"]), "required key 'L4_patterns'"),
    ("verdict WARN is not a verdict", _set(["verdict"], "WARN"), "is not one of ['PASS', 'FAIL']"),
    ("verdict lower case", _set(["verdict"], "pass"), "is not one of ['PASS', 'FAIL']"),
    ("decision outside enum", _set(["decision"], "MAYBE"), "$.decision"),
    ("status_color not a colour", _set(["status_color"], "red"), "$.status_color"),
    ("summary.pass is a string", _set(["summary", "pass"], "1"), "expected integer, got str"),
    ("summary.pass is a bool", _set(["summary", "pass"], True), "expected integer, got bool"),
    ("summary.fail is negative", _set(["summary", "fail"], -1), "below the minimum"),
    ("summary.warn is a float", _set(["summary", "warn"], 1.5), "expected integer, got float"),
    ("extra top-level key", _set(["surprise"], 1), "unexpected key 'surprise'"),
    ("extra key in summary", _set(["summary", "skip"], 0), "unexpected key 'skip'"),
    ("extra key in a finding", _set(["findings", 0, "score"], 9), "unexpected key 'score'"),
    ("unknown layer id", _set(["coverage", "L7_new_layer"], "ran"), "unexpected key 'L7_new_layer'"),
    ("coverage state not ran/skipped/partial", _set(["coverage", "L4_patterns"], "done"), "$.coverage.L4_patterns"),
    ("coverage state skipped without a reason", _set(["coverage", "L4_patterns"], "skipped:"), "$.coverage.L4_patterns"),
    ("coverage_complete is a string", _set(["coverage_complete"], "false"), "expected boolean"),
    ("coverage_gaps holds a non-layer", _set(["coverage_gaps"], ["gitleaks"]), "$.coverage_gaps[0]"),
    ("timestamp not ISO UTC", _set(["timestamp"], "2026-11-12 10:00:00"), "$.timestamp"),
    ("repo_hash too short", _set(["repo_hash"], "abc"), "$.repo_hash"),
    ("source.sha256 upper case", _set(["source", "sha256"], "A" * 64), "$.source.sha256"),
    ("standards entry not in the list", _set(["standards"], ["OWASP-Top10-2021", "Made-Up"]), "$.standards[1]"),
    ("severity outside enum", _set(["findings", 0, "severity"], "EXTREME"), "$.findings[0].severity"),
    ("category outside enum", _set(["findings", 0, "category"], "other"), "$.findings[0].category"),
    ("finding line is a string", _set(["findings", 0, "line"], "12"), "expected integer or null"),
    ("finding line is negative", _set(["findings", 0, "line"], -3), "below the minimum"),
    ("finding references holds a number", _set(["findings", 0, "references"], [798]), "references[0]"),
    ("finding file empty", _set(["findings", 0, "file"], ""), "$.findings[0].file"),
    ("file status outside enum", _set(["file_results", "__global__", "status"], "OK"), "is not one of ['PASS', 'WARN', 'FAIL']"),
    ("file_results entry extra key", _set(["file_results", "__global__", "extra"], 1), "unexpected key 'extra'"),
    ("findings_by_file value not a string", _set(["findings_by_file", "/scan/repo/src/db.py"], ["x"]), "expected string, got list"),
    ("findings is an object", _set(["findings"], {}), "expected array"),
    ("whole report is a list", None, "expected object, got list"),
    # invariants, each one broken on its own
    ("invariant: APPROVED with a FAIL verdict", _set(["decision"], "APPROVED"), "does not follow verdict"),
    ("invariant: colour does not follow verdict", _set(["status_color"], "#198754"), "do not match verdict"),
    ("invariant: coverage_complete true with gaps", _set(["coverage_complete"], True), "did not run"),
    ("invariant: coverage_gaps not the layers that did not run", _set(["coverage_gaps"], ["L1_malware"]), "differs from the layers"),
    ("invariant: summary.fail differs from findings", _set(["summary", "fail"], 5), "finding records"),
    ("invariant: directory differs from source.directory", _set(["directory"], "/elsewhere"), "directory and source.directory"),
    ("invariant: PASS with findings", _pass_verdict, "verdict is PASS but findings are present"),
    ("invariant: file outside the directory", _set(["file_results", "/etc/passwd"], {"status": "PASS", "message": ""}), "neither __global__"),
    ("invariant: FAIL status without a [FAIL] message", _set(["file_results", "/scan/repo/src/db.py", "message"], "[WARN] x"), "no [FAIL] message"),
    ("invariant: findings_by_file names a PASS file", _set(["findings_by_file", "/scan/repo/README.md"], "x"), "not a file with status FAIL"),
    ("invariant: finding message not in findings_by_file", _set(["findings", 0, "message"], "CWE-1:other"), "is not in findings_by_file"),
]


def self_test(schema) -> list[str]:
    """Return a list of problems; empty when the validator accepts the sample and rejects every mutation."""
    problems: list[str] = []
    base = sample_report()
    errs = check_report(base, schema)
    if errs:
        return ["the valid sample report was rejected, so the self-test cannot be trusted: " + "; ".join(errs[:3])]
    for name, fn, expect in MUTATIONS:
        mutated = copy.deepcopy(base)
        if fn is None:
            mutated = []                       # not even an object
        else:
            fn(mutated)
        errs = check_report(mutated, schema)
        if not errs:
            problems.append("mutation was NOT rejected: " + name)
        elif not any(expect in e for e in errs):
            problems.append("mutation %r was rejected, but not for the intended reason (wanted %r, got %r)"
                            % (name, expect, errs[0]))
    # The validator must also refuse a schema that uses a keyword it does not implement.
    for kw, val in (("oneOf", [{}]), ("$ref", "#/x"), ("minLength", 1), ("const", 1)):
        try:
            validate({}, {"type": "object", kw: val})
            problems.append("a schema using %r was accepted" % kw)
        except SchemaError:
            pass
    return problems


# ── running an engine ────────────────────────────────────────────────────────────────────────────────────────────

def _unsafe_ancestor(path: Path) -> str | None:
    for part in path.resolve().parts:
        if part in EXCLUDED_COMPONENTS:
            return part
    return None


def run_engine(engine: str, scan: Path, report_dir: Path, name: str, work: Path):
    env = {k: v for k, v in os.environ.items() if k not in SCRUB}
    env.update(WORK_DIR=str(work), LC_ALL="C.UTF-8")
    cmd = ENGINES[engine] + [str(scan), str(report_dir), name]
    return subprocess.run(cmd, env=env, capture_output=True, timeout=900)


def check_case(engine: str, fixture: str, name: str, want_verdict: str, want_exit: int, schema, base: Path) -> list[str]:
    errors: list[str] = []
    case = base / fixture
    scan, work, reports = case / "scan", case / "work", case / "reports"
    shutil.copytree(FIXTURES / fixture, scan, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    work.mkdir(parents=True)
    reports.mkdir()
    proc = run_engine(engine, scan, reports, name, work)
    out = proc.stdout.decode("utf-8", "replace").strip().splitlines()
    last = out[-1] if out else ""

    if proc.returncode != want_exit:
        errors.append("exit status %d, expected %d" % (proc.returncode, want_exit))
    if last != want_verdict:
        errors.append("last stdout line is %r, expected %r" % (last, want_verdict))

    json_path = reports / ("report_scan_%s.json" % name)
    html_path = reports / ("report_scan_%s.html" % name)
    if not json_path.is_file():
        errors.append("no report at %s (stderr: %s)" % (json_path, proc.stderr.decode("utf-8", "replace")[-300:].strip()))
        return errors
    if not html_path.is_file():
        errors.append("no HTML report beside the JSON report: %s" % html_path)

    sidecar_verdict, sidecar_path = work / ".scan_verdict", work / ".scan_report_json"
    if not sidecar_verdict.is_file() or sidecar_verdict.read_text().strip() != want_verdict:
        errors.append(".scan_verdict is missing or is not %s" % want_verdict)
    if not sidecar_path.is_file() or sidecar_path.read_text().strip() != str(json_path):
        errors.append(".scan_report_json is missing or does not name %s" % json_path)

    try:
        report = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        errors.append("the report is not valid JSON: %s" % exc)
        return errors
    problems = check_report(report, schema)
    errors.extend("report: " + p for p in problems)
    if report.get("verdict") != want_verdict:
        errors.append("report verdict is %r, expected %r" % (report.get("verdict"), want_verdict))
    if report.get("scan_name") != name:
        errors.append("scan_name is %r, expected %r" % (report.get("scan_name"), name))
    if report.get("directory") != str(scan):
        errors.append("directory is %r, expected %r" % (report.get("directory"), str(scan)))

    # The validator must also reject this real report once it is damaged. Only meaningful if it conformed.
    if not problems:
        damaged = copy.deepcopy(report)
        del damaged["coverage"]
        damaged["summary"]["pass"] = "many"
        if not check_report(damaged, schema):
            errors.append("a damaged copy of the real report was accepted: the validator is not checking")
    return errors


def check_refusal(engine: str, schema, base: Path) -> list[str]:
    """An invalid scanning_name is refused before anything is written."""
    errors: list[str] = []
    case = base / "refusal"
    scan, work, reports = case / "scan", case / "work", case / "reports"
    shutil.copytree(FIXTURES / "clean", scan, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    work.mkdir(parents=True)
    reports.mkdir()
    proc = run_engine(engine, scan, reports, "../escape", work)
    if proc.returncode != 1:
        errors.append("an invalid scanning_name gave exit status %d, expected 1" % proc.returncode)
    if proc.stdout.decode("utf-8", "replace").strip().splitlines()[-1:] in (["PASS"], ["FAIL"]):
        errors.append("an invalid scanning_name still printed a verdict")
    written = [p.name for p in list(reports.iterdir()) + [q for q in work.iterdir() if q.name.startswith(".scan_")]]
    if written:
        errors.append("an invalid scanning_name still wrote %s" % written)
    return errors


# ── main ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", choices=sorted(ENGINES), default="bash")
    ap.add_argument("--self-test", action="store_true", help="only run the self-test")
    ap.add_argument("--report", metavar="FILE", help="validate this existing report and stop")
    ap.add_argument("--keep", action="store_true", help="keep the temporary directory (its path is printed)")
    args = ap.parse_args(argv)

    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("cannot read %s: %s" % (SCHEMA_PATH, exc), file=sys.stderr)
        return 1

    if args.report:
        try:
            report = json.loads(Path(args.report).read_text(encoding="utf-8"))
            problems = check_report(report, schema)
        except (OSError, ValueError, SchemaError) as exc:
            print("%s: %s" % (args.report, exc), file=sys.stderr)
            return 1
        for p in problems:
            print("VIOLATION %s" % p, file=sys.stderr)
        print("%s: %s" % (args.report, "%d violation(s)" % len(problems) if problems else "conforms"))
        return 1 if problems else 0

    try:
        problems = self_test(schema)
    except SchemaError as exc:
        print("SCHEMA ERROR %s" % exc, file=sys.stderr)
        return 1
    if problems:
        for p in problems:
            print("SELF-TEST FAILED %s" % p, file=sys.stderr)
        return 1
    print("self-test: the valid sample conforms; %d mutations and 4 unsupported keywords were all rejected"
          % len(MUTATIONS))
    if args.self_test:
        return 0

    if args.engine == "python" and not Path(ENGINES["python"][1]).exists():
        print("the Python engine does not exist yet (scan_pipeline.py)", file=sys.stderr)
        return 1

    base = Path(tempfile.mkdtemp(prefix="schema_"))
    bad = _unsafe_ancestor(base)
    if bad:
        print("The temporary directory %s has a component named %r, which the bash engine treats as an excluded "
              "directory: it would scan nothing and pass. Set TMPDIR to a path without one (see "
              "docs/engine_contract.md section 11)." % (base, bad), file=sys.stderr)
        shutil.rmtree(base, ignore_errors=True)
        return 1

    failures = 0
    try:
        for fixture, name, verdict, status in CASES:
            errors = check_case(args.engine, fixture, name, verdict, status, schema, base)
            if errors:
                failures += 1
                print("FAIL %-12s" % fixture, file=sys.stderr)
                for e in errors:
                    print("     VIOLATION %s" % e, file=sys.stderr)
            else:
                print("ok   %-12s %s, exit %d, report conforms to the schema and to the invariants"
                      % (fixture, verdict, status))
        errors = check_refusal(args.engine, schema, base)
        if errors:
            failures += 1
            print("FAIL refusal", file=sys.stderr)
            for e in errors:
                print("     VIOLATION %s" % e, file=sys.stderr)
        else:
            print("ok   refusal      invalid scanning_name: exit 1, no verdict, nothing written")
    finally:
        if args.keep:
            print("kept %s" % base)
        else:
            shutil.rmtree(base, ignore_errors=True)

    if failures:
        print("\n%d check(s) failed" % failures, file=sys.stderr)
        return 1
    print("\nall checks passed (%s engine)" % args.engine)
    return 0


if __name__ == "__main__":
    sys.exit(main())
