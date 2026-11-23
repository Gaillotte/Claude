#!/usr/bin/env python3
"""Does the project scan clean under its own rules?

The pipeline reads its own sources like any repository, and a rule definition holds what it detects: a pattern that looks for a
download piped into a shell contains the words of one. This guard applies the engine's FAIL-level grep rules (the tables of
transit/scan_lang.py, with the grep flags the engine uses) plus the default gitleaks AWS-key and semgrep PGP-block expressions to the
project's own sources, drops what `.transit-allow.json` allows (same rule token and path as the engine reads it), and exits 1 if any
hit is left. A rule is made not to match itself with a single-character bracket (a bracketed e is the letter e, and its own text no
longer holds the word), never by changing what it detects.

    python3 -I tests/selfmatch.py                 # the project, FAIL-level hits only; exit 1 when there is one
    python3 -I tests/selfmatch.py --warn          # also list the WARN-level hits (information, never an exit status)
    python3 -I tests/selfmatch.py --root DIR --files a.sh b.py
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)

# The sources that make up the pipeline and its documentation. Not scanned here: tests/fixtures (hostile files on purpose),
# the golden reports and the build scripts of the PDF and Word documents (which quote rule text to explain it).
SCOPE = [
    "scan_pipeline.sh", "scan_pipeline.py", "ai_transit.sh", "fetch_repo.sh", "docker-run.sh", "prepare_offline_cache.sh",
    "prepare_offline_install.sh", "verify_offline_install.sh", "selfcheck.py", "generate_excel_report.py",
    "INSTALL.md", "CLAUDE.md", "OFFLINE_RUNBOOK.md", "docs/engine_contract.md", "docs/unscanned_file_types.md",
    "docs/python_port_thin_plan.md", "tests/run_tests.sh", "tests/selfmatch.py",
    "transit/core.py", "transit/layers.py", "transit/report_json.py", "transit/scan_build.py", "transit/scan_docs.py",
    "transit/scan_lang.py", "transit/containers/jar.py", "transit/containers/office.py", "transit/containers/pdf.py",
    "transit/scanners/manifests.py", "transit/scanners/native.py", "transit/tools/gitleaks.py", "transit/tools/scancode.py",
]

# transit/scan_docs.py: the credential rule of .md, .txt and .rst files.
DOC_RULE = ("fail", r"(password|secret|api_key)\s*[:=]\s*[^${[:space:]][^[:space:]]{4,}", "CWE-798:hardcoded_credential_in_doc")
# The default gitleaks rule for an AWS access key id, and the semgrep rule for a PGP private key block.
AWS_KEY = re.compile(rb"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b")
PGP_BLOCK = re.compile(rb"-----BEGIN PGP PRIVATE KEY BLOC[K]-----")


def rules_for(path, scan_lang):
    rules = list(scan_lang._UNIVERSAL_CREDENTIAL) + list(scan_lang._UNIVERSAL_REST)
    if path.endswith(".py"):
        rules += scan_lang._PYTHON_RULES
    elif path.endswith(".sh"):
        rules += scan_lang._SHELL_RULES
    elif path.endswith((".md", ".txt", ".rst")):
        rules.append(DOC_RULE)
    return rules


def grep_lines(pattern, path, icase):
    out = subprocess.run(["grep", "-nE" + ("i" if icase else ""), "-e", pattern, "--", path],
                         capture_output=True, text=True, errors="replace").stdout
    return [int(x.split(":", 1)[0]) for x in out.splitlines()]


def allowed(allow, path, message):
    """The engine's test: the rule token is the first or the second colon-separated word of the message."""
    parts = message.split(":")
    return any((tok + "::" + path) in allow for tok in (parts[0], parts[1] if len(parts) > 1 else ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=PROJECT)
    ap.add_argument("--files", nargs="*")
    ap.add_argument("--warn", action="store_true", help="also list WARN-level hits")
    args = ap.parse_args()

    sys.path.insert(0, PROJECT)
    from transit import scan_lang
    root = os.path.abspath(args.root)
    os.chdir(root)

    allow = set()
    try:
        for e in json.load(open(".transit-allow.json", encoding="utf-8")):
            allow.add(e["rule"] + "::" + e["path"])
    except (OSError, ValueError, KeyError, TypeError):
        pass

    fails = warns = checked = 0
    for path in (args.files or SCOPE):
        if not os.path.isfile(path):
            continue
        checked += 1
        rows = []                                        # (level, rule, lines, allowed)
        for row in rules_for(path, scan_lang):
            level, pattern, message = row[:3]
            hits = grep_lines(pattern, path, len(row) > 3)
            if hits:
                rows.append((level, message, hits, allowed(allow, path, message) if level == "fail" else False))
        data = open(path, "rb").read()
        for name, rx in (("gitleaks:aws-access-token", AWS_KEY), ("semgrep:detected-pgp-private-key-block", PGP_BLOCK)):
            hits = [data[:m.start()].count(b"\n") + 1 for m in rx.finditer(data)]
            if hits:
                rows.append(("fail", name, hits, False))   # a tool finding is about the directory: no per-path allowlist
        for level, message, hits, ok in rows:
            if level == "fail" and not ok:
                fails += 1
            elif level == "warn":
                warns += 1
                if not args.warn:
                    continue
            elif ok and not args.warn:
                continue
            tag = "ALLOWED" if ok else level.upper()
            print("%s: %s %s: %s" % (path, tag, message, hits[:12]))
    print("selfmatch: %d file(s), %d FAIL-level hit(s)%s" % (checked, fails, (", %d WARN-level" % warns) if args.warn else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
