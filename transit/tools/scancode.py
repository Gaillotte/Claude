# Moved out of scan_pipeline.sh (function scan_scancode) without changes to the code below.
# Reads ScanCode's JSON result and prints licence and vulnerability findings.
# Run by path from the bash engine; also importable by the Python engine. Standard library only.
import json, sys, os

report_path = sys.argv[1]
scan_dir    = sys.argv[2]

with open(report_path) as fh:
    data = json.load(fh)

for file in data.get("files", []):
    path = file.get("path", "")
    rel  = os.path.relpath(path, scan_dir) if os.path.isabs(path) else path

    for lic in file.get("license_detections", []):
        for match in lic.get("matches", []):
            spdx  = match.get("spdx_license_expression") or match.get("license_expression", "unknown")
            score = match.get("score", 0)
            risky = any(k in spdx.upper() for k in (
                "GPL", "AGPL", "LGPL", "SSPL", "BUSL", "EUPL", "CDDL", "CC-BY-SA", "CC-BY-NC"
            ))
            if risky and score >= 70:
                print(f"WARN|{rel}|licence:{spdx}")

    for pkg in file.get("packages", []):
        for vuln in pkg.get("vulnerabilities", []):
            vid      = vuln.get("vulnerability_id", "?")
            severity = vuln.get("max_severity", "").upper()
            pkg_name = pkg.get("name", "?")
            pkg_ver  = pkg.get("version", "?")
            if severity in ("CRITICAL", "HIGH"):
                print(f"FAIL|{rel}|scancode_vuln:{vid}[{severity}] in {pkg_name}=={pkg_ver}")
            else:
                print(f"WARN|{rel}|scancode_vuln:{vid}[{severity}] in {pkg_name}=={pkg_ver}")
