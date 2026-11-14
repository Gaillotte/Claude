# Moved out of scan_pipeline.sh (function _scan_gitleaks) without changes to the code below.
# Reads gitleaks' JSON report and prints one record per leak: file, line, rule id (NUL-separated).
# Run by path from the bash engine; also importable by the Python engine. Standard library only.
import json, sys
try:
    leaks = json.load(open(sys.argv[1], encoding="utf-8", errors="replace"))
except Exception:
    leaks = []
for l in leaks if isinstance(leaks, list) else []:
    f = str(l.get("File", "")).replace("\x00", "").replace("\x01", "?")
    r = str(l.get("RuleID", "unknown")).replace("\x00", "").replace("\x01", "?").replace(":", "_")
    sys.stdout.write(f + "\x01" + str(l.get("StartLine", "")) + "\x01" + r + "\x00")
