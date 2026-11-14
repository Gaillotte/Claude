"""Document scanners of the Python engine: the inline credential rules of JSON and of prose files, and (later) the
container scanners (office documents, PDF, jar and other archives).

One function per scanner, named as in scan_pipeline.sh (the two below are the inline branches of classify_file), and no
module-level state. Standard library only.
"""
from transit.core import grep_check, record_fail, record_pass


def scan_json(f):
    """`.json`: one credential rule."""
    if grep_check(r'(password|secret|token|api_key|private_key)\s*"?\s*:\s*"[^"${[:space:]]{4,}', f):
        record_fail(f, "CWE-798:hardcoded_credential_in_JSON")
    else:
        record_pass(f)


def scan_doc(f):
    """`.md`, `.txt`, `.rst`: one credential rule."""
    if grep_check(r'(password|secret|api_key)\s*[:=]\s*[^${[:space:]][^[:space:]]{4,}', f):
        record_fail(f, "CWE-798:hardcoded_credential_in_doc")
    else:
        record_pass(f)
