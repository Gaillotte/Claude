# Public names (from transit.core import ...):
#   state     G  FINDINGS  FILE_STATUS  FILE_MSG  LAYER_COVERAGE  ALLOW_MAP  TRANSIT_DIR  DEFAULT_EXCLUDE_DIRS
#   console   log  info  warn  ok  fail  fail_f  _san  _clr  has_cmd
#   verdict   record_pass  record_warn  record_fail  record_fail_hard  record_layer  note_l5_partial
#             _classify_severity  _emit_finding  _write_finding  _commit_fail
#   grep      grep_check  grep_check_i  grep_check_excl  grep_flat  grep_rules  grep_pipe  _known_cred_check
#             KNOWN_CRED_NAMES  KNOWN_CRED_PATS  KNOWN_CRED_ALL  KNOWN_CRED_EXCL
#   programs  run_tool  run_helper  call_scanner  register_tmp  cleanup_tmp  first_line  shebang_scanner
"""What the scan_* functions of scan_pipeline.sh share, with the shell's names.

The environment and its defaults (contract section 2), the console, the verdict state, the finding records, the grep helpers
and the runner of external programs. Every external program is started with an argument list, never through a shell, with
LC_ALL=C in its environment like the shell's `export LC_ALL=C`. Scalar shell variables (GLOBAL_VERDICT, PASS_COUNT, FLAT_FILE
...) live in the namespace G, because a name imported with `from transit.core import` would be a copy; the arrays are plain
module-level dicts. Standard library only.
"""
import heapq
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time
import types

# The first thing the shell does: every rule is ASCII and is meant to see bytes (children inherit this).
os.environ["LC_ALL"] = "C"

TRANSIT_DIR = os.path.dirname(os.path.abspath(__file__))


def _b(s):
    """Text -> bytes the way file names travel through this engine: UTF-8, with lone bytes kept as surrogates."""
    return s.encode("utf-8", "surrogateescape") if isinstance(s, str) else s


def _s(b):
    return b.decode("utf-8", "surrogateescape")


def _env(name, default):
    """`${NAME:-default}`: an empty value is the default too."""
    v = os.environ.get(name)
    return v if v else default


def _ascii_lower(s):
    return s.translate({c: c + 32 for c in range(65, 91)})


_WORK_DIR = _env("WORK_DIR", "/opt/ai-transit")
_MIN_SEVERITY = _env("MIN_SEVERITY", "high")
_OFFLINE_CACHE = _env("OFFLINE_CACHE", _WORK_DIR + "/offline-cache")

# The scalar globals of the shell. SCAN_DIR, SCANNING_NAME, REPORT_DIR, FINDINGS_JL and the exclusion lists are set by
# scan_pipeline.py once the arguments are read.
G = types.SimpleNamespace(
    WORK_DIR=_WORK_DIR,
    TIMESTAMP=time.strftime("%Y%m%d_%H%M%S"),
    VERBOSITY=_env("VERBOSITY", "normal"),                       # quiet | normal | verbose
    MIN_SEVERITY=_MIN_SEVERITY,                                  # low | medium | high | critical
    SEV_THRESHOLD={"low": 1, "medium": 2, "high": 3, "critical": 4}.get(_ascii_lower(_MIN_SEVERITY), 3),
    OFFLINE=True,
    OFFLINE_CACHE=_OFFLINE_CACHE,
    SEMGREP_RULES_DIR=_env("SEMGREP_RULES_DIR", _OFFLINE_CACHE + "/semgrep-rules"),
    TRIVY_CACHE_DIR=_env("TRIVY_CACHE_DIR", _OFFLINE_CACHE + "/trivy-db"),
    CLAMAV_DB_DIR=_env("CLAMAV_DB_DIR", _OFFLINE_CACHE + "/clamav"),
    RUN_SCA=_env("RUN_SCA", "false"),
    RUN_SCANCODE=_env("RUN_SCANCODE", "false"),
    REPO_INPUT=_env("REPO_INPUT", ""),
    SCAN_DIR="", SCANNING_NAME="", REPORT_DIR="", REPORT_JSON="", REPORT_HTML="", FINDINGS_JL="",
    EXTRA_EXCLUDE_DIRS=[], SEMGREP_EXCLUDES=[], CLAMSCAN_EXCLUDES=[],
    DIFF_FILES_ONLY=False, DIFF_FILES_SET=set(),
    GLOBAL_VERDICT="PASS", PASS_COUNT=0, WARN_COUNT=0, FAIL_COUNT=0,
    FLAT_INCOMPLETE=False, FLAT_FILE="", L5_PARTIAL="",
    TMP_PATHS=[],
    # where the grep helpers matched: the file, and per match how it was searched (see "Lines of a finding")
    LM_FILE="", LM_ENTRIES=[],
)

DEFAULT_EXCLUDE_DIRS = ("node_modules", ".git", "vendor", ".tox", "__pycache__", ".venv", "venv",
                        "dist", "build", ".next", ".nuxt", ".cache", "target", "coverage")

FINDINGS = {}        # path -> concatenated FAIL messages
FILE_STATUS = {}     # path -> PASS | FAIL | WARN
FILE_MSG = {}        # path -> "[WARN] message | [FAIL] message | ..."
FILE_LINES = {}      # path -> "rule: the lines that match, ... | " (the Lines column of the HTML report)
LAYER_COVERAGE = {}  # layer id -> "ran" | "skipped:<reason>" | "partial:<reason>"
ALLOW_MAP = {}       # "rule::relpath" -> reason


# ── Console ──────────────────────────────────────────────────────────────────
def _w(stream, data):
    try:
        stream.write(data)
        stream.flush()
    except (OSError, ValueError):
        pass


_CNTRL = re.compile(rb"[\x00-\x1f\x7f]|\xc2[\x80-\x9f]")


def _san(text):
    """Text from the repository reaches the console: every control byte (and the two bytes of a C1 control) becomes '?'."""
    return _s(_CNTRL.sub(b"?", _b(text)))


def _clr():
    if os.isatty(2):
        _w(sys.stderr.buffer, b"\r\x1b[K")


def log(*msg):
    if G.VERBOSITY != "quiet":
        _clr()
        _w(sys.stdout.buffer, _b("[%s] %s\n" % (time.strftime("%H:%M:%S"), " ".join(msg))))


def _line(stream, colour, tag, msg):
    _clr()
    _w(stream, _b("\x1b[%sm[%s]\x1b[0m  %s\n" % (colour, tag, _san(" ".join(msg)))))


def info(*msg):
    if G.VERBOSITY != "quiet":
        _line(sys.stdout.buffer, "34", "INFO", msg)


def warn(*msg):
    _line(sys.stderr.buffer, "33", "WARN", msg)


def ok(*msg):
    if G.VERBOSITY != "quiet":
        _line(sys.stdout.buffer, "32", "OK", msg)


def fail(*msg):
    _line(sys.stderr.buffer, "31", "FAIL", msg)
    sys.exit(1)


def fail_f(*msg):
    _line(sys.stderr.buffer, "31", "FAIL", msg)
    G.GLOBAL_VERDICT = "FAIL"


def has_cmd(name):
    return shutil.which(name) is not None


# ── Temporary files (the shell's EXIT trap) ─────────────────────────────────
def register_tmp(path):
    G.TMP_PATHS.append(path)


def cleanup_tmp():
    for p in G.TMP_PATHS:
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
        except OSError:
            pass
    G.TMP_PATHS.clear()


def is_control_file(f):
    """The three files the pipeline puts at the root of a scanned directory: scanned like any file, but they do not count as
    "something was examined"."""
    root = G.SCAN_DIR[:-1] if G.SCAN_DIR.endswith("/") else G.SCAN_DIR
    return f in (root + "/.transitignore", root + "/.transit-allow.json", root + "/.manifest_sha256.txt")


# ── Layer coverage ──────────────────────────────────────────────────────────
def record_layer(layer, state):
    LAYER_COVERAGE[layer] = state


def note_l5_partial(reason):
    if ("; %s; " % reason) not in ("; %s; " % G.L5_PARTIAL):
        G.L5_PARTIAL += ("; " if G.L5_PARTIAL else "") + reason


# ── Verdict helpers ─────────────────────────────────────────────────────────
def record_pass(file=""):
    G.LM_FILE = ""
    G.PASS_COUNT += 1
    if file and not FILE_STATUS.get(file):
        FILE_STATUS[file] = "PASS"
        FILE_MSG[file] = ""


def record_warn(file="__global__", *msg):
    file = file or "__global__"
    text = " ".join(msg)
    G.LM_FILE = ""
    G.WARN_COUNT += 1
    warn(text)
    # WARN never downgrades an existing status.
    if not FILE_STATUS.get(file):
        FILE_STATUS[file] = "WARN"
    FILE_MSG[file] = FILE_MSG.get(file, "") + "[WARN] %s | " % text


_SEMGREP_SEV = re.compile(r"^semgrep\[[^\]]*\]:[^:]*:line[0-9]*:([A-Za-z]+):")
_MARKERS = (("INFO", re.compile(r":(INFO):", re.I | re.A)), ("LOW", re.compile(r":(LOW):", re.I | re.A)),
            ("MEDIUM", re.compile(r":(WARNING|MEDIUM):", re.I | re.A)), ("HIGH", re.compile(r":(ERROR|HIGH):", re.I | re.A)),
            ("CRITICAL", re.compile(r":CRITICAL:", re.I | re.A)))
_SEV = {"INFO": (1, "INFO"), "LOW": (1, "LOW"), "WARNING": (2, "MEDIUM"), "MEDIUM": (2, "MEDIUM"),
        "ERROR": (3, "HIGH"), "HIGH": (3, "HIGH"), "CRITICAL": (4, "CRITICAL")}


def _classify_severity(msg):
    """(number, name) of a finding message: the one classification of the decision and of the record."""
    if msg.startswith(("gitleaks:", "clamav:")):
        return 4, "CRITICAL"
    lvl = ""
    if msg.startswith("semgrep["):
        m = _SEMGREP_SEV.match(msg)
        if m:
            lvl = m.group(1)
    else:
        for name, rx in _MARKERS:
            if rx.search(msg):
                lvl = name
                break
    return _SEV.get(lvl.upper(), (3, "HIGH"))


def _write_finding(tool, category, severity, rule_id, rule_name, file, line, column, message, lines="", line_count="", refs=""):
    """`lines` is a comma-separated list (the first ten matching lines), `line_count` how many lines match in all."""
    def clean(x):
        return _b(x).decode("utf-8", "replace")
    rec = dict(tool=clean(tool), category=clean(category), severity=clean(severity), rule_id=clean(rule_id),
               rule_name=clean(rule_name), file=clean(file),
               line=int(line) if line.isdigit() else None, column=int(column) if column.isdigit() else None,
               lines=[int(x) for x in lines.split(",") if x.isdigit()],
               line_count=int(line_count) if line_count.isdigit() else 0,
               message=clean(message), references=clean(refs).split(",") if refs else [])
    try:
        with open(G.FINDINGS_JL, "a", encoding="ascii") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


_TOOL_RULE = re.compile(r"^([a-z][a-z0-9_-]{1,30}):([^:]+)")
# A tool that names its line puts it at a fixed position: "semgrep[ruleset]:rule:lineN:SEV:text" and "gitleaks:rule:lineN".
# A ":lineN" inside the text of a message (a jar entry named "x:line7.txt") is repository text, not a line.
_LINE_NO = re.compile(r"^(?:semgrep\[[^\]]*\]:[^:]*:line([0-9]{1,9}):|gitleaks:.*:line([0-9]{1,9})\Z)", re.DOTALL)


# ── Lines of a finding ──────────────────────────────────────────────────────
# A finding of a built-in rule says which lines of the file match: `line` (the first one), `lines` (every matching line, at
# most ten) and `line_count` (how many lines match in all). The message is not touched: the allowlist, the severity and the
# stored messages read it. The grep helpers only remember what matched (_lm_add); _lm_resolve runs when a FAIL is recorded,
# searches the file once more for each remembered match with the SAME pattern and options and -n, and returns (the first ten
# lines, how many in all); a rule made of several whole-file tests lists the lines of all of them. Every pattern is still
# evaluated by grep: Python only numbers lines. A rule that searched something other than the file itself (a comment-stripped
# copy, continuations joined, a decoded stream, the text of an archive) has no line in the file: the file a helper searched
# must be the file the finding is recorded against, or there is no line, never a wrong one.
#
# Everything is a stream: grep's output is read a line at a time and only the number is kept, so a file of millions of matching
# lines costs time and no memory (the first version captured the whole output: 1.3 GB for a 96 MB file).
_LM_FAMILIES = ("CWE-", "OWASP-", "CVE-", "make:")
_LM_CAP = 10
_LM_MAX_ENTRIES = 8
_LM_PEM_HEADER = r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----"
_LM_PEM_WINDOW = _LM_PEM_HEADER + r".{0,200}[A-Za-z0-9+/]{60,}"
_LM_PEM_HEADERS_TRIED = 200
_LM_TOKEN_BATCH = 4096
_LM_TOKEN_BATCH_BYTES = 1 << 20      # a batch is also cut by size: a few huge tokens must not be held together
_LM_PEM_BUDGET = 8 << 20             # what the private-key rule may hold while it numbers a file: beyond it, no line


class _LmGaveUp(Exception):
    """The numbering of a finding was stopped (a timeout, a budget): the finding keeps its file and has no line."""


def _lm_z_timeout():
    """Seconds the numbering of a folded (-z) search may take (LM_Z_TIMEOUT_S, 5 by default). A search that numbers its matches
    (grep -o / -b) cannot use grep's DFA and is quadratic on a pattern such as `[^>]*` over a file of unclosed openers."""
    v = os.environ.get("LM_Z_TIMEOUT_S", "")
    return v if re.fullmatch(r"[1-9][0-9]{0,4}", v) else "5"
_LM_PREFIX = re.compile(rb"^([0-9]+)([:-])")


def _lm_add(path, mode, pattern, excl=""):
    """A helper matched: remember how. A test that does not match forgets them all (G.LM_FILE = "")."""
    if not G.LM_FILE or G.LM_FILE != path:
        G.LM_ENTRIES = []
    if len(G.LM_ENTRIES) >= _LM_MAX_ENTRIES:          # eight matches and no finding: not a rule, no line
        G.LM_FILE = ""
        return
    G.LM_FILE = path
    G.LM_ENTRIES.append((mode, pattern, excl))


def _lm_rows(argv):
    """The lines a program prints, one at a time (never the whole output)."""
    try:
        proc = subprocess.Popen(_argv(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return
    try:
        yield from proc.stdout
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def _lm_nums(flags, pattern, path):
    """The numbers of the lines of `path` that match `pattern`, ascending (grep -n output)."""
    for row in _lm_rows(["grep", flags, "-e", pattern, "--", path]):
        head = row.split(b":", 1)[0]
        if head.isdigit():
            yield int(head)


def _lm_minus(first, second):
    """The numbers of `first` that are not in `second` (both ascending): the lines of a pattern that its exclusion does not drop."""
    second = iter(second)
    cur = next(second, None)
    for n in first:
        while cur is not None and cur < n:
            cur = next(second, None)
        if cur != n:
            yield n


def _lm_tokens(pattern, path):
    """Known credential formats: the line of every matched token that the exclusion list does not drop. The exclusion applies to
    the token, not to the line, so tokens go to grep in batches of 4096 tokens or 1 MB (one process per batch, never the whole file)."""
    def kept(rows):
        _, out = run_tool(["grep", "-nviE", "-e", KNOWN_CRED_EXCL], input=b"".join(tok + b"\n" for _, tok in rows))
        keep = {int(k.split(b":", 1)[0]) for k in out.split(b"\n") if k[:1].isdigit()}
        return [rows[i - 1][0] for i in sorted(keep) if i <= len(rows)]
    rows, size = [], 0
    for row in _lm_rows(["grep", "-noIE", "-e", pattern, "--", path]):
        number, _, token = row.rstrip(b"\n").partition(b":")
        if number.isdigit():
            rows.append((int(number), token))
            size += len(token) + 1
        if len(rows) >= _LM_TOKEN_BATCH or size >= _LM_TOKEN_BATCH_BYTES:
            yield from kept(rows)
            rows, size = [], 0
    if rows:
        yield from kept(rows)


def _lm_offsets(read):
    """The byte offsets of grep -zbo output: records are b"<offset>:<text>\\0"; the text, however long, is never kept."""
    num, head = b"", True
    while True:
        chunk = read(1 << 20)
        if not chunk:
            return
        pos, n = 0, len(chunk)
        while pos < n:
            if head:
                c = chunk.find(b":", pos)
                if c < 0:
                    num += chunk[pos:]
                    pos = n
                else:
                    num += chunk[pos:c]
                    pos = c + 1
                    head = False
                    if num.isdigit():
                        yield int(num)
                    num = b""
            else:
                z = chunk.find(b"\0", pos)
                if z < 0:
                    pos = n
                else:
                    pos = z + 1
                    head = True


def _lm_newline_lines(path, offsets):
    """The line number of each ascending byte offset (the newlines before it, plus one), each once."""
    pos = newlines = last = 0
    with open(path, "rb") as fh:
        for off in offsets:
            while pos < off:
                chunk = fh.read(min(1 << 20, off - pos))
                if not chunk:
                    break
                newlines += chunk.count(b"\n")
                pos += len(chunk)
            if newlines + 1 != last:
                last = newlines + 1
                yield last


def _lm_folded(pattern, path):
    """The lines on which a match of the folded (grep -z) search starts."""
    try:
        proc = subprocess.Popen(_argv(["timeout", _lm_z_timeout(), "grep", "-zboiE", "-e", pattern, "--", path]),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return
    try:
        yield from _lm_newline_lines(path, _lm_offsets(proc.stdout.read))
        if proc.wait() == 124:                      # timeout stopped grep: what was read is not the whole answer
            raise _LmGaveUp()
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def _lm_pem_lines(path):
    """The header lines of a private key whose own window (five lines, folded) passes the key rule: one pass over the file, the
    first 200 headers (a file with more is a bundle of keys), one grep over the folded windows. The first version read the
    file once per header."""
    text, headers, stop, held = {}, [], 0, 0
    for row in _lm_rows(["grep", "-anE", "-A5", "-e", _LM_PEM_HEADER, "--", path]):
        m = _LM_PREFIX.match(row)
        if not m:
            continue                                   # the "--" between two groups
        n = int(m.group(1))
        if stop and n > stop:
            break
        held += len(row)
        if held > _LM_PEM_BUDGET:                      # lines this long are not keys: bounded memory, no line
            raise _LmGaveUp()
        text[n] = row[m.end():].rstrip(b"\n")
        if m.group(2) == b":" and len(headers) < _LM_PEM_HEADERS_TRIED:
            headers.append(n)
            if len(headers) == _LM_PEM_HEADERS_TRIED:
                stop = n + 5
    if not headers:
        return
    windows = b"".join(b"%d\t%s\n" % (h, b" ".join(text[k] for k in range(h, h + 6) if k in text).translate(_TR_FOLD) + b" ")
                       for h in headers)
    _, out = run_tool(["grep", "-aE", "-e", _LM_PEM_WINDOW], input=windows)
    for row in out.split(b"\n"):
        head = row.split(b"\t", 1)[0]
        if head.isdigit():
            yield int(head)


_TR_FOLD = bytes.maketrans(b"\r\n\t", b"   ")


def _lm_entry(entry, path):
    """The ascending line numbers of one remembered match (a line is listed once per match; the reader lists it once)."""
    mode, pattern, excl = entry
    if mode == "E":
        return _lm_nums("-anE", pattern, path)
    if mode == "iE":
        return _lm_nums("-aniE", pattern, path)
    if mode == "X":                     # matches the pattern and not the exclusion: the first list minus the second
        return _lm_minus(_lm_nums("-aniE", pattern, path), _lm_nums("-aniE", excl, path))
    if mode == "T":
        return _lm_tokens(pattern, path)
    if mode == "Z":
        return _lm_folded(pattern, path)
    if mode == "P":
        return _lm_pem_lines(path)
    return iter(())


def _lm_has_nul(path):
    """True when the file holds a NUL byte. grep reads such a file as binary: the plain helpers (grep -q, no -a) take each NUL
    for the end of a line, so a pattern satisfied across it does not match and `$` matches before it. Numbering the lines of
    such a file would need that same reading and a count of what it splits, and lines numbered another way can list a line
    the rule did not match. So a finding made by a plain match (E, iE) on such a file has no line. The other modes read the
    file as text (-a, -z) in the matcher and in the resolver alike."""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                return False
            if b"\0" in chunk:
                return True


def _lm_resolve():
    """-> (the first ten matching lines, the number of matching lines) of the helpers that matched, or ([], 0)."""
    path = G.LM_FILE
    if not path or not G.LM_ENTRIES or not os.path.isfile(path):
        return [], 0
    try:
        if any(mode in ("E", "iE") for mode, _, _ in G.LM_ENTRIES) and _lm_has_nul(path):
            return [], 0
    except OSError:
        return [], 0
    first, total, last = [], 0, None
    try:
        streams = [_lm_entry(e, path) for e in G.LM_ENTRIES]
        for n in (streams[0] if len(streams) == 1 else heapq.merge(*streams)):
            if n != last:
                last = n
                total += 1
                if len(first) < _LM_CAP:
                    first.append(n)
    except (OSError, _LmGaveUp):
        return [], 0
    return first, total


def _emit_finding(file, msg):
    """The structured fields of a FAIL, from the shape of its message (first match wins)."""
    _, sev_name = _classify_severity(msg)
    tool = rule_id = rule_name = refs = ""
    category = "security"
    if msg.startswith("semgrep["):
        tool, category = "semgrep", "sast"
        rule_id = (msg.split("]:", 1)[1] if "]:" in msg else msg).split(":", 1)[0]
    elif msg.startswith("detect-secrets:"):
        tool, category, rule_id, rule_name, refs = "detect-secrets", "secret", "high_entropy_string", "High Entropy String", "CWE-798"
    elif msg.startswith("clamav:"):
        tool, category, rule_id, rule_name = "clamav", "malware", msg[len("clamav:"):], "Malware Detected"
    elif msg.startswith("gitleaks:"):
        tool, category, rule_name, refs = "gitleaks", "secret", "Secret Detected", "CWE-798"
        rule_id = msg[len("gitleaks:"):].split(":", 1)[0]
    elif msg.startswith("yara:"):
        tool, category, rule_id, rule_name = "yara", "ioc", msg[len("yara:"):], "IOC Match"
    elif msg.startswith("bandit:"):
        tool, category, rule_name = "bandit", "sast", "Bandit Finding"
        rest = msg[len("bandit:"):]
        rule_id = rest[rest.index(":") + 1:] if ":" in rest else msg
    elif msg.startswith("cppcheck:"):
        tool, category, rule_id, rule_name = "cppcheck", "sast", msg[len("cppcheck:"):], "Cppcheck Finding"
    elif msg.startswith("shellcheck:"):
        tool, category, rule_id, rule_name = "shellcheck", "sast", msg[len("shellcheck:"):], "ShellCheck Finding"
    elif msg.startswith("CWE-") and ":" in msg[4:]:
        tool, category = "grep-pattern", "cwe"
        rule_id, rule_name = msg.split(":", 1)
        refs = rule_id
    elif msg.startswith("OWASP-") and ":" in msg[6:]:
        tool, category = "grep-pattern", "owasp"
        rule_id, rule_name = msg.split(":", 1)
    else:
        m = _TOOL_RULE.match(msg)
        if m:
            tool, rule_id = m.group(1), m.group(2)
    # The line comes from the tool when the message carries one (Semgrep: ":lineN:"); a built-in grep rule has none in its
    # message and takes the lines its last helper matched. Only the message families those rules use, only the file that
    # helper searched, and only once: anything else is null.
    m = _LINE_NO.match(msg)
    line, lines, line_count = "", "", 0
    if m:
        line = m.group(1) or m.group(2)
        if int(line) >= 1:
            lines, line_count = line, 1
    elif G.LM_FILE and G.LM_ENTRIES and file == G.LM_FILE and msg.startswith(_LM_FAMILIES):
        found, total = _lm_resolve()
        if total:
            line, lines, line_count = str(found[0]), ",".join(str(n) for n in found), total
    G.LM_FILE = ""
    if lines:
        # a built-in rule is named by its whole message (CWE-22:path_traversal_encoded), another tool by its rule id
        label = msg if tool == "grep-pattern" else (rule_id or tool)
        FILE_LINES[file] = FILE_LINES.get(file, "") + "%s: %s%s | " % (
            label, ", ".join(lines.split(",")), " of %d" % line_count if line_count > 10 else "")
    rule_name = rule_name or msg
    tool = tool or "unknown"
    rel = file[len(G.SCAN_DIR) + 1:] if file.startswith(G.SCAN_DIR + "/") else file
    if rel == G.SCAN_DIR:
        rel = "."
    _write_finding(tool, category, sev_name, rule_id, rule_name, rel, line, "", msg, lines, str(line_count), refs)


def record_fail(file, *msg):
    msg = " ".join(msg)
    rel_path = file[len(G.SCAN_DIR) + 1:] if file.startswith(G.SCAN_DIR + "/") else file
    # Allowlist: the text before the first colon, then the text between the first and the second.
    first = msg.split(":", 1)[0]
    second = (msg.split(":", 1)[1] if ":" in msg else msg).split(":", 1)[0]
    for token in (first, second):
        reason = ALLOW_MAP.get("%s::%s" % (token, rel_path), "")
        if reason:
            record_warn(file, "ALLOWED:%s (reason: %s)" % (msg, reason))
            return
    if _classify_severity(msg)[0] < G.SEV_THRESHOLD:
        record_warn(file, "LOW_SEV(below --min-severity %s):%s" % (G.MIN_SEVERITY, msg))
        return
    _commit_fail(file, msg)


def _commit_fail(file, msg):
    """The part of a FAIL that cannot be avoided: the record, the status, the counter, the console line and the verdict."""
    _emit_finding(file, msg)
    FINDINGS[file] = FINDINGS.get(file, "") + "%s | " % msg
    FILE_STATUS[file] = "FAIL"
    FILE_MSG[file] = FILE_MSG.get(file, "") + "[FAIL] %s | " % msg
    G.FAIL_COUNT += 1
    fail_f("[%s] %s" % (file, msg))


def record_fail_hard(file, msg):
    """A FAIL about the scan itself (engine:): neither allowlisted nor compared with the threshold."""
    _commit_fail(file, msg)


# ── Running programs ────────────────────────────────────────────────────────
MAX_OUTPUT = 256 * 1024 * 1024


def _argv(argv):
    return [_b(a) for a in argv]


def _rc(rc):
    return 128 - rc if rc < 0 else rc          # a signal reads as 128+n, like `$?`


def run_tool(argv, timeout=None, input=None, env=None, cwd=None, merge_stderr=False, max_output=MAX_OUTPUT, stdout_file=None):
    """Run one external program: an argument list, never a shell. -> (exit status, stdout bytes).

    stdin is /dev/null (or `input`), stderr is discarded (or merged into stdout). The child gets our environment (LC_ALL=C and
    the offline switches included); `env` overrides it: {"NAME": "value"} sets a variable, {"NAME": None} removes it (the
    shell's `env -u NAME`). The status is the shell's: 127 not found, 126 not startable, 124 timeout, 125 output over
    `max_output` (the program is killed), 128+n a signal. `stdout_file` receives stdout instead."""
    if env is not None:
        child = dict(os.environ)
        for k, v in env.items():
            if v is None:
                child.pop(k, None)
            else:
                child[k] = v
        env = child
    try:
        p = subprocess.Popen(_argv(argv), stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                             stdout=stdout_file if stdout_file is not None else subprocess.PIPE,
                             stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
                             env=env, cwd=cwd, start_new_session=timeout is not None)
    except FileNotFoundError:
        return 127, b""
    except OSError:
        return 126, b""
    feeder = None
    if input is not None:
        def feed():
            try:
                p.stdin.write(input)
            except OSError:
                pass
            finally:
                try:
                    p.stdin.close()
                except OSError:
                    pass
        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
    deadline = None if timeout is None else time.monotonic() + timeout
    chunks, total, state = [], 0, ""
    if stdout_file is None:
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        while True:
            left = None if deadline is None else deadline - time.monotonic()
            if left is not None and left <= 0:
                state = "timeout"
                break
            if not sel.select(left):
                continue
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_output:
                state = "big"
                break
            chunks.append(chunk)
        sel.close()
    if not state:
        try:
            p.wait(None if deadline is None else max(deadline - time.monotonic(), 0))
        except subprocess.TimeoutExpired:
            state = "timeout"
    if state:
        try:
            os.killpg(p.pid, signal.SIGKILL) if timeout is not None else p.kill()
        except OSError:
            pass
        p.wait()
    if p.stdout:
        p.stdout.close()
    return {"timeout": 124, "big": 125}.get(state, _rc(p.returncode)), b"".join(chunks)


def run_helper(script, *args, input=None, env=None, timeout=None, merge_stderr=False):
    """`python3 transit/<script> args...`: the helper programs the shell runs by path. -> (exit status, stdout bytes)."""
    return run_tool([sys.executable, "-I", os.path.join(TRANSIT_DIR, script)] + list(args), input=input, env=env,
                    timeout=timeout, merge_stderr=merge_stderr)


def init_offline_env():
    """`export` of the offline switches: no scanner attempts a network call."""
    os.environ.update({"SEMGREP_SEND_METRICS": "off", "DO_NOT_TRACK": "1", "CHECKPOINT_DISABLE": "1", "PIP_NO_INDEX": "1"})


# ── Scanners, by name ───────────────────────────────────────────────────────
SCANNER_MODULES = ("scan_lang", "scan_build", "scan_docs")
_loaded = {}


def _scanner(name):
    import importlib
    for mod in SCANNER_MODULES:
        if mod not in _loaded:
            try:
                _loaded[mod] = importlib.import_module("transit." + mod)
            except ModuleNotFoundError as exc:
                if exc.name != "transit." + mod:
                    warn("transit/%s.py could not be imported: %s" % (mod, exc))
                _loaded[mod] = None
            except Exception as exc:                      # a module that does not load must be visible, not silent
                warn("transit/%s.py could not be imported: %s: %s" % (mod, type(exc).__name__, exc))
                _loaded[mod] = None
        fn = getattr(_loaded[mod], name, None) if _loaded[mod] else None
        if callable(fn):
            return fn
    return None


def call_scanner(name, *args):
    """Run the scanner function `name` of transit/scan_*.py on a file. A scanner that is not ported yet is a WARN on the
    file and makes layer 5 partial: it must never read as a clean file. -> the scanner's status (None or 0 is success)."""
    fn = _scanner(name)
    if fn is None:
        msg = "python engine has not ported %s yet" % name
        record_warn(args[0], msg)
        note_l5_partial(msg)
        return 3
    return fn(*args)


# ── Shebang routing (what scan_unknown does with the first line) ────────────
def first_line(path):
    """`IFS= read -r first_line < file`: the first line, NULs dropped, as latin-1 text (one character is one byte, like the C
    locale of the shell). An unreadable file has an empty first line."""
    out = b""
    try:
        with open(path, "rb") as fh:
            while b"\n" not in out:
                chunk = fh.read(65536)
                if not chunk:
                    break
                out += chunk.replace(b"\x00", b"")
    except OSError:
        pass
    return out.split(b"\n", 1)[0].decode("latin-1")


def _words(text):
    return [w for w in re.split("[ \t]+", text) if w]               # IFS=$' \t' read -r -a


def _shebang_interpreter_line(first):
    """A shebang line reduced to the interpreter it names: `#!/usr/bin/env -S python3 -u` -> `#!/usr/bin/env python3`. The
    line is hostile text: it is split into words and only compared, never run."""
    line = first[:1024]
    if not line.startswith("#!"):
        return first
    if line.endswith("\r"):
        line = line[:-1]
    words = _words(line[2:])
    if not words:
        return first
    result = "#!" + words[0]
    if words[0].rsplit("/", 1)[-1] == "env":
        i, skip, cmd = 1, False, ""
        while i < len(words):
            w = words[i]
            i += 1
            if skip:
                skip = False
                continue
            more = []
            if w.startswith("--split-string="):
                more = _words(w[len("--split-string="):])
            elif w in ("-u", "-C", "--unset", "--chdir"):
                skip = True
                continue
            elif w.startswith(("--unset=", "--chdir=")) or w.startswith("--"):
                continue
            elif w.startswith("-") and len(w) > 1:
                opts = w[1:]
                for n, ch in enumerate(opts):            # the first of S, u, C ends the cluster
                    if ch == "S":
                        more = _words(opts[n + 1:])
                        break
                    if ch in "uC":
                        skip = skip or n + 1 == len(opts)
                        break
                if not more:
                    continue
            elif w == "-" or "=" in w:
                continue
            else:
                cmd = w
                break
            if more:                                     # the split string stands where the option stood
                words = words[:i] + more + words[i:]
        cmd = cmd[1:] if cmd[:1] in ("'", '"') else cmd
        cmd = cmd[:-1] if cmd[-1:] in ("'", '"') else cmd
        if cmd:
            result = "#!%s %s" % (words[0], cmd)
    return result


def shebang_scanner(first):
    """The scanner function a first line routes to (`scan_python`, `scan_shell` ...), or None."""
    line = _shebang_interpreter_line(first)
    if not line.startswith("#!"):
        return None
    body = line[2:]
    if "python" in body:
        return "scan_python"
    if body.endswith(("/bash", "/sh", "env bash", "env sh", "/zsh", "/ksh")):
        return "scan_shell"
    for word, scanner in (("ruby", "scan_ruby"), ("node", "scan_javascript"), ("php", "scan_php")):
        if word in body:
            return scanner
    if "pwsh" in body or "powershell" in body:
        return "scan_powershell"
    return None


# ── grep helpers ────────────────────────────────────────────────────────────
# -e is not optional: a pattern that begins with a dash is otherwise read as options, grep exits 2, and the rule is
# silently inert. `--` ends the options before the path for the same reason.
def _status(argv):
    try:
        return _rc(subprocess.call(_argv(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    except OSError:
        return 127


def grep_pipe(argv1, argv2, tr=None):
    """`argv1 | [tr] | argv2 >/dev/null` under pipefail: True when both ended with status 0."""
    G.LM_FILE = ""
    try:
        p1 = subprocess.Popen(_argv(argv1), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(_argv(argv2), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return False
    dead = False
    while True:
        chunk = p1.stdout.read(65536)
        if not chunk:
            break
        if not dead:
            try:
                p2.stdin.write(chunk.translate(tr) if tr else chunk)
            except OSError:
                dead = True                      # keep draining p1 so that it can finish
    try:
        p2.stdin.close()
    except OSError:
        pass
    p1.stdout.close()
    return p1.wait() == 0 and p2.wait() == 0


def grep_check(pattern, path):
    if _status(["grep", "-qE", "-e", pattern, "--", path]) == 0:
        _lm_add(path, "E", pattern)
        return True
    G.LM_FILE = ""
    return False


def grep_check_i(pattern, path):
    if _status(["grep", "-qiE", "-e", pattern, "--", path]) == 0:
        _lm_add(path, "iE", pattern)
        return True
    G.LM_FILE = ""
    return False


def grep_check_excl(pattern, excl, path):
    """The pattern on a line that does not also match the exclusion; both greps read the file as text (-a)."""
    if grep_pipe(["grep", "-ahiE", "-e", pattern, "--", path], ["grep", "-aviE", "-e", excl]):
        _lm_add(path, "X", pattern, excl)
        return True
    G.LM_FILE = ""
    return False


def grep_flat(pattern, path):
    """The pattern over the file as one record (-z), for constructs that can be split across lines. A grep that could not run
    to the end is neither a match nor a clean file: the FAIL engine:search_incomplete on the file, once, and G.FLAT_INCOMPLETE."""
    rc = _status(["grep", "-ziE", "-e", pattern, "--", path])
    if rc <= 1:
        if rc == 0:
            _lm_add(path, "Z", pattern)
        else:
            G.LM_FILE = ""
        return rc == 0
    G.LM_FILE = ""
    subject = G.FLAT_FILE or path
    warn("grep_flat: the search of %s could not be completed (grep exit %d)" % (subject, rc))
    G.FLAT_INCOMPLETE = True
    if "engine:search_incomplete" not in FINDINGS.get(subject, ""):
        record_fail_hard(subject, "engine:search_incomplete")
    return False


def grep_rules(f, rows):
    """A table of (level, pattern, message[, 'i']) rows over one file: `level` is 'fail' or 'warn', 'i' is the case-insensitive
    grep. -> True when a FAIL was recorded (the scanner then records no PASS, even if the FAIL was lowered to a WARN)."""
    failed = False
    for row in rows:
        level, pattern, message = row[:3]
        if (grep_check_i if len(row) > 3 else grep_check)(pattern, f):
            if level == "fail":
                record_fail(f, message)
                failed = True
            else:
                record_warn(f, message)
    return failed


# ── Known credential formats ────────────────────────────────────────────────
KNOWN_CRED_NAMES = (
    "aws_access_key_id", "aws_secret_access_key", "github_token", "github_fine_grained_pat",
    "gitlab_pat", "stripe_live_key", "slack_token", "google_api_key", "google_oauth_token",
    "sendgrid_key", "npm_token", "pypi_token", "huggingface_token", "anthropic_key",
    "openai_project_key", "openai_legacy_key", "shopify_token", "digitalocean_token",
)
KNOWN_CRED_PATS = (
    r'(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}',
    r'''[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy][[:space:]]*["']?[[:space:]]*[=:][[:space:]]*["']?[A-Za-z0-9/+=]{40}''',
    r'gh[pousr]_[A-Za-z0-9]{36,255}',
    r'github_pat_[A-Za-z0-9_]{50,}',
    r'glpat-[A-Za-z0-9_-]{20,}',
    r'[sr]k_live_[A-Za-z0-9]{24,}',
    r'xox[bpars]-[0-9]{8,14}-[0-9]{8,14}(-[0-9]{8,14})?-[A-Za-z0-9]{20,}',
    r'AIza[0-9A-Za-z_-]{35}',
    r'ya29\.[0-9A-Za-z_-]{30,}',
    r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    r'npm_[A-Za-z0-9]{36}',
    r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}',
    r'hf_[A-Za-z0-9]{34,}',
    r'sk-ant-(api|admin)[0-9]{2}-[A-Za-z0-9_-]{60,}',
    r'sk-proj-[A-Za-z0-9_-]{40,}',
    r'sk-[A-Za-z0-9]{48}',
    r'shp(at|ca|pa|ss)_[a-f0-9]{32}',
    r'dop_v1_[a-f0-9]{64}',
)
KNOWN_CRED_ALL = "|".join("(^|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|$)" % p for p in KNOWN_CRED_PATS)
KNOWN_CRED_EXCL = (r"EXAMPLE|SAMPLE|DUMMY|PLACEHOLDER|YOUR|REDACTED|FAKE|CHANGEME|x{6,}|0{10,}|\*{3,}|\.{3}|1234567890|abcdefgh|"
                   r"([A-Za-z0-9])\1{9,}|ghp_16C7e42F" "292c6912E7710c838347Ae178B4a")
_JWT = r"(^|[^A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}([^A-Za-z0-9]|$)"


def _known_cred_check(report, target):
    """Known credential formats (grep -I: a binary file is skipped) and the JWT warning. $1 is the file a finding is recorded
    against, $2 the file that is searched. -> True only if it recorded a FAIL."""
    hit = False
    if _status(["grep", "-qIE", "-e", KNOWN_CRED_ALL, "--", target]) == 0:
        for name, pat in zip(KNOWN_CRED_NAMES, KNOWN_CRED_PATS):
            token_rx = "(^|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|$)" % pat
            if grep_pipe(["grep", "-ohIE", "-e", token_rx, "--", target], ["grep", "-viE", "-e", KNOWN_CRED_EXCL]):
                G.LM_FILE = ""
                _lm_add(target, "T", token_rx)
                record_fail(report, "CWE-798:known_credential_format_%s" % name)
                hit = True
    if _status(["grep", "-qIE", "-e", _JWT, "--", target]) == 0:
        record_warn(report, "CWE-798:jwt_embedded_review_whether_it_is_a_live_credential")
    return hit
