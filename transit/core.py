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
)

DEFAULT_EXCLUDE_DIRS = ("node_modules", ".git", "vendor", ".tox", "__pycache__", ".venv", "venv",
                        "dist", "build", ".next", ".nuxt", ".cache", "target", "coverage")

FINDINGS = {}        # path -> concatenated FAIL messages
FILE_STATUS = {}     # path -> PASS | FAIL | WARN
FILE_MSG = {}        # path -> "[WARN] message | [FAIL] message | ..."
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


# ── Layer coverage ──────────────────────────────────────────────────────────
def record_layer(layer, state):
    LAYER_COVERAGE[layer] = state


def note_l5_partial(reason):
    if ("; %s; " % reason) not in ("; %s; " % G.L5_PARTIAL):
        G.L5_PARTIAL += ("; " if G.L5_PARTIAL else "") + reason


# ── Verdict helpers ─────────────────────────────────────────────────────────
def record_pass(file=""):
    G.PASS_COUNT += 1
    if file and not FILE_STATUS.get(file):
        FILE_STATUS[file] = "PASS"
        FILE_MSG[file] = ""


def record_warn(file="__global__", *msg):
    file = file or "__global__"
    text = " ".join(msg)
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


def _write_finding(tool, category, severity, rule_id, rule_name, file, line, column, message, refs=""):
    def clean(x):
        return _b(x).decode("utf-8", "replace")
    rec = dict(tool=clean(tool), category=clean(category), severity=clean(severity), rule_id=clean(rule_id),
               rule_name=clean(rule_name), file=clean(file),
               line=int(line) if line.isdigit() else None, column=int(column) if column.isdigit() else None,
               message=clean(message), references=clean(refs).split(",") if refs else [])
    try:
        with open(G.FINDINGS_JL, "a", encoding="ascii") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


_TOOL_RULE = re.compile(r"^([a-z][a-z0-9_-]{1,30}):([^:]+)")
_LINE_NO = re.compile(r":line([0-9]+)")


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
    m = _LINE_NO.search(msg)
    line = m.group(1) if m else ""
    rule_name = rule_name or msg
    tool = tool or "unknown"
    rel = file[len(G.SCAN_DIR) + 1:] if file.startswith(G.SCAN_DIR + "/") else file
    if rel == G.SCAN_DIR:
        rel = "."
    _write_finding(tool, category, sev_name, rule_id, rule_name, rel, line, "", msg, refs)


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
    return _status(["grep", "-qE", "-e", pattern, "--", path]) == 0


def grep_check_i(pattern, path):
    return _status(["grep", "-qiE", "-e", pattern, "--", path]) == 0


def grep_check_excl(pattern, excl, path):
    """The pattern on a line that does not also match the exclusion; both greps read the file as text (-a)."""
    return grep_pipe(["grep", "-ahiE", "-e", pattern, "--", path], ["grep", "-aviE", "-e", excl])


def grep_flat(pattern, path):
    """The pattern over the file as one record (-z), for constructs that can be split across lines. A grep that could not run
    to the end is neither a match nor a clean file: the FAIL engine:search_incomplete on the file, once, and G.FLAT_INCOMPLETE."""
    rc = _status(["grep", "-ziE", "-e", pattern, "--", path])
    if rc <= 1:
        return rc == 0
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
            if grep_pipe(["grep", "-ohIE", "-e", "(^|[^A-Za-z0-9])(%s)([^A-Za-z0-9]|$)" % pat, "--", target],
                         ["grep", "-viE", "-e", KNOWN_CRED_EXCL]):
                record_fail(report, "CWE-798:known_credential_format_%s" % name)
                hit = True
    if _status(["grep", "-qIE", "-e", _JWT, "--", target]) == 0:
        record_warn(report, "CWE-798:jwt_embedded_review_whether_it_is_a_live_credential")
    return hit
