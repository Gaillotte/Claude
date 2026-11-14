#!/usr/bin/env python3
"""Python engine of the AI Transit Pipeline: scan_pipeline.sh in Python, calling the same external tools.

    python3 -I scan_pipeline.py <directory_to_scan> [directory_for_report] [scanning_name]

The same functions in the same order and with the same names and messages as scan_pipeline.sh (docs/python_port_thin_plan.md,
docs/engine_contract.md): the arguments, .transit-allow.json, diff mode, .transitignore, the file listing, classify_file,
scan_by_type, the reports and the sidecars. What the scan_* functions share is in transit/core.py; the scanners are in
transit/scan_*.py and layers 1 to 3 and 6 in transit/layers.py. Standard library only, Python 3.10 or newer.
"""
import os
import re
import signal
import sys
import tempfile
import time
from fnmatch import fnmatchcase

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))       # `python3 -I` does not put it there

from transit.core import (ALLOW_MAP, DEFAULT_EXCLUDE_DIRS, FILE_MSG, FILE_STATUS, FINDINGS, G, LAYER_COVERAGE, _ascii_lower,
                          _b, _clr, _s, _san, call_scanner, cleanup_tmp, fail, first_line, has_cmd, info, init_offline_env,
                          ok, record_fail, record_fail_hard, record_layer, record_warn, register_tmp, run_helper, run_tool,
                          shebang_scanner, warn)

_FIND_BIG = 2 << 30


# ── Arguments ────────────────────────────────────────────────────────────────
def parse_args(argv):
    """Three positional arguments (words that start with -- are not arguments), checked before anything is written."""
    pos = [a for a in argv if not a.startswith("--")]
    if len(pos) < 1:
        fail("Usage: %s <directory_to_scan> [directory_for_report] [scanning_name]  [VERBOSITY=quiet|normal|verbose]" % sys.argv[0])
    scan_dir = pos[0]
    if not os.path.isdir(scan_dir):
        fail("Directory not found: %s" % scan_dir)
    # A trailing slash must not change the paths in findings or the keys an allowlist entry is matched on.
    while scan_dir != "/" and scan_dir.endswith("/"):
        scan_dir = scan_dir[:-1]
    report_dir = pos[1] if len(pos) > 1 else ""
    if report_dir and not os.path.isdir(report_dir):
        fail("Directory not found: %s" % report_dir)
    name = pos[2] if len(pos) > 2 else ""
    if "/" in name or name.startswith(".") or re.search(rb"[\x00-\x1f\x7f]", _b(name)) or len(_b(name)) > 150:
        fail("scanning_name must not contain '/', control characters or a leading dot, and is limited to 150 characters: %s" % name)
    G.SCAN_DIR, G.REPORT_DIR, G.SCANNING_NAME = scan_dir, report_dir, name or G.TIMESTAMP


# ── .transit-allow.json ──────────────────────────────────────────────────────
def load_allowlist():
    """[{"rule", "path", "reason"}] -> ALLOW_MAP["rule::path"] = reason, read the way the shell reads it: a non-string member
    ends the list, a newline in a reason cuts it, a parse error or a non-array is an empty allowlist."""
    import json
    path = G.SCAN_DIR + "/.transit-allow.json"
    if not os.path.isfile(path):
        return
    info("Allowlist found: %s" % path)
    lines = []
    try:
        with open(path, encoding="utf-8") as fh:
            entries = json.load(fh)
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                parts = (entry.get("rule", ""), entry.get("path", ""), entry.get("reason", ""))
                if not all(isinstance(x, str) for x in parts):
                    break
                line = "\x01".join(parts)
                line.encode("utf-8", "surrogateescape")
                lines.append(line)
    except Exception:
        pass
    for line in "\n".join(lines).replace("\x00", "").split("\n") if lines else []:
        fields = line.split("\x01", 2)
        rule, apath, reason = (fields + ["", ""])[:3]
        if len(fields) == 3 and reason.endswith("\x01") and reason.count("\x01") == 1:
            reason = reason[:-1]
        if rule:
            ALLOW_MAP["%s::%s" % (rule, apath)] = reason
    info("Allowlist: %d exception(s) loaded" % len(ALLOW_MAP))


# ── Diff mode ────────────────────────────────────────────────────────────────
def load_diff_files():
    """DIFF_FILES_ONLY when WORK_DIR/.diff_files exists and SINCE_COMMIT is set; NUL-separated names, or the old colon list."""
    path = G.WORK_DIR + "/.diff_files"
    since = os.environ.get("SINCE_COMMIT", "")
    if os.path.isfile(path) and not since:
        warn("Ignoring %s: SINCE_COMMIT is not set, so this is not a diff-mode run" % path)
    elif os.path.isfile(path):
        G.DIFF_FILES_ONLY = True
        with open(path, "rb") as fh:
            data = fh.read()
        if b"\x00" in data:
            names = [_s(n) for n in data.split(b"\x00") if n]
            names = [G.SCAN_DIR + "/" + n for n in names]
        else:
            names = [_s(n) for n in data.split(b":")[:-1]]      # each entry ends with ':'; the last one without it is dropped
        for n in names:
            if os.path.isfile(n):
                G.DIFF_FILES_SET.add(n)
        info("Diff mode: %d file(s) will be scanned" % len(G.DIFF_FILES_SET))


# ── .transitignore and the find prune arguments ─────────────────────────────
def load_transitignore():
    path = G.SCAN_DIR + "/.transitignore"
    if not os.path.isfile(path):
        return
    info(".transitignore found — loading exclusions")
    with open(path, "rb") as fh:
        data = fh.read().replace(b"\x00", b"")
    for line in data.split(b"\n"):
        pattern = _s(line[:-1] if line.endswith(b"\r") else line)
        if pattern and not pattern.startswith("#"):
            G.EXTRA_EXCLUDE_DIRS.append(pattern)


def build_prune_args():
    """-> (prune arguments with the .transitignore entries, the built-in ones alone). Anchored on the scan root, which is
    glob-escaped because find -path reads \\ * ? [ in the pattern."""
    root = "" if G.SCAN_DIR == "/" else G.SCAN_DIR
    for ch in ("\\", "*", "?", "["):
        root = root.replace(ch, "\\" + ch)
    args = []
    for d in DEFAULT_EXCLUDE_DIRS:              # built-in names are directories: a regular file called build is scanned
        args += ["-type", "d", "(", "-path", "%s/%s" % (root, d), "-o", "-path", "%s/*/%s" % (root, d), ")", "-prune", "-o"]
    builtin = list(args)
    for d in G.EXTRA_EXCLUDE_DIRS:              # .transitignore entries may name a file or a directory
        args += ["(", "-path", "%s/%s" % (root, d), "-o", "-path", "%s/*/%s" % (root, d), ")", "-prune", "-o",
                 "-path", "%s/%s/*" % (root, d), "-prune", "-o", "-path", "%s/*/%s/*" % (root, d), "-prune", "-o"]
    return args, builtin


# ── Layers 1 to 3 and 6: transit/layers.py, or an explicit "not ported" ─────
def _unported(layer_fn, header, rows):
    """What a layer records until transit/layers.py has it: the same WARN and state as the shell when the tool is not
    installed, and an explicit 'not ported' (never 'not installed', never ran) when it is."""
    info(header)
    for tool, present, layer, missing_warn, missing_state in rows:
        if present:
            record_warn("__global__", "python engine has not ported %s yet" % layer_fn)
            record_layer(layer, "skipped:python engine has not ported %s yet" % layer_fn)
        else:
            record_warn("__global__", missing_warn)
            record_layer(layer, missing_state)


def _unported_scan_global():
    yara = has_cmd("yara") and os.path.isdir(G.WORK_DIR + "/yara-rules")
    _unported("scan_global", "=== Layer 1: Global (AV, secrets, IOC) ===", (
        ("gitleaks", has_cmd("gitleaks"), "L1_secrets_gitleaks", "gitleaks missing — secret scan skipped",
         "skipped:gitleaks not installed"),
        ("detect-secrets", has_cmd("detect-secrets"), "L1_secrets_entropy", "detect-secrets missing",
         "skipped:detect-secrets not installed"),
        ("clamscan", has_cmd("clamscan"), "L1_malware", "clamscan missing", "skipped:clamav not installed"),
        ("yara", yara, "L1_ioc_yara", "yara or rules directory missing", "skipped:yara or rules directory missing")))


def _unported_scan_owasp_cwe():
    _unported("scan_owasp_cwe", "=== Layer 2: OWASP Top 10 2021 + CWE Top 25 (Semgrep) ===", (
        ("semgrep", has_cmd("semgrep"), "L2_owasp_cwe", "semgrep missing — OWASP/CWE layer skipped (pip install semgrep)",
         "skipped:semgrep not installed"),))


def _unported_scan_dependencies():
    _unported("scan_dependencies", "=== Layer 3: SCA — Vulnerable dependencies (OWASP A06) ===", (
        ("trivy", has_cmd("trivy"), "L3_dependency_cve", "trivy missing — dependency CVE scan skipped",
         "skipped:trivy not installed"),))


def _unported_scan_scancode():
    _unported("scan_scancode", "=== Layer 6: ScanCode — licence, copyright & vulnerability ===", (
        ("scancode", has_cmd("scancode"), "L6_licence",
         "scancode missing — licence/copyright layer skipped (pip install scancode-toolkit)", "skipped:scancode not installed"),))


def _layer(name, fallback):
    import importlib
    try:
        fn = getattr(importlib.import_module("transit.layers"), name, None)
    except ModuleNotFoundError as exc:
        if exc.name != "transit.layers":
            warn("transit/layers.py could not be imported: %s" % exc)
        fn = None
    except Exception as exc:
        warn("transit/layers.py could not be imported: %s: %s" % (type(exc).__name__, exc))
        fn = None
    return fn or fallback


# ── Classification ───────────────────────────────────────────────────────────
def _read_head(path, n):
    """The first n bytes without their NULs (bash `read -N` drops them and does not count them)."""
    out = b""
    try:
        with open(path, "rb") as fh:
            while len(out) < n:
                chunk = fh.read(65536)
                if not chunk:
                    break
                out += chunk.replace(b"\x00", b"")
    except OSError:
        pass
    return out[:n]


def _rtf_head(f):
    """Word opens an RTF whatever the file is called: it must START with {\\rtf."""
    return _read_head(f, 16).lstrip(b" \t\n\v\f\r").startswith(b"{\\rtf")


def _flat_office_head(f):
    h = _read_head(f, 8192)
    return (b"schemas.microsoft.com/office/2006/xmlPackage" in h or b"schemas.microsoft.com/office/word/2003/wordml" in h
            or b"urn:schemas-microsoft-com:office:spreadsheet" in h)


_BASENAME_RULES = (
    (("Dockerfile*",), "scan_docker"),
    (("Makefile*", "makefile*", "GNUmakefile*"), "scan_makefile"),
    (("CMakeLists.txt", "CMakeLists.*.txt"), "scan_cmake"),
    (("package.json", "composer.json"), "scan_package_json"),
    (("requirements*.txt", "constraints*.txt"), "scan_requirements"),
    (("gradle.properties", "gradle-wrapper.properties", "*.gradle", "*.gradle.kts"), "scan_gradle"),
    (("setup.py", "conanfile.py"), "scan_setup_py"),
)
_OFFICE = (".docx .docm .dotx .dotm .xlsx .xlsm .xlsb .xltx .xltm .xlam .pptx .pptm .ppsx .ppsm .potx .potm .ppam "
           ".doc .dot .xls .xlt .xla .ppt .pot .pps .ppa .odt .ods .odp .odg .ott .ots .otp .otg .fodt .fods .fodp .fodg .rtf")
_EXT_RULES = (
    (".py", "scan_python"), (".js .ts .jsx .tsx .mjs .cjs", "scan_javascript"), (".java", "scan_java"), (".php", "scan_php"),
    (".rb", "scan_ruby"), (".go", "scan_go"), (".c .cpp .h .hpp .cc", "scan_c_cpp"), (".sh .bash .zsh .ksh", "scan_shell"),
    (".ps1 .psm1 .psd1 .pssc .psrc", "scan_powershell"), (".ps1xml .psc1 .cdxml", "scan_powershell_xml"),
    (".bat .cmd", "scan_bat"), (".rs", "scan_rust"), (".kt .kts", "scan_kotlin"), (".cs", "scan_csharp"),
    (".yml .yaml", "scan_yaml"), (".tf .tfvars .hcl", "scan_terraform"), (".so .dll .dylib .exe .elf .bin", "scan_binary"),
    (".zip .tar .gz .tgz .bz2 .xz", "scan_archive"), (".jar .war .ear .aar", "scan_jar"), (_OFFICE, "scan_office"),
    (".pdf", "scan_pdf"), (".mk .mak .make", "scan_makefile"), (".html .htm .xhtml", "scan_html"), (".cmake", "scan_cmake"),
    (".sql", "scan_sql"), (".json", "scan_json"),
)
_EXT_SCANNER = {e: scanner for exts, scanner in _EXT_RULES for e in exts.split()}


def _handled(rc):
    return rc is None or rc == 0


def classify_file(f):
    """Layer 4 on every file, then the scanner its basename, extension (lower-cased) or first bytes call for."""
    base = os.path.basename(f).rstrip("\n")                  # `$(basename)` drops trailing newlines
    ext = _ascii_lower(f.rsplit(".", 1)[-1] if "." in f else f)

    call_scanner("scan_universal_patterns", f)

    for patterns, scanner in _BASENAME_RULES:
        if any(fnmatchcase(base, p) for p in patterns):
            call_scanner(scanner, f)
            return

    dotext = "." + ext
    if dotext in (".xml", ".pom"):
        call_scanner("scan_xml", f)
        # Word and Excel open a Flat OPC package or a 2003 XML document from a .xml
        if _flat_office_head(f):
            call_scanner("scan_office", f, "sniffed")
    elif dotext in _EXT_SCANNER:
        call_scanner(_EXT_SCANNER[dotext], f)
    elif dotext in (".md", ".txt", ".rst"):
        if not (_rtf_head(f) and _handled(call_scanner("scan_office", f, "sniffed"))):   # Word opens an RTF whatever it is called
            call_scanner("scan_doc", f)
    elif not (_rtf_head(f) and _handled(call_scanner("scan_office", f, "sniffed"))):
        # an extensionless script is routed by its shebang, anything else goes to the MIME check of scan_unknown
        call_scanner(shebang_scanner(first_line(f)) or "scan_unknown", f)


# ── Layer 5: per-type scan ───────────────────────────────────────────────────
def _is_control_file(f):
    """The three files the pipeline puts at the root of a scanned directory: scanned like any file, but they do not count as
    "something was examined"."""
    root = G.SCAN_DIR[:-1] if G.SCAN_DIR.endswith("/") else G.SCAN_DIR
    return f in (root + "/.transitignore", root + "/.transit-allow.json", root + "/.manifest_sha256.txt")


def _symlink_escapes(link, target):
    """Does a symlink point out of the scanned directory? The target text is read, not followed."""
    if target.startswith("/"):
        return True
    root = G.SCAN_DIR[:-1] if G.SCAN_DIR.endswith("/") else G.SCAN_DIR
    rel = link[len(root) + 1:] if link.startswith(root + "/") else link
    depth = rel.rsplit("/", 1)[0].count("/") + 1 if "/" in rel else 0
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def _find_list(prune_args):
    """`find SCAN_DIR <prune> -type f -print0` written to a file so that its exit status is read -> (status, [paths])."""
    fd, tmp = tempfile.mkstemp(prefix="filelist_", dir=G.WORK_DIR)
    register_tmp(tmp)
    try:
        with os.fdopen(fd, "wb") as fh:
            rc, _ = run_tool(["find", G.SCAN_DIR] + prune_args + ["-type", "f", "-print0"], stdout_file=fh)
        with open(tmp, "rb") as fh:
            names = [_s(n) for n in fh.read().split(b"\x00") if n]
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return rc, [n for n in names if n != tmp]


def scan_by_type(prune_args, prune_builtin_args):
    info("=== Layer 5: Per-type SAST ===")
    list_rc, listed = _find_list(prune_args)
    scan_files, scanned_real = [], 0
    for f in listed:
        if not os.path.isfile(f):
            continue
        if G.DIFF_FILES_ONLY and f not in G.DIFF_FILES_SET:           # diff mode: only the changed files
            continue
        scan_files.append(f)
        if not _is_control_file(f):
            scanned_real += 1

    # Symlinks are not files to this scan and nothing follows them: a link that leaves the scanned directory is a FAIL, any
    # other is a WARN, so that none passes unseen.
    _, raw = run_tool(["find", G.SCAN_DIR] + prune_args + ["-type", "l", "-printf", "%p\\0%l\\0"], max_output=_FIND_BIG)
    parts = raw.split(b"\x00")
    for i in range(0, len(parts) - 1, 2):
        link, target = _s(parts[i]), _s(parts[i + 1])
        if _symlink_escapes(link, target):
            record_fail(link, "symlink:target_outside_the_scanned_directory")
        else:
            record_warn(link, "symlink:not_followed_its_target_is_not_scanned_through_the_link")

    # Two ways to have examined nothing although the repository has files, both fail-closed: the listing itself failed, or
    # .transitignore removed every file. Only the .transitignore patterns count (an empty repository keeps its behaviour).
    nothing_scanned = False
    if list_rc != 0:
        warn("the file listing of %s did not complete (find exit %d): files may have been missed" % (G.SCAN_DIR, list_rc))
        record_fail_hard("__global__", "engine:file_listing_failed")
    elif scanned_real == 0 and G.EXTRA_EXCLUDE_DIRS:
        _, everything = _find_list(prune_builtin_args)
        if any(not _is_control_file(f) and (not G.DIFF_FILES_ONLY or f in G.DIFF_FILES_SET) for f in everything):
            nothing_scanned = True
            warn(".transitignore removed every file from the scan (%d pattern(s)): nothing was examined" % len(G.EXTRA_EXCLUDE_DIRS))
            record_fail_hard("__global__", "engine:nothing_scanned")

    total, current = len(scan_files), 0
    for f in scan_files:
        current += 1
        # the live progress line is drawn only on a terminal, and its text is the repository's: sanitised, then cut
        if G.VERBOSITY != "quiet" and os.isatty(2):
            short = f[len(G.SCAN_DIR) + 1:] if f.startswith(G.SCAN_DIR + "/") else f
            sys.stderr.buffer.write(_b("\r\x1b[K\x1b[34m[L5]\x1b[0m  [%*d/%d] %s" % (len(str(total)), current, total, _san(short)[:80])))
            sys.stderr.buffer.flush()
        classify_file(f)

    _clr()
    ok("Layer 5: %d files scanned" % current)
    if list_rc != 0:
        state = "skipped:file listing failed (find exit %d)" % list_rc
        record_layer("L4_patterns", state)
        record_layer("L5_per_language_sast", state)
    elif nothing_scanned:
        record_layer("L4_patterns", "skipped:nothing scanned (every file excluded)")
        record_layer("L5_per_language_sast", "skipped:nothing scanned (every file excluded)")
    else:
        record_layer("L4_patterns", "ran")
        record_layer("L5_per_language_sast", "partial:%s" % G.L5_PARTIAL if G.L5_PARTIAL else "ran")


# ── Reports ──────────────────────────────────────────────────────────────────
def _batches(names, limit=100000):
    batch, size = [], 0
    for n in names:
        if batch and size + len(n) > limit:
            yield batch
            batch, size = [], 0
        batch.append(n)
        size += len(n) + 1
    if batch:
        yield batch


def _hashes():
    """repo_hash (the sorted list of paths) and source.sha256 (every file's own SHA-256, in a fixed order; the repo_hash if
    any step of the pipeline failed). A find that fails is fatal to the run, as `set -e` made it in the shell."""
    rc, out = run_tool(["find", G.SCAN_DIR, "-type", "f"], max_output=_FIND_BIG)
    if rc != 0:
        fail("find over %s ended with status %d: no report" % (G.SCAN_DIR, rc))
    lines = out.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    rc, h = run_tool(["sha256sum"], input=b"".join(ln + b"\n" for ln in sorted(lines)))
    if rc != 0 or not h.split():
        fail("sha256sum ended with status %d: no report" % rc)
    repo_hash = _s(h.split()[0])

    content_hash = ""
    rc, out = run_tool(["find", ".", "-type", "f", "-print0"], cwd=G.SCAN_DIR, max_output=_FIND_BIG)
    if rc == 0:
        names = sorted(n for n in out.split(b"\x00") if n)
        sums, good = [], True
        for batch in _batches(names):
            rc, part = run_tool(["sha256sum", "--"] + batch, cwd=G.SCAN_DIR, max_output=_FIND_BIG)
            good = good and rc == 0
            sums.append(part)
        if good:
            rc, h = run_tool(["sha256sum"], input=b"".join(sums))
            content_hash = _s(h.split()[0]) if rc == 0 and h.split() else ""
    return repo_hash, content_hash or repo_hash


def generate_report_json():
    """The data goes to temporary files and the report writer is the helper program the shell runs."""
    tmp = tempfile.mkdtemp(prefix="tmp.", dir=os.environ.get("TMPDIR") or None)
    register_tmp(tmp)

    def stream(name, items):
        path = os.path.join(tmp, name)
        with open(path, "wb") as fh:
            for x in items:
                fh.write(_b(x) + b"\x00")
        return path

    def strip_sep(text):
        return text[:-3] if text.endswith(" | ") else text

    paths = list(FILE_STATUS)
    args = [stream("fk", FINDINGS), stream("fv", [strip_sep(v) for v in FINDINGS.values()]),
            stream("sk", paths), stream("ss", [FILE_STATUS[p] for p in paths]), stream("sm", [FILE_MSG.get(p, "") for p in paths]),
            stream("ck", LAYER_COVERAGE), stream("cv", LAYER_COVERAGE.values())]
    repo_hash, content_hash = _hashes()
    env = dict(REPORT_VERDICT=G.GLOBAL_VERDICT, REPORT_TS=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               REPORT_REPO_INPUT=G.REPO_INPUT, REPORT_SCAN_DIR=G.SCAN_DIR, REPORT_SCANNING_NAME=G.SCANNING_NAME,
               REPORT_HASH=repo_hash, REPORT_CONTENT_HASH=content_hash, REPORT_RUN_SCA=G.RUN_SCA,
               REPORT_RUN_SCANCODE=G.RUN_SCANCODE, REPORT_PASS=str(G.PASS_COUNT), REPORT_WARN=str(G.WARN_COUNT),
               REPORT_FAIL=str(G.FAIL_COUNT), REPORT_OUT=G.REPORT_JSON, REPORT_FINDINGS_JL=G.FINDINGS_JL)
    rc, out = run_helper("report_json.py", *args, env=env, merge_stderr=True)
    if rc != 0:
        fail("the JSON report could not be written (status %d): %s" % (rc, _s(out)[-400:]))


def _html_esc(s):
    """Everything the report prints about a file comes from the repository: & first, then < > " '."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def generate_report_html():
    colour = "#2ecc71" if G.GLOBAL_VERDICT == "PASS" else "#e74c3c"
    out = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
           "<title>AI Transit Report — %s</title>" % G.TIMESTAMP,
           """<style>
body{background:#0d1b2a;color:#eee;font-family:monospace;padding:2rem;max-width:1400px;margin:0 auto}
h1{color:%s} h2{color:#00a8ff}
table{border-collapse:collapse;width:100%%;margin-top:1rem}
th{background:#1f3864;padding:.6rem;text-align:left}
td{border:1px solid #334;padding:.5rem;vertical-align:top}
tr:nth-child(even){background:#16213e}
.pass{color:#2ecc71;font-weight:bold} .fail{color:#e74c3c;font-weight:bold} .warn{color:#f39c12;font-weight:bold}
.tag{background:#1f3864;border-radius:4px;padding:2px 6px;font-size:.85em;margin:1px;display:inline-block}
.owasp{background:#c0392b} .cwe{background:#2980b9} .cert{background:#27ae60}
</style></head><body>""" % colour,
           "<h1>Verdict: %s</h1>" % G.GLOBAL_VERDICT,
           "<p>Directory: <code>%s</code> | Date: %s</p>" % (_html_esc(G.SCAN_DIR), G.TIMESTAMP),
           "<p>Standards: <span class='tag owasp'>OWASP Top 10 2021</span>\n              <span class='tag cwe'>CWE Top 25</span>\n"
           "              <span class='tag cert'>CERT Secure Coding</span>%s</p>"
           % ("\n              <span class='tag'>SCA/CVE</span>" if G.RUN_SCA == "true" else ""),
           "<p>PASS: <span class='pass'>%d</span> |\n              WARN: <span class='warn'>%d</span> |\n"
           "              FAIL: <span class='fail'>%d</span></p>" % (G.PASS_COUNT, G.WARN_COUNT, G.FAIL_COUNT),
           "<h2>Results by file</h2>", "<table><tr><th>File</th><th>Status</th><th>Finding</th></tr>"]
    for path, status in FILE_STATUS.items():
        cls = {"PASS": "pass", "FAIL": "fail"}.get(status, "warn")
        out.append("<tr><td><code>%s</code></td><td class='%s'>%s</td><td>%s</td></tr>"
                   % (_html_esc(path), cls, status, _html_esc(FILE_MSG.get(path, ""))))
    out.append("</table></body></html>")
    with open(G.REPORT_HTML, "wb") as fh:
        fh.write(_b("\n".join(out) + "\n"))


# ── Main ─────────────────────────────────────────────────────────────────────
def main(argv):
    parse_args(argv)
    for tool in ("grep", "find", "sha256sum"):          # a scan without grep would read every rule as "no match"
        if not has_cmd(tool):
            fail("required program not found: %s" % tool)

    # Offline operation is the only mode.
    off = os.environ.get("OFFLINE") or "true"
    if off != "true":
        warn("OFFLINE=%s ignored: scan_pipeline.sh has no online mode" % off)
    info("Offline mode: no scanner will attempt a network call")
    init_offline_env()

    load_allowlist()
    load_diff_files()
    load_transitignore()
    prune_args, prune_builtin_args = build_prune_args()
    for d in list(DEFAULT_EXCLUDE_DIRS) + G.EXTRA_EXCLUDE_DIRS:
        G.SEMGREP_EXCLUDES += ["--exclude-dir", d]
        G.CLAMSCAN_EXCLUDES.append("--exclude-dir=" + d)

    try:
        for sub in ("reports", "quarantine", "approved"):
            os.makedirs("%s/%s" % (G.WORK_DIR, sub), exist_ok=True)
        os.chmod(G.WORK_DIR + "/quarantine", 0o700)
        fd, G.FINDINGS_JL = tempfile.mkstemp(prefix="findings_", suffix=".jsonl", dir=G.WORK_DIR)
        os.close(fd)
    except OSError as exc:
        fail("cannot prepare %s: %s" % (G.WORK_DIR, exc.strerror))
    register_tmp(G.FINDINGS_JL)
    if G.REPORT_DIR:
        G.REPORT_JSON = "%s/report_scan_%s.json" % (G.REPORT_DIR, G.SCANNING_NAME)
        G.REPORT_HTML = "%s/report_scan_%s.html" % (G.REPORT_DIR, G.SCANNING_NAME)
    else:
        G.REPORT_JSON = "%s/reports/report_%s.json" % (G.WORK_DIR, G.TIMESTAMP)
        G.REPORT_HTML = "%s/reports/report_%s.html" % (G.WORK_DIR, G.TIMESTAMP)

    info("Starting scan: %s" % G.SCAN_DIR)
    # Exclusions leave a trace: one WARN, with the number of patterns and nothing else from the file.
    if G.EXTRA_EXCLUDE_DIRS:
        record_warn("__global__", "transitignore:exclusions_applied(%d pattern(s))" % len(G.EXTRA_EXCLUDE_DIRS))
    info("Standards: OWASP Top 10 2021 · CWE Top 25 · CERT Secure Coding%s" % (" · SCA" if G.RUN_SCA == "true" else ""))

    _layer("scan_global", _unported_scan_global)()                 # Layer 1: AV + secrets + IOC
    _layer("scan_owasp_cwe", _unported_scan_owasp_cwe)()           # Layer 2: Semgrep OWASP/CWE rulesets
    if G.RUN_SCA == "true":
        _layer("scan_dependencies", _unported_scan_dependencies)()  # Layer 3: SCA
    else:
        info("Layer 3 (dependency CVEs) is disabled — set RUN_SCA=true to run it")
        record_layer("L3_dependency_cve", "skipped:disabled (RUN_SCA is not true)")
    # Layer 4: universal patterns run inside classify_file()
    scan_by_type(prune_args, prune_builtin_args)                   # Layer 5: per-language SAST
    if G.RUN_SCANCODE == "true":
        _layer("scan_scancode", _unported_scan_scancode)()         # Layer 6: ScanCode
    else:
        info("Layer 6 (ScanCode licences) is disabled — set RUN_SCANCODE=true to run it")
        record_layer("L6_licence", "skipped:disabled (RUN_SCANCODE is not true)")

    generate_report_json()
    generate_report_html()

    info("JSON report : %s" % G.REPORT_JSON)
    info("HTML report : %s" % G.REPORT_HTML)
    # The verdict and the report path go to sidecar files so that ai_transit.sh can read them reliably.
    with open(G.WORK_DIR + "/.scan_verdict", "wb") as fh:
        fh.write(_b(G.GLOBAL_VERDICT + "\n"))
    with open(G.WORK_DIR + "/.scan_report_json", "wb") as fh:
        fh.write(_b(G.REPORT_JSON + "\n"))
    sys.stdout.buffer.write(_b(G.GLOBAL_VERDICT + "\n"))
    sys.stdout.buffer.flush()
    # A verdict other than PASS is also the exit status, so a CI stage can gate on it.
    if G.GLOBAL_VERDICT != "PASS":
        sys.exit(1)


def _on_signal(signum, _frame):
    sys.exit(128 + signum)                      # the finally below removes the temporary files, like the shell's EXIT trap


if __name__ == "__main__":
    for _sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(_sig, _on_signal)
    try:
        main(sys.argv[1:])
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:                # an internal error aborts the run: exit 1, no verdict line, nothing printed raw
        where = exc.__traceback__
        while where is not None and where.tb_next is not None:
            where = where.tb_next
        sys.stderr.write("[FAIL]  internal error: %s: %s (%s:%s)\n" % (
            type(exc).__name__, _san(str(exc)), os.path.basename(where.tb_frame.f_code.co_filename) if where else "?",
            where.tb_lineno if where else "?"))
        sys.exit(1)
    finally:
        cleanup_tmp()
