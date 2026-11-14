"""Layers 1, 2, 3 and 6 of the Python engine: the tool layers of scan_pipeline.sh, in the same order, with the same messages,
coverage states, program arguments and offline flags. Every program is started with an argument list (core.run_tool), its
output is read and never printed, and a tool that could not run is a WARN and a coverage state, never "ran".

    scan_global        layer 1: gitleaks (_scan_gitleaks), detect-secrets, ClamAV, YARA
    scan_owasp_cwe     layer 2: Semgrep over the four staged rule files
    scan_dependencies  layer 3 (RUN_SCA=true): trivy on the staged database; the OFFLINE notes for pip-audit, safety, npm audit
    scan_scancode      layer 6 (RUN_SCANCODE=true): ScanCode, then the helper program that reads its report

The `python3 -c` snippets the shell pipes tool output through (the JSON shape checks of detect-secrets, Semgrep and trivy)
are run in-process, with the same checks. Offline is the only mode (docs/engine_divergences.md D-026): the pip-audit, safety
and npm audit branches the shell keeps for an online run cannot be reached there and are not ported; their OFFLINE notes are.
Standard library only.
"""
import glob
import json
import os
import shutil
import tempfile

from transit.core import (G, LAYER_COVERAGE, _s, fail, fail_f, has_cmd, info, ok, record_fail, record_layer, record_pass,
                          record_warn, register_tmp, run_helper, run_tool, warn)


# ── What the shell does for free ─────────────────────────────────────────────
def _subst(raw):
    """`$(...)`: NUL bytes are dropped and so is every trailing newline; a byte that is not UTF-8 stays as a surrogate."""
    return _s(raw.replace(b"\x00", b"").rstrip(b"\n"))


def _read(line, sep, n):
    """`IFS=sep read -r a b c ...` for n variables and a separator that is not white space: the first n-1 fields, then the
    rest of the line; the one separator that ends the last field is dropped, others are kept. -> n strings."""
    parts = line.split(sep, n - 1)
    if len(parts) == n and parts[-1].count(sep) == 1 and parts[-1].endswith(sep):
        parts[-1] = parts[-1][:-1]
    return parts + [""] * (n - len(parts))


def _quiet(argv, env=None):
    """`argv >/dev/null 2>&1`: -> exit status. The output of a tool is read from a file or not at all, never printed."""
    with open(os.devnull, "wb") as devnull:
        return run_tool(argv, env=env, stdout_file=devnull)[0]


def _basename(path):
    return os.path.basename(path).rstrip("\n")          # `$(basename ...)`


def _find_any(expr):
    """`find SCAN_DIR <expr> 2>/dev/null | sed -n '1,N p'` as a test for "did it print anything". Under `set -eo pipefail`
    a find that ends with a non-zero status ended the shell's run (no report), so it ends this one."""
    with tempfile.TemporaryFile(dir=G.WORK_DIR) as fh:
        rc, _ = run_tool(["find", G.SCAN_DIR] + expr, stdout_file=fh)
        fh.seek(0)
        found = bool(fh.readline().strip(b"\n"))
    if rc != 0:
        fail("find over %s ended with status %d: no report" % (G.SCAN_DIR, rc))
    return found


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — GLOBAL (malware, secrets, AV)
# ═══════════════════════════════════════════════════════════════════════════════
def _scan_gitleaks():
    """gitleaks on our terms, not the repository's: a generated config that only extends the built-in rules, the repository's
    ignore file and inline allow comments switched off, GITLEAKS_CONFIG* unset, the output to a report file and never to the
    console. Each leak (200 at most) is a FAIL with its file and line; the secret is redacted and never stored."""
    cap, n = 200, 0
    tmp = tempfile.mkdtemp(prefix="gitleaks_", dir=G.WORK_DIR)
    register_tmp(tmp)
    os.makedirs(tmp + "/noignore", exist_ok=True)
    with open(tmp + "/gitleaks.toml", "w") as fh:
        fh.write("[extend]\nuseDefault = true\n")
    opts = ["--no-git", "--source", G.SCAN_DIR, "--config", tmp + "/gitleaks.toml",
            "--report-format", "json", "--report-path", tmp + "/report.json"]
    _, out = run_tool(["gitleaks", "detect", "--help"], merge_stderr=True)
    help_text = _subst(out)
    for flag in ("--no-banner", "--redact"):
        if flag in help_text:
            opts.append(flag)
    if "--log-level" in help_text:
        opts += ["--log-level", "error"]
    if "--gitleaks-ignore-path" in help_text:
        opts += ["--gitleaks-ignore-path", tmp + "/noignore"]
    if "--ignore-gitleaks-allow" in help_text:
        opts.append("--ignore-gitleaks-allow")
    else:
        record_warn("__global__", "gitleaks:inline_allow_comments_not_disabled (this gitleaks has no --ignore-gitleaks-allow; upgrade it)")
    if os.path.exists(G.SCAN_DIR + "/.gitleaks.toml") or os.path.exists(G.SCAN_DIR + "/.gitleaksignore"):
        record_warn(G.SCAN_DIR, "gitleaks:repository_allowlist_ignored (.gitleaks.toml and .gitleaksignore are not honoured; use .transit-allow.json)")

    rc = _quiet(["gitleaks", "detect"] + opts, env={"GITLEAKS_CONFIG": None, "GITLEAKS_CONFIG_TOML": None})

    try:
        has_report = os.stat(tmp + "/report.json").st_size > 0
    except OSError:
        has_report = False
    if has_report:
        _, out = run_helper("tools/gitleaks.py", tmp + "/report.json")
        for record in out.split(b"\x00")[:-1]:                  # a last record with no NUL is not read, as `read -d ''`
            f, line, rule = _read(_s(record), "\x01", 3)
            if not f:
                continue
            n += 1
            if n > cap:
                continue
            if not f.startswith("/"):
                f = "%s/%s" % (G.SCAN_DIR, f)
            record_fail(f, "gitleaks:%s:line%s" % (rule, line))
        if n > cap:
            record_fail(G.SCAN_DIR, "gitleaks:more_leaks_not_listed_%d" % (n - cap))
    shutil.rmtree(tmp, ignore_errors=True)

    if rc == 0:
        record_pass(G.SCAN_DIR)
        ok("gitleaks: no secrets")
        record_layer("L1_secrets_gitleaks", "ran")
    elif rc == 1:
        # Exit 1 is "leaks found"; with no readable report that is all we know.
        if n == 0:
            record_fail(G.SCAN_DIR, "gitleaks:secrets_detected")
        record_layer("L1_secrets_gitleaks", "ran")
    else:
        # Anything else means gitleaks itself failed: fail closed, and say it did not run.
        record_fail(G.SCAN_DIR, "gitleaks:scan_error_exit_%d" % rc)
        record_layer("L1_secrets_gitleaks", "skipped:gitleaks failed (exit %d)" % rc)


def _detect_secrets_hits(text):
    """The number of secrets in detect-secrets' JSON, or None when the output is not that document."""
    try:
        return sum(len(v) for v in json.loads(text)["results"].values())
    except Exception:
        return None


def scan_global():
    info("=== Layer 1: Global (AV, secrets, IOC) ===")

    if has_cmd("gitleaks"):
        info("gitleaks…")
        _scan_gitleaks()
    else:
        record_warn("__global__", "gitleaks missing — secret scan skipped")
        record_layer("L1_secrets_gitleaks", "skipped:gitleaks not installed")

    if has_cmd("detect-secrets"):
        info("detect-secrets…")
        # A crash, or output that is not the JSON detect-secrets prints, is the layer not running (a WARN and a coverage
        # state), not "0 secrets". Whatever a failed run did print and could be read is still acted on.
        dsec_state = "ran"
        dsec_rc, out = run_tool(["detect-secrets", "scan", G.SCAN_DIR])
        dsec_hits = _detect_secrets_hits(_subst(out) + "\n")
        if dsec_rc != 0:
            record_warn("__global__", "detect-secrets:scan_error_exit_%d" % dsec_rc)
            dsec_state = "skipped:detect-secrets failed (exit %d)" % dsec_rc
        elif dsec_hits is None:
            record_warn("__global__", "detect-secrets:output_could_not_be_read")
            dsec_state = "skipped:detect-secrets output could not be read"
        if dsec_hits is not None and dsec_hits > 0:
            record_fail(G.SCAN_DIR, "detect-secrets:%d_high_entropy_string(s)" % dsec_hits)
        elif dsec_state == "ran":
            record_pass(G.SCAN_DIR)
            ok("detect-secrets: no secrets detected")
        record_layer("L1_secrets_entropy", dsec_state)
    else:
        record_warn("__global__", "detect-secrets missing")
        record_layer("L1_secrets_entropy", "skipped:detect-secrets not installed")

    if has_cmd("clamscan"):
        info("clamscan…")
        # clamscan reads a local signature DB, so it works offline, but only if signatures were staged. An empty DB detects
        # nothing while still exiting 0, which would read as "clean".
        clam_opts = []
        if glob.glob(G.CLAMAV_DB_DIR + "/*.c[vl]d"):
            clam_opts.append("--database=" + G.CLAMAV_DB_DIR)
        elif not glob.glob("/var/lib/clamav/*.c[vl]d"):
            record_warn("__global__", "OFFLINE:ClamAV signature database is empty — malware scan detected nothing because it has no "
                        "signatures, not because the code is clean; stage a DB in %s" % G.CLAMAV_DB_DIR)
            record_layer("L1_malware", "skipped:no ClamAV signatures available")
        # clamscan documents two outcomes: 0 (clean) and 1 (infected). Every other status is clamscan failing.
        clam_rc = _quiet(["clamscan", "-r", "--quiet"] + clam_opts + G.CLAMSCAN_EXCLUDES + [G.SCAN_DIR])
        if clam_rc == 0:
            record_pass(G.SCAN_DIR)
            ok("ClamAV: clean")
        elif clam_rc == 1:
            record_fail(G.SCAN_DIR, "clamav:malware_detected")
        else:
            record_warn("__global__", "clamav:scan_error_exit_%d" % clam_rc)
            record_layer("L1_malware", "skipped:clamav failed (exit %d)" % clam_rc)
        if not LAYER_COVERAGE.get("L1_malware"):
            record_layer("L1_malware", "ran")
    else:
        record_warn("__global__", "clamscan missing")
        record_layer("L1_malware", "skipped:clamav not installed")

    if has_cmd("yara") and os.path.isdir(G.WORK_DIR + "/yara-rules"):
        yara_files = sorted(glob.glob(glob.escape(G.WORK_DIR + "/yara-rules/") + "*.yar"), key=os.fsencode)
        if yara_files and os.path.isfile(yara_files[0]):
            info("yara…")
            # The output and the exit status of each run are read apart: the layer is "ran" only when every rule file ran
            # with status 0, and a hit is a FAIL whatever the status.
            y_bad, y_hits = "", False
            for rule in yara_files:
                y_rc, out = run_tool(["yara", "-r", rule, G.SCAN_DIR])
                if _subst(out):
                    record_fail(G.SCAN_DIR, "yara:ioc_match:%s" % _basename(rule))
                    y_hits = True
                if y_rc != 0:
                    record_warn("__global__", "yara:scan_error_exit_%d:%s" % (y_rc, _basename(rule)))
                    y_bad = y_bad or str(y_rc)
            if y_bad:
                record_layer("L1_ioc_yara", "skipped:yara failed (exit %s)" % y_bad)
            else:
                if not y_hits:
                    ok("YARA: no IOC")
                record_layer("L1_ioc_yara", "ran")
        else:
            # yara is installed and the directory exists, but there is no rule to run: nothing was examined.
            record_warn("__global__", "yara rules directory has no .yar files — IOC scan skipped")
            record_layer("L1_ioc_yara", "skipped:yara rules directory has no .yar files")
    else:
        record_warn("__global__", "yara or rules directory missing")
        record_layer("L1_ioc_yara", "skipped:yara or rules directory missing")


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — OWASP Top 10 2021 + CWE Top 25 via Semgrep
# ═══════════════════════════════════════════════════════════════════════════════
def _semgrep_rows(text):
    """The checks of the shell's `python3 -c` over Semgrep's stdout: one line per result, `path rule message line severity`
    joined by \\x01. -> the text printed, or None when Semgrep's output is not a JSON object with a `results` list."""
    try:
        results = json.loads(text)["results"]
        if not isinstance(results, list):
            raise TypeError("results is not a list")
        rows = []
        for r in results:
            path = r.get("path", "")
            rule = r.get("check_id", "")
            msg = r.get("extra", {}).get("message", "")[:120]
            line = str(r.get("start", {}).get("line", ""))
            sev = r.get("extra", {}).get("severity", "INFO")
            rows.append(chr(1).join((path, rule, msg, line, sev)))
        # print() writes the text out, which fails for a lone surrogate that is not a raw byte
        return _subst(("\n".join(rows) + "\n").encode("utf-8", "surrogateescape"))
    except Exception:
        return None


def scan_owasp_cwe():
    info("=== Layer 2: OWASP Top 10 2021 + CWE Top 25 (Semgrep) ===")

    if not has_cmd("semgrep"):
        record_warn("__global__", "semgrep missing — OWASP/CWE layer skipped (pip install semgrep)")
        record_layer("L2_owasp_cwe", "skipped:semgrep not installed")
        return

    # Offline: "p/..." identifiers resolve against the semgrep registry over the network. The pre-exported YAML of each ruleset
    # is used instead, and a ruleset with no staged file is skipped loudly rather than silently producing zero findings.
    semgrep_extra = ["--metrics=off"]
    staged, missing = [], []
    for rs in ("p/owasp-top-ten", "p/cwe-top-25", "p/security-audit", "p/secrets"):
        name = rs[len("p/"):]
        if os.path.isfile("%s/%s.yaml" % (G.SEMGREP_RULES_DIR, name)):
            staged.append("%s/%s.yaml" % (G.SEMGREP_RULES_DIR, name))
        else:
            missing.append(name)
    if missing:
        record_warn("__global__", "OFFLINE:semgrep rulesets not staged (%s) — those OWASP/CWE rules did NOT run; export them with "
                    "'semgrep --config p/<name> --dump-config' on a connected host into %s" % (" ".join(missing), G.SEMGREP_RULES_DIR))
        record_layer("L2_owasp_cwe", "partial:rulesets missing (%s)" % " ".join(missing))
    if not staged:
        record_warn("__global__", "OFFLINE:Layer 2 skipped entirely — no semgrep rulesets available in %s" % G.SEMGREP_RULES_DIR)
        record_layer("L2_owasp_cwe", "skipped:no semgrep rulesets staged for offline use")
        return

    found_any, sg_state = False, ""
    for ruleset in staged:
        info("  semgrep %s…" % ruleset)
        # One run per rule set; the JSON is parsed once.
        sg_rc, out = run_tool(["semgrep", "--config=" + ruleset, "--quiet", "--json", "--no-autofix"] + semgrep_extra
                              + G.SEMGREP_EXCLUDES + [G.SCAN_DIR])
        ruleset_findings = _semgrep_rows(_subst(out) + "\n")
        sg_parsed = ruleset_findings is not None
        ruleset_findings = ruleset_findings or ""

        # Semgrep exits 0 (and 1 when asked to fail on findings). Another status is Semgrep failing. The first failure names
        # the layer's state; a WARN names every rule set that failed. The findings of the other rule sets, and of this one
        # if its output could be read, are kept.
        if sg_rc not in (0, 1):
            record_warn("__global__", "semgrep:scan_error_exit_%d (%s)" % (sg_rc, ruleset.rsplit("/", 1)[-1]))
            sg_state = sg_state or "skipped:semgrep failed (exit %d)" % sg_rc
        elif not sg_parsed:
            record_warn("__global__", "semgrep:output_could_not_be_read (%s)" % ruleset.rsplit("/", 1)[-1])
            sg_state = sg_state or "skipped:semgrep output could not be read"

        if sg_parsed and not ruleset_findings:
            if sg_rc in (0, 1):
                ok("  %s: no findings" % ruleset)
        elif ruleset_findings:
            for row in ruleset_findings.split("\n"):
                path, rule, msg, line, sev = _read(row, "\x01", 5)
                if path:
                    record_fail(path, "semgrep[%s]:%s:line%s:%s:%s" % (ruleset, rule, line, sev, msg))
            found_any = True

    if not sg_state and not found_any:
        ok("OWASP/CWE scan: no findings")
    # A Semgrep that failed is a bigger gap than a rule set that was never staged, so it replaces "partial". Otherwise a
    # "partial" already recorded for missing rulesets is not overwritten.
    if sg_state:
        record_layer("L2_owasp_cwe", sg_state)
    elif not LAYER_COVERAGE.get("L2_owasp_cwe"):
        record_layer("L2_owasp_cwe", "ran")


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — Software Composition Analysis (SCA) — vulnerable dependencies
# ═══════════════════════════════════════════════════════════════════════════════
def _trivy_vulnerabilities(text):
    """The number of vulnerabilities in trivy's JSON, or None when the output is not a trivy document: a JSON object with
    SchemaVersion or Results, Results a list of objects whose Vulnerabilities, if present, is a list."""
    try:
        data = json.loads(text)
        if not isinstance(data, dict) or not ("SchemaVersion" in data or "Results" in data):
            return None
        results = data.get("Results")
        if results is None:
            results = []
        if not isinstance(results, list):
            return None
        total = 0
        for r in results:
            if not isinstance(r, dict):
                return None
            v = r.get("Vulnerabilities")
            if v is None:
                continue
            if not isinstance(v, list):
                return None
            total += len(v)
        return total
    except Exception:
        return None


def scan_dependencies():
    info("=== Layer 3: SCA — Vulnerable dependencies (OWASP A06) ===")

    # trivy: universal SCA (Python, JS, Go, Ruby, Java, etc.)
    if has_cmd("trivy"):
        info("trivy fs…")
        # Offline: forbid every update attempt and read the staged database. --offline-scan also stops trivy from resolving
        # dependencies that would need a network round-trip (Java GAV lookups).
        trivy_extra = []
        if os.path.isdir(G.TRIVY_CACHE_DIR) and glob.glob(G.TRIVY_CACHE_DIR + "/db/*"):
            trivy_extra = ["--skip-db-update", "--skip-java-db-update", "--offline-scan", "--cache-dir", G.TRIVY_CACHE_DIR]
        else:
            record_warn("__global__", "OFFLINE:trivy database not staged in %s — dependency CVE scan did NOT run; populate it with "
                        "'trivy fs --download-db-only --cache-dir <dir>' on a connected host" % G.TRIVY_CACHE_DIR)
            record_layer("L3_dependency_cve", "skipped:trivy database not staged for offline use")
        # Only a trivy that was started, ended with status 0 and printed its JSON counts as ran. With no staged database it is
        # not started at all, and the layer neither claims "no known CVEs" nor adds a PASS.
        if trivy_extra:
            trivy_state = "ran"
            trivy_rc, out = run_tool(["trivy", "fs", "--quiet", "--exit-code", "0", "--format", "json"] + trivy_extra + [G.SCAN_DIR])
            vuln_count = _trivy_vulnerabilities(_subst(out) + "\n")
            if trivy_rc != 0:
                record_warn("__global__", "trivy:scan_error_exit_%d" % trivy_rc)
                trivy_state = "skipped:trivy failed (exit %d)" % trivy_rc
            elif vuln_count is None:
                record_warn("__global__", "trivy:output_could_not_be_read")
                trivy_state = "skipped:trivy output could not be read"
            record_layer("L3_dependency_cve", trivy_state)
            if vuln_count:
                record_fail(G.SCAN_DIR, "trivy:%d_vulnerable_dependencies" % vuln_count)
            elif trivy_state == "ran":
                record_pass(G.SCAN_DIR)
                ok("trivy: no known CVEs")
    else:
        record_warn("__global__", "trivy missing — dependency CVE scan skipped")
        record_layer("L3_dependency_cve", "skipped:trivy not installed")

    # pip-audit and safety both resolve advisories from a remote service and have no offline database, and so does npm audit.
    # Say so explicitly: a silent skip would leave those dependency CVEs unreported with nothing in the record.
    if _find_any(["-name", "requirements*.txt", "-o", "-name", "Pipfile.lock", "-o", "-name", "pyproject.toml"]):
        record_warn("__global__", "OFFLINE:Python dependency CVE scan unavailable (pip-audit and safety both require a network "
                    "advisory service) — rely on the staged trivy database for Python CVEs")
    if _find_any(["-name", "package-lock.json", "-o", "-name", "yarn.lock"]):
        record_warn("__global__", "OFFLINE:JavaScript dependency CVE scan unavailable (npm audit requires the registry) — rely on "
                    "the staged trivy database for JS CVEs")


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 6 — ScanCode: licence, copyright & vulnerability
# ═══════════════════════════════════════════════════════════════════════════════
def scan_scancode():
    info("=== Layer 6: ScanCode — licence, copyright & vulnerability ===")

    if not has_cmd("scancode"):
        record_warn("__global__", "scancode missing — licence/copyright layer skipped (pip install scancode-toolkit)")
        record_layer("L6_licence", "skipped:scancode not installed")
        return

    sc_report = "%s/reports/scancode_%s.json" % (G.WORK_DIR, G.TIMESTAMP)

    info("Running scancode on %s …" % G.SCAN_DIR)
    # --vulnerability resolves CVEs against the VulnerableCode service. Licence and copyright detection are fully local, so
    # offline those are kept and only the part that needs a network is dropped.
    sc_opts = ["--license", "--copyright", "--package"]
    record_warn("__global__", "OFFLINE:scancode CVE lookup disabled (--vulnerability queries VulnerableCode) — licence and "
                "copyright detection still run")

    # A layer that was switched on and could not deliver says so in the coverage block, not only in a WARN. The report of an
    # earlier run with the same timestamp must not pass for this run's.
    try:
        os.unlink(sc_report)
    except OSError:
        pass
    sc_rc = _quiet(["scancode"] + sc_opts + ["--json-pp", sc_report, "--quiet", "--timeout", "120", G.SCAN_DIR])
    if sc_rc != 0:
        record_warn("__global__", "scancode:scan_error — check %s" % sc_report)
        record_layer("L6_licence", "skipped:scancode failed (exit %d)" % sc_rc)
        return

    if not os.path.isfile(sc_report):
        record_warn("__global__", "scancode:no_report_generated")
        record_layer("L6_licence", "skipped:scancode produced no report")
        return

    if not has_cmd("python3"):
        record_warn("__global__", "scancode:python3_missing — cannot parse report")
        record_layer("L6_licence", "skipped:python3 not available")
        return

    # A report that exists but cannot be read (ScanCode killed while it wrote, not JSON, JSON of the wrong shape) makes the
    # reader exit non-zero.
    sc_read_rc, out = run_helper("tools/scancode.py", sc_report, G.SCAN_DIR)
    if sc_read_rc != 0:
        record_warn("__global__", "scancode:report_could_not_be_read")
        record_layer("L6_licence", "skipped:scancode report could not be read")
        return

    warn_count = fail_count = 0
    for row in _subst(out).split("\n"):
        level, sc_rel, msg = _read(row, "|", 3)
        if not level:
            continue
        abs_path = "%s/%s" % (G.SCAN_DIR, sc_rel)
        if level == "FAIL":
            record_fail(abs_path, msg)
            fail_count += 1
        elif level == "WARN":
            record_warn(abs_path, msg)
            warn_count += 1

    if fail_count > 0:
        fail_f("scancode: %d CRITICAL/HIGH vulnerability finding(s)" % fail_count)
    elif warn_count > 0:
        warn("scancode: %d licence/vulnerability warning(s) — review before enterprise use" % warn_count)
    else:
        ok("scancode: no risky licences or vulnerabilities detected")

    record_layer("L6_licence", "ran")
    ok("ScanCode report: %s" % sc_report)
