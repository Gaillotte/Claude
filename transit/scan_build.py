"""Build and configuration file scanners of the Python engine: YAML, Terraform, Dockerfile, XML (Maven and Ant), package
manifests, requirements, Gradle, setup.py, CMake, Makefile, HTML, Windows batch and PowerShell.

One function per scanner, named as in scan_pipeline.sh, in the shell's order and with the shell's messages. Where the shell
repeats `if grep_check '...' "$f"; then record_fail ...; fi`, a table of (level, pattern, message[, 'i']) rows and one loop
do the same (`grep_rules`; `_rules` when the file that is searched is a view of the file the finding is recorded against).
No module-level state. Standard library only.
"""
import os
import re
import tempfile
from fnmatch import fnmatchcase

from transit.core import (G, grep_check, grep_check_excl, grep_check_i, grep_flat, grep_rules, has_cmd, record_fail,
                          record_pass, record_warn, register_tmp, run_helper, run_tool)


def _basename(f):
    return os.path.basename(f).rstrip("\n")              # `$(basename "$f")` drops trailing newlines


def _rules(f, v, rows):
    """`grep_rules` over the view `v` of the file `f`: the finding is recorded against `f`. -> True when a FAIL was recorded."""
    failed = False
    for row in rows:
        level, pattern, message = row[:3]
        if (grep_check_i if len(row) > 3 else grep_check)(pattern, v):
            if level == "fail":
                record_fail(f, message)
                failed = True
            else:
                record_warn(f, message)
    return failed


def _temp_view(prefix, data):
    """`mktemp "${TMPDIR:-/tmp}/<prefix>XXXXXX"` holding `data` -> its path, or "" when it could not be made."""
    try:
        fd, path = tempfile.mkstemp(prefix=prefix, dir=os.environ.get("TMPDIR") or "/tmp")
    except OSError:
        return ""
    register_tmp(path)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except OSError:                                  # a view that could not be written is no view: the raw file is searched
        _drop_temp(path)
        return ""
    return path


def _drop_temp(path):
    try:
        os.unlink(path)
    except OSError:
        pass
    if path in G.TMP_PATHS:
        G.TMP_PATHS.remove(path)


# ── YAML ─────────────────────────────────────────────────────────────────────
_YAML_RULES = [
    # Unpinned GitHub Actions (supply chain risk)
    ('fail', r'uses:\s+\S+/[^@]+$', 'OWASP-A08:unpinned_action_supply_chain_risk'),
    # Inline secrets in CI/CD config
    ('fail', r'(password|secret|token|key|api_key)\s*:\s*[^${[:space:]][^{]', 'CWE-798:inline_credential_in_yaml'),
    # SSTI pattern in templates (Jinja2 / Helm)
    ('warn', r'\{\{[^}]*(request\.|user\.|\.env\.)', 'CWE-94:potential_SSTI_template_injection'),
    ('fail', r'privileged:\s*true', 'OWASP-A05:privileged_container'),
    ('fail', r'(hostNetwork|hostPID|hostIPC):\s*true', 'OWASP-A05:dangerous_host_namespace_sharing'),
]


def scan_yaml(f):
    if not grep_rules(f, _YAML_RULES):
        record_pass(f)


# ── Terraform / HCL ─────────────────────────────────────────────────────────
_TERRAFORM_RULES = [
    ('fail', r'(password|secret|token)\s*=\s*"[^"]+"', 'CWE-798:hardcoded_secret_in_terraform'),
    ('fail', r'acl\s*=\s*"public-read', 'OWASP-A05:S3_public_read_ACL'),
    ('warn', r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', 'OWASP-A05:unrestricted_CIDR_0_0_0_0'),
    ('fail', r'encrypted\s*=\s*false', 'OWASP-A02:encryption_disabled'),
]


def scan_terraform(f):
    failed = False
    if has_cmd("checkov"):
        # --skip-download prevents checkov fetching remote provider schemas.
        argv = ["checkov", "-f", f, "--quiet"] + (["--skip-download"] if G.OFFLINE else [])
        _, raw = run_tool(argv)                      # `2>/dev/null || true`: the status is thrown away, the text is read
        count = sum(1 for line in raw.replace(b"\x00", b"").rstrip(b"\n").split(b"\n") if b"FAILED" in line)
        if count:
            record_fail(f, "checkov:%d_CIS_IaC_findings" % count)
            failed = True
    else:
        record_warn(f, "checkov missing")
    failed = grep_rules(f, _TERRAFORM_RULES) or failed
    if not failed:
        record_pass(f)


# ── Dockerfile ───────────────────────────────────────────────────────────────
_DOCKER_RULES = [
    # :latest tag — non-deterministic build
    ('fail', r':\s*latest\b', 'OWASP-A05:unpinned_base_image_latest_tag'),
    # ADD with remote URL — no integrity check
    ('fail', r'ADD\s+https?://', 'CWE-494:ADD_remote_URL_no_integrity_check'),
    # RUN curl|bash — supply chain
    ('fail', r'RUN\s+.*(curl|wget).*\|\s*(bash|sh)', 'CWE-78:RUN_curl_pipe_bash_supply_chain'),
]


def _has_nonroot_user(f):
    """`while IFS= read -r line; do [[ $line =~ ^USER[[:space:]]+ ]] ...`: a line that begins with USER and a space whose second
    word (quotes removed, up to the first colon) is neither root nor 0. A last line without a newline is not read (read
    fails on it), a NUL byte is dropped, and awk's default field separators are blank, tab and newline."""
    try:
        with open(f, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    for raw in data.replace(b"\x00", b"").split(b"\n")[:-1]:
        line = raw.decode("latin-1")
        if not re.match(r"USER[ \t\n\v\f\r]+", line):
            continue
        fields = [w for w in re.split(r"[ \t\n]+", line) if w]
        user_arg = (fields[1] if len(fields) > 1 else "").replace('"', "").replace("'", "").split(":", 1)[0]
        if user_arg not in ("root", "0", ""):
            return True
    return False


def scan_docker(f):
    failed = False
    if has_cmd("hadolint"):
        rc, _ = run_tool(["hadolint", f])           # its findings are not echoed: tool output never reaches the console raw
        if rc != 0:
            record_fail(f, "hadolint:dockerfile_issue")
            failed = True
    else:
        record_warn(f, "hadolint missing")
    failed = grep_rules(f, _DOCKER_RULES) or failed
    # CWE-250 — container runs as root: warn if no USER directive exists, or if the only USER is root / uid 0
    if not _has_nonroot_user(f):
        record_warn(f, "CWE-250:no_nonroot_USER_directive_container_may_run_as_root")
    # Sensitive env vars in image layers
    if grep_check(r'ENV\s+(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)', f):
        record_fail(f, "CWE-798:sensitive_ENV_var_baked_into_image_layer")
        failed = True
    if not failed:
        record_pass(f)


# ── XML, Maven and Ant ──────────────────────────────────────────────────────
def _xml_view(d):
    """The document as UTF-8 with its <!-- comments --> replaced by a space. UTF-16 and UTF-32 are decoded first (a byte-order
    mark, or the NUL pattern of a wide encoding without one); the comments are removed with find, not a regular expression,
    and an opener with no closer ends the search, so the rest of the file stays visible."""
    enc = None
    if d[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        enc = "utf-32"
    elif d[:2] in (b"\xff\xfe", b"\xfe\xff"):
        enc = "utf-16"
    elif d[:4] == b"<\x00\x00\x00":
        enc = "utf-32-le"
    elif d[:4] == b"\x00\x00\x00<":
        enc = "utf-32-be"
    elif d[:3] != b"\xef\xbb\xbf":
        head = d[:1024]
        half = max(1, len(head) // 2)
        even, odd = head[0::2].count(0), head[1::2].count(0)
        if odd * 2 > half and even * 8 < half:
            enc = "utf-16-le"
        elif even * 2 > half and odd * 8 < half:
            enc = "utf-16-be"
    if enc:
        d = d.decode(enc, "replace").encode("utf-8")
    out, i = [], 0
    while True:
        a = d.find(b"<!--", i)
        if a < 0:
            break
        b = d.find(b"-->", a + 4)
        if b < 0:
            break
        out.append(d[i:a])
        out.append(b" ")
        i = b + 3
    out.append(d[i:])
    return b"".join(out)


_XXE_RESOURCE = r'''<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+["'](file:|expect:|php:|gopher:|jar:|netdoc:|ftp:|https?:|/|\\\\)'''
_XXE_BOMB = r'''<!ENTITY[[:space:]]+[%]?[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]+["'][^"']*(&[A-Za-z0-9_.-]+;[^"'&]*){4,}'''
_XXE_EXTERNAL = r'<!ENTITY[^>]*[[:space:]](SYSTEM|PUBLIC)[[:space:]]'
_XML_CREDENTIAL = r'<(password|passphrase|secret|apiKey|api-key|accessKey|privateKey|token)>[[:space:]]*[^<[:space:]]{6,}'
_XML_CREDENTIAL_OK = (r'>[[:space:]]*(\$\{|\{|/|~|[A-Za-z]:\\)|'
                      r'>[[:space:]]*(changeit|changeme|password|passwd|secret|somepassword|proxypass|repopwd|example|placeholder|optional|x{3,}|\*+|your[-_a-z]*)[[:space:]]*<|'
                      r'\.\.\.[[:space:]]*<')

_MAVEN_RULES = [
    ('fail', r'''(<executable>[[:space:]]*(sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh|curl|wget)[[:space:]]*<|<exec[^>]*executable=["'](sh|bash|zsh|cmd|powershell|pwsh|curl|wget)["'])''',
     'CWE-78:maven_exec_runs_shell_or_downloader', 'i'),
    ('warn', r'exec-maven-plugin', 'maven:exec_plugin_runs_a_program_during_the_build', 'i'),
    ('warn', r'maven-antrun-plugin', 'maven:antrun_plugin_runs_arbitrary_ant_tasks', 'i'),
    ('warn', r'<scope>[[:space:]]*system[[:space:]]*<', 'maven:system_scope_dependency_bypasses_resolution', 'i'),
]
_ANT_FAIL_RULES = [
    ('fail', r'''<get[^>]+src=["']http://''', 'CWE-319:ant_get_over_plaintext_http', 'i'),
    ('fail', r'''<exec[^>]*executable=["'](sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh|curl|wget)["']''',
     'CWE-78:ant_exec_runs_shell_or_downloader', 'i'),
]

_REPO_OPEN = re.compile(rb'<(repository|pluginRepository|snapshotRepository)>')
_REPO_URL_HTTP = re.compile(rb'<url>[ \t]*http://')
_REPO_CLOSE = re.compile(rb'</(repository|pluginRepository|snapshotRepository)>')


def _maven_repository_over_http(path):
    """The awk of the shell: a line `<url>http://` inside a <repository>, <pluginRepository> or <snapshotRepository> block."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    inside = found = False
    for line in data.split(b"\n"):
        if _REPO_OPEN.search(line):
            inside = True
        if inside and _REPO_URL_HTTP.search(line):
            found = True
        if _REPO_CLOSE.search(line):
            inside = False
    return found


def scan_xml(f):
    failed = False
    base = _basename(f)

    # Work on a view with comments removed and a wide encoding decoded; if it cannot be built the raw file is searched.
    x, tmp = f, ""
    try:
        with open(f, "rb") as fh:
            view = _xml_view(fh.read())
    except Exception:
        view = b""
    tmp = _temp_view("aitransit_xml_", view)
    if tmp and view:
        x = tmp
    G.FLAT_FILE, G.FLAT_INCOMPLETE = f, False

    # ── XXE: an ENTITY that points at something, matched with newlines folded ──
    if grep_flat(_XXE_RESOURCE, x):
        record_fail(f, "CWE-611:xxe_external_entity_references_a_resource")
        failed = True
    if grep_flat(_XXE_BOMB, x):
        record_fail(f, "CWE-776:xml_entity_expansion_bomb")
        failed = True
    if grep_flat(_XXE_EXTERNAL, x):
        record_warn(f, "CWE-611:xml_declares_an_external_entity")
    if G.FLAT_INCOMPLETE:
        failed = True
    G.FLAT_FILE = ""

    # ── Credentials: the element name is the credential word ──
    if grep_check_excl(_XML_CREDENTIAL, _XML_CREDENTIAL_OK, x):
        record_fail(f, "CWE-798:hardcoded_credential_in_XML")
        failed = True

    if base == "pom.xml" or fnmatchcase(base, "*.pom"):
        # A repository over plaintext http://, scoped to <repository> blocks (a homepage <url> is not one).
        if _maven_repository_over_http(x):
            record_fail(f, "CWE-319:maven_repository_over_plaintext_http")
            failed = True
        failed = _rules(f, x, _MAVEN_RULES) or failed
    elif base == "build.xml" or fnmatchcase(base, "build-*.xml") or fnmatchcase(base, "*-build.xml"):
        failed = _rules(f, x, _ANT_FAIL_RULES) or failed
        if grep_check_excl(r'''<(sshexec|scp|ftp)[^>]*[[:space:]]password=["'][^"']{4,}''', r'''password=["']\$\{''', x):
            record_fail(f, "CWE-798:ant_credential_attribute")
            failed = True
        if grep_check_i(r'<exec[[:space:]>]', x):
            record_warn(f, "ant:exec_task_runs_a_program_during_the_build")

    if tmp:
        _drop_temp(tmp)
    if not failed:
        record_pass(f)


# ── Package manifests ───────────────────────────────────────────────────────
def scan_package_json(f):
    """package.json and composer.json: the facts the manifests helper prints, or patterns on the raw text when it could not
    parse the file (and then it can only warn about a plaintext URL)."""
    failed = False
    facts = ""
    base = _basename(f)
    if has_cmd("python3"):
        _, out = run_helper("scanners/manifests.py", f)
        facts = out.decode("utf-8", "surrogateescape").rstrip("\n")

    if "FACT parsed" not in facts:
        record_warn(f, "pkg:not_parsed_as_json_checked_by_pattern_only")
        if grep_check_i(r'"((pre|post)?install|prepare|prepublish(only)?|post-install-cmd|post-update-cmd)"[[:space:]]*:[[:space:]]*"[^"]*(curl|wget)[^"]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh', f):
            facts += "\nFACT hook_pipe"
        if grep_check_i(r'"[^"]+"[[:space:]]*:[[:space:]]*"(http|git)://', f):
            record_warn(f, "pkg:plaintext_url_present_unscoped_check_dependencies_manually")

    if base == "composer.json":
        if "FACT hook_pipe" in facts:
            record_fail(f, "CWE-78:composer_hook_fetches_and_executes")
            failed = True
        if "FACT hook_decode" in facts:
            record_fail(f, "CWE-78:composer_hook_decodes_and_executes")
            failed = True
        if "FACT composer_insecure" in facts:
            record_fail(f, "CWE-319:composer_insecure_transport")
            failed = True
        # Composer hooks are ordinary (@php artisan ...); fetching in one is not.
        if "FACT script_fetch" in facts or "FACT script_pipe" in facts:
            record_warn(f, "composer:script_fetches_from_the_network")
    else:
        if "FACT hook_pipe" in facts:
            record_fail(f, "CWE-78:npm_lifecycle_hook_fetches_and_executes")
            failed = True
        if "FACT hook_decode" in facts:
            record_fail(f, "CWE-78:npm_lifecycle_hook_decodes_and_executes")
            failed = True
        if "FACT dep_plain" in facts:
            record_fail(f, "CWE-319:npm_dependency_over_plaintext")
            failed = True
        if "FACT install_hook" in facts:
            record_warn(f, "npm:install_time_hook_present")
        if "FACT script_pipe" in facts:
            record_warn(f, "npm:script_pipes_a_download_into_a_shell")
        elif "FACT script_fetch" in facts:
            record_warn(f, "npm:script_fetches_from_the_network")
        if "FACT dep_remote" in facts:
            record_warn(f, "npm:dependency_from_a_git_or_tarball_url_not_the_registry")

    # Credentials in the manifest itself; a semver range as the value is not a secret ("csrf-token": "^2.0.0").
    if grep_check_excl(r'(password|secret|token|api_key|private_key)"?[[:space:]]*:[[:space:]]*"[^"${[:space:]]{4,}',
                       r':[[:space:]]*"[\^~><=v]*[0-9]+(\.[0-9xX*]+)*"', f):
        record_fail(f, "CWE-798:hardcoded_credential_in_JSON")
        failed = True

    if not failed:
        record_pass(f)


# ── pip requirements ─────────────────────────────────────────────────────────
_REQUIREMENTS_RULES = [
    ('fail', r'^[[:space:]]*((--index-url|-i|--extra-index-url|--find-links|-f)[[:space:]=]+http://|(-e[[:space:]]+)?(git\+http://|git://)|http://[^[:space:]]+\.(tar\.gz|tgz|zip|whl|tar\.bz2))',
     'CWE-319:pip_index_or_requirement_over_plaintext', 'i'),
    ('fail', r'(https?|git\+https?|ssh)://[^/[:space:]:@]+:[^/[:space:]@]+@', 'CWE-798:pip_credentials_embedded_in_url'),
    ('warn', r'^[[:space:]]*--trusted-host', 'pip:trusted_host_disables_tls_verification', 'i'),
    ('warn', r'^[[:space:]]*--extra-index-url', 'pip:extra_index_url_enables_dependency_confusion', 'i'),
]


def scan_requirements(f):
    failed = grep_rules(f, _REQUIREMENTS_RULES)
    # A VCS requirement not pinned to a commit follows a moving branch.
    if grep_check_excl(r'git\+(https|ssh)://', r'@[0-9a-f]{7,40}([#[:space:]]|$)', f):
        record_warn(f, "pip:vcs_requirement_not_pinned_to_a_commit")
    if not failed:
        record_pass(f)


# ── Gradle ───────────────────────────────────────────────────────────────────
_GRADLE_PROPERTIES_RULES = [
    # Java .properties has no quoting: a blank value, a ${...} reference and a path are excluded.
    ('fail', r'^[[:space:]]*[A-Za-z0-9_.-]*(password|passwd|secret|apikey|api[_.-]?key|auth[_.-]?token|access[_.-]?token)[[:space:]]*=[[:space:]]*[^[:space:]$/~.]',
     'CWE-798:gradle_credential_in_properties', 'i'),
    ('fail', r'^[[:space:]]*(org\.gradle\.)?dependency[._-]verification[[:space:]]*=[[:space:]]*(off|lenient)',
     'CWE-494:gradle_dependency_verification_disabled', 'i'),
    ('fail', r'^[[:space:]]*(org\.gradle\.jvmargs|systemProp\.)[^=]*=.*-(javaagent|agentpath|agentlib):',
     'CWE-829:gradle_daemon_java_agent', 'i'),
    ('warn', r'^[[:space:]]*systemProp\.javax\.net\.ssl\.(trustStore|trustStorePassword)[[:space:]]*=',
     'CWE-295:gradle_truststore_override', 'i'),
]
_GRADLE_WRAPPER_RULES = [
    # The `\:` is Java .properties escaping of the colon.
    ('fail', r'^[[:space:]]*distributionUrl[[:space:]]*=[[:space:]]*(http|ftp)\\?://', 'CWE-494:gradle_wrapper_plaintext_distribution', 'i'),
    ('warn', r'^[[:space:]]*validateDistributionUrl[[:space:]]*=[[:space:]]*false', 'CWE-494:gradle_wrapper_url_validation_disabled', 'i'),
]
_GRADLE_SCRIPT_RULES = [
    ('fail', r'''apply[[:space:]]*\(?[[:space:]]*from[[:space:]]*[:=][[:space:]]*["']?(https?|ftp)://''',
     'CWE-829:gradle_apply_from_remote_script', 'i'),
    ('fail', r'allowinsecureprotocol[[:space:]]*=[[:space:]]*true', 'CWE-494:gradle_insecure_repository_protocol_enabled', 'i'),
    ('fail', r'''(["'][^"']*["']|\])[[:space:]]*\.execute\(\)|(^|[^[:alnum:]_.])ProcessBuilder[[:space:]]*\(|Runtime\.getRuntime\(\)\.exec[[:space:]]*\(''',
     'CWE-78:gradle_process_spawn_from_literal', 'i'),
    ('warn', r'(new[[:space:]]+URL|URL|URI)[[:space:]]*\([^)]*\)[[:space:]]*(\.toURL\(\))?[[:space:]]*\.(text|readText|getText|openStream|newInputStream)',
     'CWE-494:gradle_configuration_time_remote_fetch', 'i'),
    ('warn', r'''(^|[^[:alnum:]_.])(commandLine|javaexec|providers\.exec|exec)[[:space:]]*[({'"]''',
     'CWE-78:gradle_build_step_runs_process', 'i'),
]


def scan_gradle(f):
    base = _basename(f)
    if base == "gradle.properties":
        rows = _GRADLE_PROPERTIES_RULES
    elif base == "gradle-wrapper.properties":
        rows = _GRADLE_WRAPPER_RULES
    else:
        rows = _GRADLE_SCRIPT_RULES
    if not grep_rules(f, rows):
        record_pass(f)


# ── Windows batch: .bat and .cmd ─────────────────────────────────────────────
_BAT_REM = re.compile(rb'[ \t\v\f\r]*@?rem([ \t\v\f\r]|\Z)', re.I)
_BAT_COLONS = re.compile(rb'[ \t\v\f\r]*@?::')


def _bat_view(data):
    """`tr -d '\\r' | sed` twice: carriage returns removed, REM / @REM / :: comment lines dropped, and a line that ends with a
    caret joined with the next one (its leading white space removed); a caret on the last line stays."""
    lines = data.replace(b"\r", b"").split(b"\n")
    ended = lines[-1] == b""                        # the file ended with a newline: sed sees no extra empty line
    if ended:
        lines.pop()
    dropped = [bool(_BAT_REM.match(ln) or _BAT_COLONS.match(ln)) for ln in lines]
    kept = [ln for ln, gone in zip(lines, dropped) if not gone]
    out, i = [], 0
    while i < len(kept):
        cur = kept[i]
        i += 1
        while cur.endswith(b"^") and i < len(kept):
            cur = cur[:-1] + kept[i].lstrip(b" \t\n\v\f\r")
            i += 1
        out.append(cur)
    # sed leaves off the final newline only when the last line of an unterminated file survives
    return b"\n".join(out) + (b"\n" if out and (ended or dropped[-1]) else b"")


_BAT_FETCH = r'(curl|wget|bitsadmin(\.exe)?[^|&]*[-/](transfer|addfile)|certutil(\.exe)?[^|&]*[-/](urlcache|verifyctl)|powershell.*(downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient|[[:space:]](iwr|irm)[[:space:]]))'

_BAT_FAIL_ONE = [
    # a native downloader: certutil -urlcache and bitsadmin /transfer
    ('fail', r'(certutil(\.exe)?[^|&]*[-/](urlcache|verifyctl)|bitsadmin(\.exe)?[^|&]*[-/](transfer|addfile))',
     'CWE-78:bat_download_cradle_certutil_or_bitsadmin', 'i'),
    # a PowerShell download cradle launched from batch
    ('fail', r'powershell(\.exe)?.*(downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient|[[:space:]](iwr|irm)[[:space:]])',
     'CWE-78:bat_powershell_download_cradle', 'i'),
    # a base64 command line
    ('fail', r'''powershell(\.exe)?.*[-/]e[a-z]*[[:space:]]+["']?[A-Za-z0-9+/]{24,}''', 'CWE-78:bat_powershell_encoded_command', 'i'),
    # certutil -decode into something executable
    ('fail', r'certutil(\.exe)?[^|&]*[-/]decode[^|&]*\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|msi|scr|hta)',
     'CWE-78:bat_certutil_decodes_to_an_executable', 'i'),
    # fetch, then run, on one line (`call :label` is a subroutine call: a call must name something that is not a label)
    ('fail', r'''(curl|wget|bitsadmin|certutil|powershell).*(https?|ftp)://.*(&&|&|\|)[[:space:]]*(start[[:space:]]|call[[:space:]]+[^:[:space:]]|cmd|wscript|cscript|mshta|"?%[A-Za-z_]+%)''',
     'CWE-78:bat_download_then_execute', 'i'),
    # obfuscation: carets inside a word
    ('fail', r'[a-z]\^[a-z]\^[a-z]', 'CWE-78:bat_caret_obfuscated_command_name', 'i'),
    # a literal credential (`set /p` is a prompt, a %reference% is the correct form)
    ('fail', r'set[[:space:]]+(/a[[:space:]]+)?"?[A-Za-z_]*(passwd|password|secret|api_?key|auth_?token|access_?token|credential)[A-Za-z_]*=[^%!"[:space:]][^"[:space:]]{3,}',
     'CWE-798:bat_hardcoded_credential', 'i'),
    # persistence: a Run / RunOnce / Winlogon / IFEO key, or a file dropped into the Startup folder
    ('fail', r'reg(\.exe)?[[:space:]]+add[^|&]*(currentversion[\\]+run(once)?|winlogon|image file execution options)',
     'CWE-912:bat_persistence_run_key', 'i'),
    ('fail', r'(copy|xcopy|move|echo|type)[^|&]*start menu[\\]+programs[\\]+startup', 'CWE-912:bat_persistence_startup_folder', 'i'),
]
_BAT_DEFENCES = [
    r'reg(\.exe)?[[:space:]]+add[^|&]*(enablelua|consentpromptbehavioradmin|disableantispyware|disablerealtimemonitoring|disableantivirus)',
    r'(add|set)-mppreference.*(exclusionpath|exclusionextension|disablerealtimemonitoring)',
    r'netsh[^|&]*advfirewall[^|&]*state[[:space:]]+off',
    r'sc(\.exe)?[[:space:]]+(stop|config)[[:space:]]+(windefend|mpssvc)',
]
_BAT_DESTRUCTIVE = [
    r'(^|[^[:alnum:]_])(del|erase|rd|rmdir)[[:space:]]+(/[a-z][[:space:]]*)*"?(%systemdrive%|%homedrive%|%userprofile%|%appdata%|[a-z]:)([\\](\*(\.\*)?)?)?"?[[:space:]]*$',
    r'(^|[^[:alnum:]_])format(\.com)?[[:space:]]+[a-z]:',
]
_BAT_FAIL_TWO = [
    ('fail', r'(curl|wget).*([[:space:]]--insecure|[[:space:]]-k([[:space:]]|$)|--no-check-certificate)|servercertificatevalidationcallback',
     'CWE-494:bat_download_without_certificate_verification', 'i'),
    ('fail', r'net[[:space:]]+localgroup[^|&]*(administrators|administrateurs)[^|&]*/add', 'CWE-250:bat_local_admin_account_added', 'i'),
]
_BAT_WARN_ONE = [
    ('warn', r'net[[:space:]]+user[^|&]*/add', 'bat:creates_a_local_account', 'i'),
    ('warn', r'certutil(\.exe)?[^|&]*[-/]decode', 'bat:certutil_decodes_a_file', 'i'),
    ('warn', r'schtasks(\.exe)?[[:space:]]+/create', 'bat:creates_a_scheduled_task', 'i'),
    # `for /f ... in ('curl ...')` reads a download into a variable; only a fetcher counts
    ('warn', r"""for[[:space:]]+/f[^(]*\([[:space:]]*'[^']*(curl|wget|certutil[^']*urlcache|bitsadmin)""",
     'bat:command_output_comes_from_a_download', 'i'),
]
_BAT_WARN_TWO = [
    ('warn', r'(curl|wget|bitsadmin|certutil|powershell).*http://', 'bat:plaintext_http_download_no_transport_integrity', 'i'),
    ('warn', r'powershell.*[-/]e[a-z]*[[:space:]]+(bypass|unrestricted)', 'bat:powershell_execution_policy_bypass', 'i'),
    ('warn', r'powershell.*[-/]w(indowstyle)?[[:space:]]+h(idden)?([[:space:]]|$)', 'bat:powershell_hidden_window', 'i'),
    ('warn', r'(^|[^[:alnum:]_])(mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?[[:space:]]', 'bat:script_host_or_proxy_execution', 'i'),
    ('warn', r'wmic.*process.*call.*create', 'bat:wmic_process_create', 'i'),
    ('warn', r'(start|call|cmd[[:space:]]*/c|xcopy|copy)[[:space:]]+[^[:space:]]*\\\\[A-Za-z0-9._-]+\\', 'bat:runs_or_copies_from_a_remote_unc_path', 'i'),
    # Substring extractions ADJACENT to each other build a word one character at a time: %a:~2,1%%a:~3,1%
    ('warn', r'%[a-z0-9_]+:~[-0-9]+(,[-0-9]+)?%%[a-z0-9_]+:~[-0-9]+(,[-0-9]+)?%', 'bat:command_assembled_from_variable_substrings', 'i'),
]


def scan_bat(f):
    failed = False
    v, tmp = f, ""
    # If the view cannot be built the raw file is scanned instead: more noise, never less coverage.
    try:
        with open(f, "rb") as fh:
            view = _bat_view(fh.read())
    except OSError:
        view = None
    if view is not None:
        tmp = _temp_view("aitransit_bat_", view)
        if tmp:
            v = tmp

    failed = _rules(f, v, _BAT_FAIL_ONE) or failed
    if any(grep_check_i(p, v) for p in _BAT_DEFENCES):               # CWE-693 — UAC, Defender, the firewall turned off
        record_fail(f, "CWE-693:bat_security_control_disabled")
        failed = True
    if any(grep_check_i(p, v) for p in _BAT_DESTRUCTIVE):            # a delete aimed EXACTLY at a drive root or the profile
        record_fail(f, "bat:destructive_delete_of_a_drive_root_or_profile")
        failed = True
    failed = _rules(f, v, _BAT_FAIL_TWO) or failed

    # ── Ordinary in real Windows administration: reported, not blocked ──
    _rules(f, v, _BAT_WARN_ONE)
    if grep_check_i(_BAT_FETCH, v) and grep_check_i(r'(^|[&|(][[:space:]]*)(start|msiexec)[[:space:]]|call[[:space:]]+[^:[:space:]]', v):
        record_warn(f, "bat:downloads_then_runs_a_program")
    _rules(f, v, _BAT_WARN_TWO)

    if tmp:
        _drop_temp(tmp)
    if not failed:
        record_pass(f)


# ── setup.py and conanfile.py ────────────────────────────────────────────────
def scan_setup_py(f):
    failed = False
    # CWE-78 — a download piped into a shell.
    if grep_check(r'''(curl|wget)[^"']*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh''', f):
        record_fail(f, "CWE-78:setup_py_fetches_and_executes")
        failed = True
    # CWE-95 — exec/eval applied to something fetched, on one line.
    if grep_check(r'(exec|eval)[[:space:]]*\([^)]*(urlopen|urlretrieve|requests\.(get|post)|urllib|https?://)', f):
        record_fail(f, "CWE-95:setup_py_executes_a_network_response")
        failed = True
    # CWE-95 — a decoded blob that is then executed (the pieces sit on different lines: a whole-file test).
    if (grep_check(r'(exec|eval)[[:space:]]*\([[:space:]]*(base64\.[a-z0-9_]*decode|codecs\.decode|zlib\.decompress|bytes\.fromhex|binascii\.[a-z]*)', f)
            or (grep_check(r'(b64decode|a85decode|b32decode|bytes\.fromhex|zlib\.decompress|binascii\.unhexlify)', f)
                and grep_check(r'(^|[^[:alnum:]_.])(exec|eval)[[:space:]]*\(', f))):
        record_fail(f, "CWE-95:setup_py_decodes_and_executes")
        failed = True
    # CWE-78 — a socket handed to a shell, or a pty.
    if (grep_check(r'(pty\.spawn|/dev/tcp/|nc[[:space:]]+-[a-z]*e[[:space:]])', f)
            or (grep_check(r'socket\.socket[[:space:]]*\(', f)
                and grep_check(r'(/bin/(ba)?sh|cmd\.exe|dup2[[:space:]]*\()', f))):
        record_fail(f, "CWE-78:setup_py_reverse_shell")
        failed = True
    # CWE-912 — an installer that writes into somewhere that runs later.
    if grep_check(r'(authorized_keys|crontab|/etc/cron\.|\.ssh/id_|/etc/systemd/system)', f):
        record_fail(f, "CWE-912:setup_py_persistence")
        failed = True

    # ── Reported, not blocked ──
    if grep_check(r'''cmdclass[[:space:]]*=[^#]*['"](install|develop|egg_info)['"]''', f):
        record_warn(f, "setup:overrides_install_command_runs_package_code_at_install_time")
    if grep_check(r'(urlretrieve|urlopen|requests\.(get|post)|[^[:alnum:]_](wget|curl)[[:space:]])', f):
        record_warn(f, "setup:downloads_something_at_install_time")
    if grep_check(r'(os\.system|subprocess\.(call|run|check_call|check_output|Popen))', f):
        record_warn(f, "setup:runs_a_program_at_install_time")
    if not failed:
        record_pass(f)


# ── CMake ────────────────────────────────────────────────────────────────────
_CMAKE_RULES = [
    # credential in a set() call; the first value character may be neither $ nor a backslash
    ('fail', r'''set[[:space:]]*\([[:space:]]*[A-Za-z_]*(PASSWORD|PASSWD|SECRET|API_?KEY|TOKEN|CREDENTIAL)[A-Za-z_]*[[:space:]]+["'][^$\\"'][^"']{5,}["']''',
     'CWE-798:cmake_hardcoded_credential', 'i'),
    # fetched over plaintext
    ('fail', r'''(file[[:space:]]*\([[:space:]]*DOWNLOAD[[:space:]]+["']?http://|^[[:space:]]*URL[[:space:]]+["']?http://[^[:space:]"']*\.(tar\.(gz|bz2|xz|zst)|tgz|tbz2|txz|zip|7z|jar|whl))''',
     'CWE-319:cmake_download_over_plaintext_http', 'i'),
    ('fail', r'(CMAKE_)?TLS_VERIFY[[:space:]]+(OFF|0|FALSE)', 'CWE-295:cmake_tls_verification_disabled', 'i'),
    ('fail', r'(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh', 'CWE-78:cmake_curl_pipe_shell_supply_chain', 'i'),
    # compiled-in defences removed (the rule names the negative forms)
    ('fail', r'(fno-stack-protector|_FORTIFY_SOURCE=0|-z[[:space:]]*execstack|fno-pie\b)', 'CWE-1188:cmake_hardening_disabled', 'i'),
    # a build that writes outside its tree, into somewhere that runs later
    ('fail', r'file[[:space:]]*\([[:space:]]*(WRITE|APPEND)[^)]*(/etc/|\.ssh/|authorized_keys|/etc/cron)',
     'CWE-912:cmake_writes_to_a_sensitive_path', 'i'),
    # ── Review-worthy, but ordinary enough not to block ──
    ('warn', r'''COMMAND[[:space:]]+["']?(curl|wget)\b''', 'cmake:build_step_fetches_from_the_network', 'i'),
    ('warn', r'''COMMAND[[:space:]]+["']?(sh|bash)["']?[[:space:]]+-c''', 'cmake:build_step_runs_shell_dash_c', 'i'),
    ('warn', r'install[[:space:]]*\([[:space:]]*(CODE|SCRIPT)', 'cmake:install_runs_arbitrary_code', 'i'),
    ('warn', r'''GIT_TAG[[:space:]]+["']?(master|main|HEAD|develop)["']?[[:space:]]*$''', 'cmake:dependency_pinned_to_a_moving_branch', 'i'),
]


def scan_cmake(f):
    if not grep_rules(f, _CMAKE_RULES):
        record_pass(f)


# ── HTML ─────────────────────────────────────────────────────────────────────
_HTML_RULES = [
    ('fail', r'\beval[[:space:]]*\(', 'CWE-95:html_eval_dynamic_code_execution', 'i'),
    ('fail', r'''unescape[[:space:]]*\([[:space:]]*["']?%''', 'CWE-95:html_obfuscated_percent_encoded_payload', 'i'),
    ('fail', r'document\.write[[:space:]]*\([[:space:]]*(unescape|atob|String\.fromCharCode)', 'CWE-79:html_obfuscated_document_write', 'i'),
    ('fail', r'''<script[^>]+src=["']?http://''', 'CWE-319:html_remote_script_over_plaintext_http', 'i'),
    ('fail', r'''<iframe[^>]*(display:[[:space:]]*none|visibility:[[:space:]]*hidden|width=["']?0["' ]|height=["']?0["' ])''',
     'CWE-1021:html_hidden_iframe', 'i'),
    ('fail', r'''<base[^>]+href=["']?http://''', 'CWE-319:html_base_href_plaintext_hijacks_relative_urls', 'i'),
    ('fail', r'''<form[^>]+action=["']?http://''', 'CWE-319:html_form_posts_over_plaintext_http', 'i'),
    # a credential in the markup: HTML splits the name and the value across two attributes
    ('fail', r'''(name|id)=["'][^"']*(api[_-]?key|password|passwd|secret|token)[^"']*["'][^>]*value=["'][^"']{6,}''',
     'CWE-798:html_hardcoded_credential_in_attribute', 'i'),
    ('fail', r'''<meta[^>]+(api[_-]?key|secret|token|password)[^>]+content=["'][^"']{6,}''', 'CWE-798:html_hardcoded_credential_in_meta', 'i'),
    # a cookie read wired to a network sink, in both orders, bounded to one statement
    ('fail', r'(document\.cookie[^;]{0,150}(fetch[[:space:]]*\(|XMLHttpRequest|sendBeacon|\.src[[:space:]]*=)|(fetch[[:space:]]*\(|XMLHttpRequest|sendBeacon|\.src[[:space:]]*=)[^;]{0,150}document\.cookie)',
     'CWE-200:html_cookie_exfiltration_to_network_sink', 'i'),
    # ── Review-worthy, but too common to block ──
    ('warn', r'(innerHTML|outerHTML|insertAdjacentHTML)[[:space:]]*(=|\()', 'CWE-79:html_unsanitised_html_sink', 'i'),
    ('warn', r'new[[:space:]]+Function[[:space:]]*\(', 'CWE-95:html_function_constructor', 'i'),
    ('warn', r'\batob[[:space:]]*\(', 'html:base64_decode_inspect_payload', 'i'),
    ('warn', r'''<script[^>]+src=["']?//[a-z0-9]''', 'html:protocol_relative_script_src', 'i'),
    ('warn', r'''<meta[^>]+http-equiv=["']?refresh[^>]+url=[^"'>]*//''', 'html:meta_refresh_external_redirect', 'i'),
    ('warn', r'''(href|src)=["']?javascript:[^"'>;]''', 'html:javascript_uri', 'i'),
]


def scan_html(f):
    if not grep_rules(f, _HTML_RULES):
        record_pass(f)


# ── Makefile ─────────────────────────────────────────────────────────────────
_MAKEFILE_RULES = [
    # download piped straight into a shell
    ('fail', r'(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|k)?sh\b', 'CWE-78:make_curl_pipe_shell_supply_chain'),
    # a $(shell ...) that fetches: runs at parse time
    ('fail', r'\$\(shell[^)]*\b(curl|wget|nc|ncat|ssh|scp)\b', 'CWE-78:make_shell_function_fetches_at_parse_time'),
    ('fail', r'base64[[:space:]]+(-d|-D|--decode)[^|]*\|[[:space:]]*(ba)?sh\b', 'CWE-78:make_base64_decoded_payload_executed'),
    # reverse shell (the leading word boundary keeps `nc` out of `sync`)
    ('fail', r'(\b(nc|ncat|netcat)[[:space:]]+-[A-Za-z]*e[A-Za-z]*[[:space:]]|/dev/tcp/)', 'CWE-78:make_reverse_shell'),
    # credential written into a variable ($(X), ${X} or empty is the correct form)
    ('fail', r'^[[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(password|passwd|secret|api_?key|token|credential)[A-Za-z0-9_]*[[:space:]]*[:+?!]?=[[:space:]]*[^[:space:]$]{6,}',
     'CWE-798:make_hardcoded_credential', 'i'),
    ('fail', r'(curl[^|]*([[:space:]]-k\b|--insecure)|wget[^|]*--no-check-certificate)', 'CWE-494:make_download_without_certificate_verification'),
    # setuid/setgid bit granted (`install -m 0755` is ordinary: the mode must start with 2 or 4)
    ('fail', r'(chmod[[:space:]]+[^;&|]*[ugo]*\+s|-m[[:space:]]*[24][0-7]{3})', 'CWE-732:make_setuid_or_setgid_bit'),
    ('fail', r'(crontab|/etc/cron\.|authorized_keys|/etc/systemd/system)', 'CWE-912:make_persistence_cron_or_authorized_keys'),
    # destructive delete of root or of the home directory: the target must be exactly / or ~ or $HOME
    ('fail', r'rm[[:space:]]+-[A-Za-z]*[rR][A-Za-z]*[[:space:]]+(/|~|\$\{?HOME\}?)([[:space:]]|/\*|$)',
     'make:destructive_recursive_delete_of_root_or_home'),
    # ── Review-worthy, but ordinary enough not to block ──
    ('warn', r'(^[[:space:]]*sudo[[:space:]]|[[:space:]]sudo[[:space:]])', 'make:sudo_in_recipe_runs_as_root'),
    ('warn', r'chmod[[:space:]]+(-[A-Za-z]+[[:space:]]+)*777', 'CWE-732:make_world_writable_chmod_777'),
    ('warn', r'(curl|wget)[^|]*http://', 'make:plaintext_http_download_no_transport_integrity'),
    ('warn', r'git[[:space:]]+clone[^;&|]*(http|git@)', 'make:clones_and_builds_from_a_remote_repository'),
]


def scan_makefile(f):
    if not grep_rules(f, _MAKEFILE_RULES):
        record_pass(f)


# ── PowerShell ───────────────────────────────────────────────────────────────
# PowerShell is case-insensitive throughout, so every match is -i. `iex` is matched before a space, a parenthesis or the end of
# the line; the backtick variants are the obfuscated spellings i`ex, ie`x and i`e`x.
_PS_IEXA = r'(invoke-expression|(^|[^[:alnum:]_.$-])(iex|i`e`?x|ie`x)([[:space:]]|\(|$))'
_PS_FETCH = r'(downloadstring|downloaddata|downloadfile|net\.webclient|invoke-webrequest|invoke-restmethod|start-bitstransfer|(^|[^[:alnum:]_.$-])(iwr|irm)([[:space:]]|\())'
_PS_RUN = r'''(start-process|invoke-item|msiexec|regsvr32|rundll32|(^|[;|{[:space:]])&[[:space:]]*["'$(])'''


def _ps_rules(f):
    """The PowerShell rule set shared by .ps1 and its relatives. -> True when a FAIL was recorded (PS_FAILED)."""
    failed = False
    gi = grep_check_i

    # CWE-78 — fetch, then execute (whole-file: `irm $u |` and `iex` can be on different lines)
    if (gi(_PS_IEXA, f) and gi(_PS_FETCH, f)) or gi(r'(curl|wget)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh([[:space:]]|$)', f):
        record_fail(f, "CWE-78:PowerShell_download_and_execute")
        failed = True
    # CWE-78 — a base64 command line (-EncodedCommand and its abbreviations)
    if gi(r'-encodedcommand', f) or gi(r'''(powershell|pwsh)(\.exe)?[^|;]*[[:space:]]-e[a-z]*[[:space:]]+["']?[A-Za-z0-9+/]{30,}''', f):
        record_fail(f, "CWE-78:PowerShell_EncodedCommand_obfuscation")
        failed = True
    # CWE-95 — decode a blob, then run it
    if gi(r'frombase64string', f) and (gi(_PS_IEXA, f) or gi(r'(scriptblock\]::create|assembly\]::load|virtualalloc|createthread)', f)):
        record_fail(f, "CWE-95:PowerShell_decodes_and_executes")
        failed = True
    # CWE-95 — a backtick inside the command name
    if gi(r'(^|[^[:alnum:]_.$-])(i`e`?x|ie`x)([[:space:]]|\(|$)', f):
        record_fail(f, "CWE-95:PowerShell_obfuscated_Invoke_Expression")
        failed = True
    # CWE-693 — defeating the Antimalware Scan Interface, or Defender itself
    if gi(r'(amsiinitfailed|amsiutils|amsiscanbuffer|amsicontext)', f):
        record_fail(f, "CWE-693:PowerShell_AMSI_bypass")
        failed = True
    if gi(r'set-mppreference[^|;]*-disable(realtimemonitoring|ioavprotection|behaviormonitoring|scriptscanning|intrusionpreventionsystem|blockatfirstseen)[[:space:]:=]*(\$true|1|true)', f):
        record_fail(f, "CWE-693:PowerShell_disables_Defender")
        failed = True
    # CWE-912 — persistence: a Run key, a WMI event subscription, or a file in the Startup folder
    if (gi(r'(new-itemproperty|set-itemproperty|reg(\.exe)?[[:space:]]+add)[^|;]*currentversion[\\]+run', f)
            or gi(r'(__eventfilter|commandlineeventconsumer|activescripteventconsumer)', f)
            or gi(r'(copy-item|move-item|set-content|out-file|add-content|new-item)[^|;]*[\\]start menu[\\]programs[\\]startup', f)):
        record_fail(f, "CWE-912:PowerShell_persistence")
        failed = True
    # CWE-78 — a socket whose stream is fed to a command interpreter
    if ((gi(r'tcpclient', f) and gi(r'getstream', f) and (gi(_PS_IEXA, f) or gi(r'(cmd\.exe|powershell)', f)))
            or gi(r'(nc(\.exe)?[[:space:]]+-[a-z]*e[[:space:]]|/dev/tcp/)', f)):
        record_fail(f, "CWE-78:PowerShell_reverse_shell")
        failed = True
    # CWE-94 — allocate executable memory and start a thread in it
    if gi(r'virtualalloc', f) and gi(r'(createthread|createremotethread|writeprocessmemory|marshal\]::copy)', f):
        record_fail(f, "CWE-94:PowerShell_in_memory_shellcode_loader")
        failed = True
    # CWE-506 — offensive tooling by name
    if gi(r'(invoke-mimikatz|invoke-shellcode|invoke-reflectivepeinjection|invoke-dllinjection|invoke-tokenmanipulation|invoke-kerberoast|invoke-powerdump|get-gpppassword|invoke-ninjacopy|sekurlsa::)', f):
        record_fail(f, "CWE-506:PowerShell_known_offensive_tool")
        failed = True
    # CWE-798 — a literal credential (the variable name must be exactly one of these)
    if (gi(r'''\$(password|passwd|secret|apikey|api_key|token|accesstoken|clientsecret|client_secret|authtoken)[[:space:]]*=[[:space:]]*["'][^"'$]{4,}["']''', f)
            or gi(r'''convertto-securestring[[:space:]]+["'][^"'$]{4,}["'][^|;]*-asplaintext''', f)):
        record_fail(f, "CWE-798:hardcoded_credential")
        failed = True
    # CWE-319 — a download over plaintext http://: it blocks if something is then run, alone it warns
    if gi(r'''(downloadfile|downloadstring|downloaddata|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer)[^;|]*["']http://''', f):
        if gi(_PS_RUN, f) or gi(_PS_IEXA, f):
            record_fail(f, "CWE-319:PowerShell_plaintext_download_then_run")
            failed = True
        else:
            record_warn(f, "powershell:plaintext_http_download")

    # ── Ordinary on their own: reported, not blocked ──
    if gi(_PS_IEXA, f):
        record_warn(f, "CWE-78:PowerShell_command_execution_Invoke_Expression")
    if gi(r'(start-process|cmd(\.exe)?[[:space:]]+/c)', f):
        record_warn(f, "CWE-78:PowerShell_command_execution_Start_Process")
    if gi(_PS_FETCH, f) and gi(_PS_RUN, f):
        record_warn(f, "powershell:downloads_then_runs_a_program")
    if gi(r'(set-executionpolicy|-executionpolicy|[[:space:]]-ep)[[:space:]]+(bypass|unrestricted)', f):
        record_warn(f, "powershell:execution_policy_bypass")
    if gi(r'(-windowstyle|[[:space:]]-w)[[:space:]]+h(idden)?([[:space:]]|$)', f):
        record_warn(f, "powershell:hidden_window")
    if gi(r'add-mppreference[^|;]*-exclusion', f):
        record_warn(f, "powershell:adds_a_Defender_exclusion")
    if gi(r'(schtasks(\.exe)?[[:space:]]+/create|register-scheduledtask|new-scheduledtask)', f):
        record_warn(f, "powershell:creates_a_scheduled_task")
    if gi(r'(servercertificatevalidationcallback[^;]*(\$true|\{[[:space:]]*\$true)|-skipcertificatecheck|trustallcertspolicy)', f):
        record_warn(f, "CWE-295:powershell_certificate_validation_disabled")
    if gi(r'(net(\.exe)?[[:space:]]+(user|localgroup)[^|;]*/add|new-localuser|add-localgroupmember)', f):
        record_warn(f, "powershell:creates_or_elevates_a_local_account")
    # `& ('ie' + 'x')`: a command name assembled from pieces
    if gi(r'''&[[:space:]]*\([[:space:]]*["'][^"')]{1,12}["'][[:space:]]*(\+|-f)''', f):
        record_warn(f, "powershell:command_name_built_from_strings")
    # Data files (.psd1 .pssc .psrc): these run code at import or define what a remote session may do
    if gi(r'''scriptstoprocess[[:space:]]*=[[:space:]]*@?\(?[[:space:]]*["']''', f):
        record_warn(f, "powershell:manifest_runs_scripts_at_import")
    if gi(r'''visible(cmdlets|functions|externalcommands|providers|aliases)[[:space:]]*=[[:space:]]*@?\(?[[:space:]]*["']\*''', f):
        record_warn(f, "powershell:role_capability_exposes_everything")
    return failed


def scan_powershell(f):
    if not _ps_rules(f):
        record_pass(f)


def scan_powershell_xml(f):
    """.ps1xml, .psc1, .cdxml: the PowerShell rules, then the external-entity check of scan_xml (newlines folded)."""
    failed = _ps_rules(f)
    G.FLAT_FILE, G.FLAT_INCOMPLETE = "", False
    if grep_flat(_XXE_RESOURCE, f):
        record_fail(f, "CWE-611:xxe_external_entity_references_a_resource")
        failed = True
    if G.FLAT_INCOMPLETE:
        failed = True
    if not failed:
        record_pass(f)
