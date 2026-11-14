"""Language scanners of the Python engine: layer 4 (the universal patterns of every file) and the scan_* functions of the
programming languages: Python, JavaScript, C and C++, shell, Java, PHP, Ruby, Go, SQL, Rust, Kotlin and C#.

One function per scanner, named as in scan_pipeline.sh and in the same order of checks. A run of `grep_check` calls of the
shell is a table of (level, pattern, message) rows and one `grep_rules` loop. The per-file tools (bandit, shellcheck,
cppcheck, Semgrep) go through run_tool with the shell's arguments. The only state is JS_RULESET_WARNED, the shell's global of
the same name. Standard library only.
"""
import json
import os
import re

from transit.core import (G, _known_cred_check, grep_check, grep_pipe, grep_rules, has_cmd, note_l5_partial, record_fail,
                          record_pass, record_warn, run_tool)


def _text(raw):
    """`out=$(tool ...)` read as text: NUL bytes are dropped, a byte that is not UTF-8 is kept as a surrogate."""
    return raw.replace(b"\0", b"").decode("utf-8", "surrogateescape")


# CWE-321: a real PEM header with a base64 body within a few lines; both greps read the file as text (-a).
_PEM_HEADER = r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----"
_PEM_BODY = _PEM_HEADER + r".{0,200}[A-Za-z0-9+/]{60,}"
_TR_SPACES = bytes.maketrans(b"\r\n\t", b"   ")

_UNIVERSAL_CREDENTIAL = [
    ('fail', r"""(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["'][^${"'[:space:]]{4,}""",
     'CWE-798:hardcoded_credential'),
]
_UNIVERSAL_REST = [
    ('warn', r'-----BEGIN CERTIFICATE-----', 'crypto:public_certificate_embedded'),
    ('fail', r'(%2e%2e|%252e%252e|\.\.%2f|\.\.%5c|%2f\.\.|%5c\.\.)', 'CWE-22:path_traversal_encoded', 'i'),
    ('fail', r"""\.\.[/\\][^[:space:]"'`]*((etc/)?(passwd|shadow)|\.ssh/|\.aws/|id_rsa|system32|proc/self)""",
     'CWE-22:path_traversal_to_sensitive_path', 'i'),
    ('fail', r"""(["'`]\.\.[/\\]["'`][[:space:]]*[+.][[:space:]]*|[+.][[:space:]]*["'`]/?\.\.[/\\]|f["'][^"']*(\{[^}]*\}[^"']*\.\.[/\\]|\.\.[/\\][^"']*\{[^}]*\})|`[^`]*(\$\{[^}]*\}[^`]*\.\.[/\\]|\.\.[/\\][^`]*\$\{))""",
     'CWE-22:path_traversal_composed_with_input', 'i'),
    ('warn', r'(requests\.get|urllib\.request|fetch|axios|http\.get)\s*\([^)]*\b(url|host|endpoint|target)\b',
     'CWE-918:potential_SSRF_unvalidated_URL'),
    ('warn', r'\b(md5|sha1|des|rc4|blowfish)\b', 'CWE-327:weak_crypto_algorithm'),
    ('warn', r'\b(Math\.random|random\.random|rand\(\)|mt_rand)\b', 'CWE-338:weak_PRNG_for_security'),
    ('warn', r'(TODO.*remove|FIXME.*auth|backdoor|test.*password|debug.*token|hardcoded.*key)',
     'OWASP-A02:debug_or_backdoor_comment'),
    ('warn', r'(logging\.disable|log_level.*NOTSET|setLevel.*CRITICAL.*security|disableStdoutLogger)',
     'OWASP-A09:logging_suppressed'),
]


def scan_universal_patterns(f):
    """Layer 4, run on every file first: credentials, private keys, known credential formats, traversal, weak crypto."""
    grep_rules(f, _UNIVERSAL_CREDENTIAL)
    if grep_pipe(["grep", "-aE", "-A5", "-e", _PEM_HEADER, "--", f], ["grep", "-aE", "-e", _PEM_BODY], tr=_TR_SPACES):
        record_fail(f, "CWE-321:hardcoded_private_key")
    _known_cred_check(f, f)
    grep_rules(f, _UNIVERSAL_REST)


_PYTHON_RULES = [
    ('fail', r'\b(os\.system|subprocess\.call|subprocess\.Popen|commands\.getoutput)\s*\(', 'CWE-78:OS_command_injection_risk'),
    ('fail', r'\b(eval|exec)\s*\(', 'CWE-95:dynamic_code_execution_eval_exec'),
    ('fail', r'\b(pickle\.loads|pickle\.load|marshal\.loads|yaml\.load\s*\([^,)]+\))\b',
     'CWE-502:insecure_deserialization_pickle_yaml'),
    ('fail', r"""(execute|executemany)[[:space:]]*\([[:space:]]*(f["']|("[^"]*"|'[^']*')[[:space:]]*(\+|%|\.format\())""",
     'CWE-89:SQL_injection_query_built_by_string_interpolation'),
    ('warn', r'(redirect|HttpResponseRedirect)\s*\(\s*request\.', 'CWE-601:potential_open_redirect'),
    ('fail', r'^\s*assert\s+(is_admin|is_authenticated|has_perm|user\.is)', 'CWE-703:assert_used_for_security_check'),
]


def scan_python(f):
    failed = False
    if has_cmd("bandit"):
        # `bandit -q -l -i "$f" 2>/dev/null || true`: the status is thrown away, the text is read
        _, raw = run_tool(["bandit", "-q", "-l", "-i", f])
        out = _text(raw)
        # Real bandit prints "Severity: High" and names the test in the Issue line above it; the "Test ID" form is still read.
        sev_m = re.search(r"Severity: (MEDIUM|HIGH)", out, re.I)
        if sev_m:
            line = next((ln for ln in out.split("\n") if "Test ID" in ln), "")
            bid = "\n".join(re.findall(r"B[0-9]+", line))
            if not bid:
                lines = out.split("\n")
                for i, ln in enumerate(lines):
                    if i > 0 and re.search(r"Severity: (MEDIUM|HIGH)", ln, re.I):
                        m = re.search(r"Issue: \[(B[0-9]+)", lines[i - 1])
                        if m:
                            bid = m.group(1)
                        break
            record_fail(f, "bandit:%s:%s" % (sev_m.group(0), bid))
            failed = True
    else:
        record_warn(f, "bandit missing")
    failed = grep_rules(f, _PYTHON_RULES) or failed
    if not failed:
        record_pass(f)


_JS_RULESET_WARNED = False
_JS_RULES = [
    ('fail', r'(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*[+]?=', 'CWE-79:XSS_innerHTML_document_write'),
    ('fail', r'\b(child_process|exec\s*\(|execSync\s*\(|spawn\s*\()', 'CWE-78:OS_command_injection_child_process'),
    ('fail', r'\beval\s*\(|new\s+Function\s*\(', 'CWE-95:dynamic_code_execution_eval'),
    ('warn', r'(DOMParser|parseXML|libxmljs\.parseXml)', 'CWE-611:potential_XXE_XML_parsing'),
    ('fail', r'(__proto__|constructor\[.prototype.\]|Object\.assign\s*\(\s*\{\})', 'CWE-1321:prototype_pollution'),
    ('fail', r'(Object\.assign|_\.merge|deepmerge)\s*\(\s*\w+\s*,\s*req\.', 'CWE-915:mass_assignment_req_merge'),
    ('fail', r'(query|raw|knex\.raw|sequelize\.query)\s*\(`[^`]*(SELECT|INSERT|UPDATE|DELETE)',
     'CWE-89:SQL_injection_template_literal'),
]


def scan_javascript(f):
    global _JS_RULESET_WARNED
    failed = False
    if has_cmd("semgrep"):
        # The rule set is the staged file, never a registry name; without it Semgrep is not run and layer 5 is partial.
        jsrules = G.SEMGREP_RULES_DIR + "/javascript.yaml"
        if os.path.isfile(jsrules):
            sg_rc, raw = run_tool(["semgrep", "--config=" + jsrules, "--quiet", "--json", "--no-autofix", "--metrics=off", f])
            try:                                       # the shell's `python3 -c 'print(len(json.load(sys.stdin)["results"]))'`
                cnt = len(json.loads(_text(raw))["results"])
            except Exception:
                cnt = None
            if sg_rc not in (0, 1):
                record_warn(f, "semgrep:js:scan_error_exit_%d" % sg_rc)
                note_l5_partial("semgrep javascript failed (exit %d)" % sg_rc)
            elif cnt is None:
                record_warn(f, "semgrep:js:output_could_not_be_read")
                note_l5_partial("semgrep javascript output could not be read")
            elif cnt > 0:
                record_fail(f, "semgrep:js:%d_findings" % cnt)
                failed = True
        else:
            note_l5_partial("javascript rule set not staged")
            if not _JS_RULESET_WARNED:
                _JS_RULESET_WARNED = True
                record_warn("__global__", "OFFLINE:semgrep javascript rule set not staged in %s — per-file JavaScript SAST "
                            "did NOT run; stage it with prepare_offline_cache.sh on a connected host" % G.SEMGREP_RULES_DIR)
    else:
        record_warn(f, "semgrep missing")
    failed = grep_rules(f, _JS_RULES) or failed
    if not failed:
        record_pass(f)


_C_CPP_RULES = [
    ('fail', r'\b(gets|gets_s|strcpy|strcat|sprintf|vsprintf)\s*\(', 'CWE-120:unsafe_string_function_gets_strcpy_sprintf'),
    ('fail', r'\b(system|popen|execl|execle|execlp|execv|execve|execvp)\s*\(', 'CWE-78:OS_command_execution'),
    ('fail', r'(printf|fprintf|sprintf|syslog)\s*\(\s*(argv|getenv|user_input|stdin)', 'CWE-134:format_string_user_input'),
    ('warn', r'malloc\s*\(\s*[a-z_]+\s*\*\s*[a-z_]+\s*\)', 'CWE-190:potential_integer_overflow_in_malloc'),
    ('warn', r'\bfree\s*\(\s*\w+\s*\).*\bfree\s*\(\s*\w+\s*\)', 'CWE-415:potential_double_free'),
    ('warn', r'\brand\s*\(\)', 'CWE-338:rand_not_cryptographically_secure'),
    ('fail', r'\b(tmpnam|tempnam|mktemp)\s*\(', 'CWE-377:TOCTOU_insecure_temp_file'),
]


def scan_c_cpp(f):
    failed = False
    if has_cmd("cppcheck"):
        # `cppcheck --enable=all --quiet "$f" 2>&1 || true`: stderr is part of the text, the status is thrown away
        _, raw = run_tool(["cppcheck", "--enable=all", "--quiet", f], merge_stderr=True)
        out = _text(raw)
        if re.search(r"error:|warning:", out):
            first_err = re.search(r"(error|warning):[^$\n]+", out)        # `grep -oE '(error|warning):[^$]+' | head -1`
            record_fail(f, "cppcheck:%s" % (first_err.group(0) if first_err else ""))
            failed = True
    else:
        record_warn(f, "cppcheck missing")
    failed = grep_rules(f, _C_CPP_RULES) or failed
    if not failed:
        record_pass(f)


_SHELL_RULES = [
    ('fail', r'curl\s+.*\|\s*(bash|sh)|wget\s+.*\|\s*(bash|sh)', 'CWE-78:remote_code_execution_curl_pipe_bash'),
    ('fail', r'eval\s+\$', 'CWE-88:eval_variable_injection'),
    ('warn', r"""export\s+PATH\s*=\s*['"]?[^/]""", 'CWE-426:PATH_starts_with_relative_directory'),
    ('warn', r'/tmp/\$\$|/tmp/[a-z_]+[^/]*(tmp|temp)', 'CWE-377:predictable_temp_file_name'),
    ('warn', r"""IFS\s*=\s*['"]?""", 'shell:IFS_manipulation'),
]


def scan_shell(f):
    failed = False
    if has_cmd("shellcheck"):
        # the findings it prints on stdout are not echoed (tool output never reaches the console raw)
        rc, _ = run_tool(["shellcheck", "-S", "warning", f])
        if rc != 0:
            record_fail(f, "shellcheck:warnings")
            failed = True
    else:
        record_warn(f, "shellcheck missing")
    failed = grep_rules(f, _SHELL_RULES) or failed
    if not failed:
        record_pass(f)


_JAVA_RULES = [
    ('fail', r'(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(', 'CWE-78:OS_command_injection_Runtime_exec'),
    ('fail', r'(createQuery|createNativeQuery|prepareStatement)\s*\(\s*"[^"]*"\s*\+', 'CWE-89:SQL_injection_string_concat_JDBC'),
    ('warn', r'response\.(getWriter|getOutputStream).*request\.getParameter', 'CWE-79:XSS_unsanitized_param_in_response'),
    ('fail', r'\b(ObjectInputStream|XMLDecoder|XStream)\b', 'CWE-502:insecure_deserialization_ObjectInputStream'),
    ('fail', r'(jndi:|ldap://|rmi://|\$\{jndi)', 'CVE-2021-44228:Log4Shell_JNDI_injection'),
    ('fail', r'(TrustAllCerts|X509TrustManager|checkClientTrusted|checkServerTrusted)\s*\{',
     'CWE-295:improper_certificate_validation_TrustAll'),
    ('warn', r'DocumentBuilderFactory\.newInstance\(\)', 'CWE-611:potential_XXE_DocumentBuilder_check_entity_config'),
]


def scan_java(f):
    if not grep_rules(f, _JAVA_RULES):
        record_pass(f)


_PHP_RULES = [
    ('fail', r'\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(', 'CWE-78:OS_command_injection_shell_exec'),
    ('fail', r'(mysql_query|mysqli_query|pg_query)\s*\(.*\.\s*\$', 'CWE-89:SQL_injection_string_concat'),
    ('fail', r'echo\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)', 'CWE-79:XSS_echo_unsanitized_superglobal'),
    ('fail', r'\b(include|require|include_once|require_once)\s*\(\s*\$', 'CWE-22:path_traversal_dynamic_include'),
    ('fail', r'\bunserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)', 'CWE-502:insecure_deserialization_unserialize'),
]


def scan_php(f):
    if not grep_rules(f, _PHP_RULES):
        record_pass(f)


_RUBY_RULES = [
    ('fail', r'\b(system|exec|Kernel\.exec|%x\{|`[^`]+`)', 'CWE-78:OS_command_injection'),
    ('fail', r'\beval\s*[({]', 'CWE-95:dynamic_code_execution_eval'),
    ('fail', r'(where|find_by_sql|execute)\s*\(\s*"[^"]*#\{', 'CWE-89:SQL_injection_ActiveRecord_interpolation'),
    ('fail', r'(File\.read|File\.open|IO\.read)\s*\(\s*params\[', 'CWE-22:path_traversal_params_in_file_read'),
]


def scan_ruby(f):
    if not grep_rules(f, _RUBY_RULES):
        record_pass(f)


_GO_RULES = [
    ('warn', r'\bexec\.Command\s*\(', 'CWE-78:OS_command_execution_exec_Command'),
    ('fail', r'fmt\.Sprintf.*\b(SELECT|INSERT|UPDATE|DELETE)\b', 'CWE-89:SQL_injection_fmt_Sprintf'),
    ('warn', r'(os\.Open|ioutil\.ReadFile|http\.ServeFile)\s*\(\s*(r\.URL|req\.URL|path)', 'CWE-22:potential_path_traversal'),
    ('warn', r'"math/rand"', 'CWE-338:math_rand_not_crypto_safe_use_crypto_rand'),
]


def scan_go(f):
    failed = grep_rules(f, _GO_RULES)
    # G404: a tls.Config{ in a file that never mentions MinVersion
    if grep_check(r'tls\.Config\s*\{', f) and not grep_check('MinVersion', f):
        record_warn(f, "CWE-326:TLS_config_without_MinVersion")
    if not failed:
        record_pass(f)


_SQL_RULES = [
    ('fail', r'(xp_cmdshell|sp_OACreate|OPENROWSET|BULK INSERT)', 'CWE-78:SQL_OS_execution_xp_cmdshell'),
    ('fail', r'DROP\s+(TABLE|DATABASE|SCHEMA|VIEW|FUNCTION|PROCEDURE)', 'CWE-89:destructive_DDL_statement'),
    ('fail', r"""(;\s*--|'--|\b(OR|AND)\s+['"]?1['"]?\s*=\s*['"]?1)""", 'CWE-89:SQL_injection_pattern'),
    ('fail', r'\bUNION\s+(ALL\s+)?SELECT\b', 'CWE-89:SQL_UNION_injection_payload'),
]


def scan_sql(f):
    if not grep_rules(f, _SQL_RULES):
        record_pass(f)


_RUST_RULES = [
    ('fail', r'\bunsafe\s*\{', 'CWE-119:unsafe_block_requires_review'),
    ('fail', r'std::process::Command', 'CWE-78:process_Command_exec'),
    ('fail', r'(password|secret|api_key|token)\s*=\s*"[^"]{4,}"', 'CWE-798:hardcoded_credential'),
]


def scan_rust(f):
    if not grep_rules(f, _RUST_RULES):
        record_pass(f)


_KOTLIN_RULES = [
    ('fail', r'Runtime\.getRuntime\(\)\.exec\(', 'CWE-78:Runtime_exec_command_injection'),
    ('fail', r'(password|secret|apiKey|api_key|token)\s*=\s*"[^"]{4,}"', 'CWE-798:hardcoded_credential'),
    ('fail', r'MessageDigest\.getInstance\("(MD5|SHA-1)"', 'CWE-327:weak_hash_MD5_or_SHA1'),
]


def scan_kotlin(f):
    if not grep_rules(f, _KOTLIN_RULES):
        record_pass(f)


_CSHARP_RULES = [
    ('fail', r'Process\.Start\s*\(', 'CWE-78:Process_Start_command_injection'),
    ('fail', r'(password|secret|apiKey|api_key|token)\s*=\s*"[^"]{4,}"', 'CWE-798:hardcoded_credential'),
    ('fail', r'new\s+MD5CryptoServiceProvider\s*\(\)', 'CWE-327:MD5_weak_hash_algorithm'),
    ('fail', r'"SELECT.*"\s*\+', 'CWE-89:SQL_string_concatenation'),
]


def scan_csharp(f):
    if not grep_rules(f, _CSHARP_RULES):
        record_pass(f)
