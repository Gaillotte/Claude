"""Language scanners of the Python engine: layer 4 (the universal patterns of every file), Python and shell.

One function per scanner, named as in scan_pipeline.sh, and no module-level state. Other scanners of this group
(scan_javascript, scan_c_cpp, scan_java ...) are added here by the engineers who port them. Standard library only.
"""
import re

from transit.core import (_known_cred_check, grep_pipe, grep_rules, has_cmd, record_fail, record_pass, record_warn, run_tool)

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
        out = raw.decode("utf-8", "surrogateescape")
        if re.search(r"Severity: (MEDIUM|HIGH)", out):
            sev = re.search(r"Severity: [A-Za-z0-9_]+", out).group(0)
            line = next((ln for ln in out.split("\n") if "Test ID" in ln), "")
            record_fail(f, "bandit:%s:%s" % (sev, "\n".join(re.findall(r"B[0-9]+", line))))
            failed = True
    else:
        record_warn(f, "bandit missing")
    failed = grep_rules(f, _PYTHON_RULES) or failed
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
