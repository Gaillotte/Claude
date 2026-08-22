#!/usr/bin/env bash
# Scan de sécurité multicouche — OWASP Top 10 · CWE Top 25 · CERT · SCA
set -euo pipefail

WORK_DIR="${WORK_DIR:-/opt/ai-transit}"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# ── Fonctions de log ────────────────────────────────────────────────────────
log()    { echo "[$(date '+%H:%M:%S')] $*"; }
info()   { echo -e "\033[34m[INFO]\033[0m  $*"; }
warn()   { echo -e "\033[33m[WARN]\033[0m  $*" >&2; }
ok()     { echo -e "\033[32m[OK]\033[0m    $*"; }
fail()   { echo -e "\033[31m[FAIL]\033[0m  $*" >&2; exit 1; }
fail_f() { echo -e "\033[31m[FAIL]\033[0m  $*" >&2; GLOBAL_VERDICT="FAIL"; }

has_cmd() { command -v "$1" &>/dev/null; }

# ── Argument ─────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    fail "Usage : $0 <directory_to_scan>"
fi

SCAN_DIR="$1"
[[ -d "$SCAN_DIR" ]] || fail "Directory not found: $SCAN_DIR"

GLOBAL_VERDICT="PASS"
declare -A FINDINGS      # path → concatenated FAIL messages
declare -A FILE_STATUS   # path → PASS | FAIL | WARN
declare -A FILE_MSG      # path → message
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

mkdir -p "${WORK_DIR}/reports" "${WORK_DIR}/quarantine" "${WORK_DIR}/approved"
chmod 700 "${WORK_DIR}/quarantine"

REPORT_JSON="${WORK_DIR}/reports/report_${TIMESTAMP}.json"
REPORT_HTML="${WORK_DIR}/reports/report_${TIMESTAMP}.html"

# ── Helpers ──────────────────────────────────────────────────────────────────
record_pass() {
    local file="${1:-}"
    (( PASS_COUNT++ )) || true
    if [[ -n "$file" && -z "${FILE_STATUS[$file]:-}" ]]; then
        FILE_STATUS["$file"]="PASS"
        FILE_MSG["$file"]=""
    fi
}

record_warn() {
    local file="${1:-__global__}"; shift
    (( WARN_COUNT++ )) || true
    warn "$*"
    if [[ -z "${FILE_STATUS[$file]:-}" ]]; then
        FILE_STATUS["$file"]="WARN"
        FILE_MSG["$file"]="$*"
    fi
}

record_fail() {
    local file="$1"; shift
    local msg="$*"
    FINDINGS["$file"]+="${msg} | "
    FILE_STATUS["$file"]="FAIL"
    FILE_MSG["$file"]+="${msg} | "
    (( FAIL_COUNT++ )) || true
    fail_f "[$file] $msg"
}

# grep helper: returns 0 if pattern found, never fails the script
grep_check() { grep -qE "$1" "$2" 2>/dev/null; }

# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — GLOBAL (malware, secrets, AV)
# ═══════════════════════════════════════════════════════════════════════════════
scan_global() {
    info "=== Layer 1: Global (AV, secrets, IOC) ==="

    if has_cmd betterleaks; then
        info "betterleaks…"
        if ! betterleaks dir "$SCAN_DIR" -v 2>/dev/null; then
            record_fail "$SCAN_DIR" "betterleaks:secrets_detected"
        else
            record_pass "$SCAN_DIR"
            ok "betterleaks: no secrets"
        fi
    else
        record_warn "__global__" "betterleaks missing — secret scan skipped"
    fi

    if has_cmd detect-secrets; then
        info "detect-secrets…"
        local dsec_out
        dsec_out=$(detect-secrets scan "$SCAN_DIR" 2>/dev/null || true)
        if echo "$dsec_out" | grep -q '"type"'; then
            record_fail "$SCAN_DIR" "detect-secrets:high_entropy_string"
        else
            record_pass "$SCAN_DIR"
            ok "detect-secrets: no anomaly"
        fi
    else
        record_warn "__global__" "detect-secrets missing"
    fi

    if has_cmd clamscan; then
        info "clamscan…"
        if ! clamscan -r --quiet "$SCAN_DIR" 2>/dev/null; then
            record_fail "$SCAN_DIR" "clamav:malware_detected"
        else
            record_pass "$SCAN_DIR"
            ok "ClamAV: clean"
        fi
    else
        record_warn "__global__" "clamscan missing"
    fi

    if has_cmd yara && [[ -d "${WORK_DIR}/yara-rules" ]]; then
        local yara_files=( "${WORK_DIR}/yara-rules/"*.yar )
        if [[ -f "${yara_files[0]:-}" ]]; then
            info "yara…"
            for rule in "${yara_files[@]}"; do
                if yara -r "$rule" "$SCAN_DIR" 2>/dev/null | grep -q .; then
                    record_fail "$SCAN_DIR" "yara:ioc_match:$(basename "$rule")"
                fi
            done
            ok "YARA: no IOC"
        fi
    else
        record_warn "__global__" "yara or rules directory missing"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — OWASP Top 10 2021 + CWE Top 25 via Semgrep
# Ref: https://owasp.org/Top10/  https://cwe.mitre.org/top25/
# ═══════════════════════════════════════════════════════════════════════════════
scan_owasp_cwe() {
    info "=== Layer 2: OWASP Top 10 2021 + CWE Top 25 (Semgrep) ==="

    if ! has_cmd semgrep; then
        record_warn "__global__" "semgrep missing — OWASP/CWE layer skipped (pip install semgrep)"
        return
    fi

    local rulesets=(
        "p/owasp-top-ten"    # OWASP Top 10 2021
        "p/cwe-top-25"       # CWE Top 25 Most Dangerous
        "p/security-audit"   # generic security audit
        "p/secrets"          # additional secret patterns
    )

    local found_any=false
    for ruleset in "${rulesets[@]}"; do
        info "  semgrep ${ruleset}…"
        local out
        out=$(semgrep --config="${ruleset}" --quiet --json \
              --no-autofix "$SCAN_DIR" 2>/dev/null || true)

        if echo "$out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
results = data.get('results', [])
if results:
    for r in results:
        path   = r.get('path', '')
        rule   = r.get('check_id', '')
        msg    = r.get('extra', {}).get('message', '')
        line   = r.get('start', {}).get('line', '')
        sev    = r.get('extra', {}).get('severity', 'INFO')
        print(f'{path}|||{rule}|||{msg[:120]}|||{line}|||{sev}')
    sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
            ok "  ${ruleset}: no findings"
        else
            local semgrep_out
            semgrep_out=$(semgrep --config="${ruleset}" --quiet --json \
                          --no-autofix "$SCAN_DIR" 2>/dev/null || true)
            while IFS='|||' read -r path rule msg line sev; do
                [[ -z "$path" ]] && continue
                record_fail "$path" "semgrep[${ruleset}]:${rule}:line${line}:${sev}:${msg}"
            done < <(echo "$semgrep_out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('results', []):
    path = r.get('path','')
    rule = r.get('check_id','')
    msg  = r.get('extra',{}).get('message','')[:120]
    line = str(r.get('start',{}).get('line',''))
    sev  = r.get('extra',{}).get('severity','INFO')
    print(f'{path}|||{rule}|||{msg}|||{line}|||{sev}')
" 2>/dev/null || true)
            found_any=true
        fi
    done

    $found_any || ok "OWASP/CWE scan: no findings"
}

# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — Software Composition Analysis (SCA) — vulnerable dependencies
# Ref: OWASP A06:2021 Vulnerable and Outdated Components
# ═══════════════════════════════════════════════════════════════════════════════
scan_dependencies() {
    info "=== Layer 3: SCA — Vulnerable dependencies (OWASP A06) ==="

    # trivy: universal SCA (Python, JS, Go, Ruby, Java, etc.)
    if has_cmd trivy; then
        info "trivy fs…"
        local trivy_out
        trivy_out=$(trivy fs --quiet --exit-code 0 --format json "$SCAN_DIR" 2>/dev/null || true)
        local vuln_count
        vuln_count=$(echo "$trivy_out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
total = sum(len(r.get('Vulnerabilities') or [])
            for res in data.get('Results', [])
            for r in [res])
print(total)
" 2>/dev/null || echo "0")
        if [[ "$vuln_count" -gt 0 ]]; then
            record_fail "$SCAN_DIR" "trivy:${vuln_count}_vulnerable_dependencies"
        else
            record_pass "$SCAN_DIR"
            ok "trivy: no known CVEs"
        fi
    else
        record_warn "__global__" "trivy missing — dependency CVE scan skipped"
    fi

    # pip-audit: Python requirements
    local req_files
    req_files=$(find "$SCAN_DIR" -name "requirements*.txt" -o -name "Pipfile.lock" \
                -o -name "pyproject.toml" 2>/dev/null | head -5)
    if [[ -n "$req_files" ]]; then
        if has_cmd pip-audit; then
            info "pip-audit…"
            echo "$req_files" | while read -r req; do
                local out
                out=$(pip-audit -r "$req" --format json 2>/dev/null || true)
                local count
                count=$(echo "$out" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(len([v for dep in d.get('dependencies',[]) for v in dep.get('vulns',[])]))
" 2>/dev/null || echo "0")
                if [[ "$count" -gt 0 ]]; then
                    record_fail "$req" "pip-audit:${count}_CVEs_in_dependencies"
                fi
            done
        elif has_cmd safety; then
            info "safety check…"
            echo "$req_files" | while read -r req; do
                if ! safety check -r "$req" --quiet 2>/dev/null; then
                    record_fail "$req" "safety:vulnerable_python_dependency"
                fi
            done
        else
            record_warn "__global__" "pip-audit/safety missing — Python dep CVE scan skipped"
        fi
    fi

    # npm audit: JavaScript package.json
    local pkg_files
    pkg_files=$(find "$SCAN_DIR" -name "package-lock.json" -o -name "yarn.lock" 2>/dev/null | head -3)
    if [[ -n "$pkg_files" ]]; then
        if has_cmd npm; then
            info "npm audit…"
            echo "$pkg_files" | while read -r pkg; do
                local pkg_dir
                pkg_dir=$(dirname "$pkg")
                local out
                out=$(npm audit --json --prefix "$pkg_dir" 2>/dev/null || true)
                local count
                count=$(echo "$out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('metadata',{}).get('vulnerabilities',{}).get('total', 0))
" 2>/dev/null || echo "0")
                if [[ "$count" -gt 0 ]]; then
                    record_fail "$pkg" "npm-audit:${count}_vulnerable_packages"
                fi
            done
        else
            record_warn "__global__" "npm missing — JS dependency CVE scan skipped"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — Universal security patterns (all file types)
# Covers: CWE-259, CWE-321, CWE-798, CWE-22, CWE-918, CWE-327, CWE-338
# ═══════════════════════════════════════════════════════════════════════════════
scan_universal_patterns() {
    local f="$1"
    local triggered=false

    # CWE-798 / CWE-259 — Hardcoded credentials
    if grep_check \
        '(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["'"'"'][^${"'"'"'\s]{4,}' \
        "$f"; then
        record_fail "$f" "CWE-798:hardcoded_credential"
        triggered=true
    fi

    # CWE-321 — Hardcoded cryptographic key
    if grep_check \
        '(PRIVATE KEY|CERTIFICATE|BEGIN RSA|BEGIN EC|BEGIN DSA|BEGIN OPENSSH)' \
        "$f"; then
        record_fail "$f" "CWE-321:hardcoded_crypto_key"
        triggered=true
    fi

    # CWE-22 — Path traversal
    if grep_check \
        '(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)' \
        "$f"; then
        record_fail "$f" "CWE-22:path_traversal_pattern"
        triggered=true
    fi

    # CWE-918 — Server-Side Request Forgery (SSRF)
    if grep_check \
        '(requests\.get|urllib\.request|fetch|axios|http\.get)\s*\([^)]*\b(url|host|endpoint|target)\b' \
        "$f"; then
        record_warn "$f" "CWE-918:potential_SSRF_unvalidated_URL"
    fi

    # CWE-327 — Broken cryptographic algorithm (MD5/SHA1 for security use)
    if grep_check \
        '\b(md5|sha1|des|rc4|blowfish)\b' \
        "$f"; then
        record_warn "$f" "CWE-327:weak_crypto_algorithm"
    fi

    # CWE-338 — Cryptographically weak PRNG
    if grep_check \
        '\b(Math\.random|random\.random|rand\(\)|mt_rand)\b' \
        "$f"; then
        record_warn "$f" "CWE-338:weak_PRNG_for_security"
    fi

    # OWASP A02 — debug/backdoor artefacts left by AI generators
    if grep_check \
        '(TODO.*remove|FIXME.*auth|backdoor|test.*password|debug.*token|hardcoded.*key)' \
        "$f"; then
        record_warn "$f" "OWASP-A02:debug_or_backdoor_comment"
    fi

    # OWASP A09 — insufficient logging (no log of security events)
    # Detected by absence is too noisy; flag explicit log suppression instead
    if grep_check \
        '(logging\.disable|log_level.*NOTSET|setLevel.*CRITICAL.*security|disableStdoutLogger)' \
        "$f"; then
        record_warn "$f" "OWASP-A09:logging_suppressed"
    fi

    $triggered || true  # do not set PASS here — handled by per-type scanner
}

# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — Per-type SAST scanners
# ═══════════════════════════════════════════════════════════════════════════════

# ── Python ───────────────────────────────────────────────────────────────────
# OWASP: A03 Injection · A02 Crypto · A08 Software Integrity
# CWE: 78, 89, 327, 502, 601, 703
scan_python() {
    local f="$1"
    local failed=false

    # Bandit: full SAST (maps findings to CWE automatically)
    if has_cmd bandit; then
        local out
        out=$(bandit -q -l -i "$f" 2>/dev/null || true)
        if echo "$out" | grep -qE 'Severity: (MEDIUM|HIGH)'; then
            local sev
            sev=$(echo "$out" | grep -oE 'Severity: \w+' | head -1)
            record_fail "$f" "bandit:${sev}:$(echo "$out" | grep 'Test ID' | head -1 | grep -oE 'B[0-9]+')"
            failed=true
        fi
    else
        record_warn "$f" "bandit missing"
    fi

    # CWE-78 — OS command injection
    if grep_check '\b(os\.system|subprocess\.call|subprocess\.Popen|commands\.getoutput)\s*\(' "$f"; then
        record_fail "$f" "CWE-78:OS_command_injection_risk"
        failed=true
    fi

    # CWE-95 / CWE-78 — eval/exec dynamic execution
    if grep_check '\b(eval|exec)\s*\(' "$f"; then
        record_fail "$f" "CWE-95:dynamic_code_execution_eval_exec"
        failed=true
    fi

    # CWE-502 — Insecure deserialization
    if grep_check '\b(pickle\.loads|pickle\.load|marshal\.loads|yaml\.load\s*\([^,)]+\))\b' "$f"; then
        record_fail "$f" "CWE-502:insecure_deserialization_pickle_yaml"
        failed=true
    fi

    # CWE-89 — SQL injection (string concatenation in queries)
    if grep_check '(execute|cursor\.execute)\s*\(\s*[f'"'"'"].*(SELECT|INSERT|UPDATE|DELETE|DROP)' "$f"; then
        record_fail "$f" "CWE-89:SQL_injection_string_concat"
        failed=true
    fi

    # CWE-601 — Open redirect
    if grep_check '(redirect|HttpResponseRedirect)\s*\(\s*request\.' "$f"; then
        record_warn "$f" "CWE-601:potential_open_redirect"
    fi

    # CWE-703 — assert used for security checks (stripped in optimized builds)
    if grep_check '^\s*assert\s+(is_admin|is_authenticated|has_perm|user\.is)' "$f"; then
        record_fail "$f" "CWE-703:assert_used_for_security_check"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────────
# OWASP: A03 Injection · A05 Misconfiguration · A07 Auth
# CWE: 79, 78, 89, 611, 915, 1321
scan_javascript() {
    local f="$1"
    local failed=false

    if has_cmd semgrep; then
        local out
        out=$(semgrep --config=p/javascript --quiet --json --no-autofix "$f" 2>/dev/null || true)
        local cnt
        cnt=$(echo "$out" | python3 -c "
import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))
" 2>/dev/null || echo "0")
        if [[ "$cnt" -gt 0 ]]; then
            record_fail "$f" "semgrep:js:${cnt}_findings"
            failed=true
        fi
    else
        record_warn "$f" "semgrep missing"
    fi

    # CWE-79 — XSS via innerHTML/document.write/outerHTML
    if grep_check '(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*[+]?=' "$f"; then
        record_fail "$f" "CWE-79:XSS_innerHTML_document_write"
        failed=true
    fi

    # CWE-78 — OS command injection
    if grep_check '\b(child_process|exec\s*\(|execSync\s*\(|spawn\s*\()' "$f"; then
        record_fail "$f" "CWE-78:OS_command_injection_child_process"
        failed=true
    fi

    # CWE-95 — eval / Function() constructor
    if grep_check '\beval\s*\(|new\s+Function\s*\(' "$f"; then
        record_fail "$f" "CWE-95:dynamic_code_execution_eval"
        failed=true
    fi

    # CWE-611 — XXE via DOMParser/libxmljs without entity disabling
    if grep_check '(DOMParser|parseXML|libxmljs\.parseXml)' "$f"; then
        record_warn "$f" "CWE-611:potential_XXE_XML_parsing"
    fi

    # CWE-1321 — Prototype pollution
    if grep_check '(__proto__|constructor\[.prototype.\]|Object\.assign\s*\(\s*\{\})' "$f"; then
        record_fail "$f" "CWE-1321:prototype_pollution"
        failed=true
    fi

    # CWE-915 — Mass assignment / loose object merge
    if grep_check '(Object\.assign|_\.merge|deepmerge)\s*\(\s*\w+\s*,\s*req\.' "$f"; then
        record_fail "$f" "CWE-915:mass_assignment_req_merge"
        failed=true
    fi

    # CWE-89 — SQL injection in JS ORM
    if grep_check '(query|raw|knex\.raw|sequelize\.query)\s*\(`[^`]*(SELECT|INSERT|UPDATE|DELETE)' "$f"; then
        record_fail "$f" "CWE-89:SQL_injection_template_literal"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── C / C++ ──────────────────────────────────────────────────────────────────
# CWE: 120, 121, 122, 134, 190, 415, 416
# CERT: STR31-C, MEM30-C, INT30-C
scan_c_cpp() {
    local f="$1"
    local failed=false

    if has_cmd cppcheck; then
        local out
        out=$(cppcheck --enable=all --quiet "$f" 2>&1 || true)
        if echo "$out" | grep -qE 'error:|warning:'; then
            local first_err
            first_err=$(echo "$out" | grep -oE '(error|warning):[^$]+' | head -1)
            record_fail "$f" "cppcheck:${first_err}"
            failed=true
        fi
    else
        record_warn "$f" "cppcheck missing"
    fi

    # CWE-120 / CERT STR31-C — classic buffer overflow functions
    if grep_check '\b(gets|gets_s|strcpy|strcat|sprintf|vsprintf)\s*\(' "$f"; then
        record_fail "$f" "CWE-120:unsafe_string_function_gets_strcpy_sprintf"
        failed=true
    fi

    # CWE-78 / CERT ENV33-C — shell execution
    if grep_check '\b(system|popen|execl|execle|execlp|execv|execve|execvp)\s*\(' "$f"; then
        record_fail "$f" "CWE-78:OS_command_execution"
        failed=true
    fi

    # CWE-134 — Format string vulnerability
    if grep_check '(printf|fprintf|sprintf|syslog)\s*\(\s*(argv|getenv|user_input|stdin)' "$f"; then
        record_fail "$f" "CWE-134:format_string_user_input"
        failed=true
    fi

    # CWE-190 — Integer overflow before allocation
    if grep_check 'malloc\s*\(\s*[a-z_]+\s*\*\s*[a-z_]+\s*\)' "$f"; then
        record_warn "$f" "CWE-190:potential_integer_overflow_in_malloc"
    fi

    # CWE-415 / CWE-416 — Double free / use-after-free
    if grep_check '\bfree\s*\(\s*\w+\s*\).*\bfree\s*\(\s*\w+\s*\)' "$f"; then
        record_warn "$f" "CWE-415:potential_double_free"
    fi

    # CWE-338 — CERT MSC30-C: rand() not suitable for security
    if grep_check '\brand\s*\(\)' "$f"; then
        record_warn "$f" "CWE-338:rand_not_cryptographically_secure"
    fi

    # CERT FIO45-C — TOCTOU race condition on temp files
    if grep_check '\b(tmpnam|tempnam|mktemp)\s*\(' "$f"; then
        record_fail "$f" "CWE-377:TOCTOU_insecure_temp_file"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── Shell ─────────────────────────────────────────────────────────────────────
# CWE: 78, 88, 377, 426
scan_shell() {
    local f="$1"
    local failed=false

    if has_cmd shellcheck; then
        if ! shellcheck -S warning "$f" 2>/dev/null; then
            record_fail "$f" "shellcheck:warnings"
            failed=true
        fi
    else
        record_warn "$f" "shellcheck missing"
    fi

    # CWE-78 — remote code execution via download+execute
    if grep_check 'curl\s+.*\|\s*(bash|sh)|wget\s+.*\|\s*(bash|sh)' "$f"; then
        record_fail "$f" "CWE-78:remote_code_execution_curl_pipe_bash"
        failed=true
    fi

    # CWE-88 — eval with variable (argument injection)
    if grep_check 'eval\s+\$' "$f"; then
        record_fail "$f" "CWE-88:eval_variable_injection"
        failed=true
    fi

    # CWE-426 — PATH hijacking (unqualified command with custom PATH)
    if grep_check 'export\s+PATH\s*=\s*['"'"'"]?[^/]' "$f"; then
        record_warn "$f" "CWE-426:PATH_starts_with_relative_directory"
    fi

    # CWE-377 — Insecure temp file (predictable name)
    if grep_check '/tmp/\$\$|/tmp/[a-z_]+[^/]*(tmp|temp)' "$f"; then
        record_warn "$f" "CWE-377:predictable_temp_file_name"
    fi

    # IFS manipulation (risk of word-splitting bypass)
    if grep_check 'IFS\s*=\s*['"'"'"]?' "$f"; then
        record_warn "$f" "shell:IFS_manipulation"
    fi

    $failed || record_pass "$f"
}

# ── Java ─────────────────────────────────────────────────────────────────────
# CWE: 78, 89, 79, 502, 295, 611
scan_java() {
    local f="$1"
    local failed=false

    # CWE-78 — OS command injection
    if grep_check '(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(' "$f"; then
        record_fail "$f" "CWE-78:OS_command_injection_Runtime_exec"
        failed=true
    fi

    # CWE-89 — SQL injection via string concatenation
    if grep_check '(createQuery|createNativeQuery|prepareStatement)\s*\(\s*"[^"]*"\s*\+' "$f"; then
        record_fail "$f" "CWE-89:SQL_injection_string_concat_JDBC"
        failed=true
    fi

    # CWE-79 — XSS in servlet response
    if grep_check 'response\.(getWriter|getOutputStream).*request\.getParameter' "$f"; then
        record_warn "$f" "CWE-79:XSS_unsanitized_param_in_response"
    fi

    # CWE-502 — Insecure deserialization
    if grep_check '\b(ObjectInputStream|XMLDecoder|XStream)\b' "$f"; then
        record_fail "$f" "CWE-502:insecure_deserialization_ObjectInputStream"
        failed=true
    fi

    # Log4Shell / JNDI injection
    if grep_check '(jndi:|ldap://|rmi://|\$\{jndi)' "$f"; then
        record_fail "$f" "CVE-2021-44228:Log4Shell_JNDI_injection"
        failed=true
    fi

    # CWE-295 — Improper certificate validation
    if grep_check '(TrustAllCerts|X509TrustManager|checkClientTrusted|checkServerTrusted)\s*\{' "$f"; then
        record_fail "$f" "CWE-295:improper_certificate_validation_TrustAll"
        failed=true
    fi

    # CWE-611 — XXE via DocumentBuilder without disabling entities
    if grep_check 'DocumentBuilderFactory\.newInstance\(\)' "$f"; then
        record_warn "$f" "CWE-611:potential_XXE_DocumentBuilder_check_entity_config"
    fi

    $failed || record_pass "$f"
}

# ── PHP ───────────────────────────────────────────────────────────────────────
# CWE: 78, 89, 79, 22, 502
scan_php() {
    local f="$1"
    local failed=false

    # CWE-78 — command injection
    if grep_check '\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(' "$f"; then
        record_fail "$f" "CWE-78:OS_command_injection_shell_exec"
        failed=true
    fi

    # CWE-89 — SQL injection
    if grep_check '(mysql_query|mysqli_query|pg_query)\s*\(.*\.\s*\$' "$f"; then
        record_fail "$f" "CWE-89:SQL_injection_string_concat"
        failed=true
    fi

    # CWE-79 — XSS via echo without htmlspecialchars
    if grep_check 'echo\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)' "$f"; then
        record_fail "$f" "CWE-79:XSS_echo_unsanitized_superglobal"
        failed=true
    fi

    # CWE-22 — Path traversal via include/require
    if grep_check '\b(include|require|include_once|require_once)\s*\(\s*\$' "$f"; then
        record_fail "$f" "CWE-22:path_traversal_dynamic_include"
        failed=true
    fi

    # CWE-502 — unsafe deserialization
    if grep_check '\bunserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)' "$f"; then
        record_fail "$f" "CWE-502:insecure_deserialization_unserialize"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── Ruby ──────────────────────────────────────────────────────────────────────
# CWE: 78, 89, 79, 22
scan_ruby() {
    local f="$1"
    local failed=false

    # CWE-78
    if grep_check '\b(system|exec|Kernel\.exec|%x\{|`[^`]+`)' "$f"; then
        record_fail "$f" "CWE-78:OS_command_injection"
        failed=true
    fi

    # CWE-95
    if grep_check '\beval\s*[({]' "$f"; then
        record_fail "$f" "CWE-95:dynamic_code_execution_eval"
        failed=true
    fi

    # CWE-89
    if grep_check '(where|find_by_sql|execute)\s*\(\s*"[^"]*#\{' "$f"; then
        record_fail "$f" "CWE-89:SQL_injection_ActiveRecord_interpolation"
        failed=true
    fi

    # CWE-22 — path traversal
    if grep_check '(File\.read|File\.open|IO\.read)\s*\(\s*params\[' "$f"; then
        record_fail "$f" "CWE-22:path_traversal_params_in_file_read"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── Go ────────────────────────────────────────────────────────────────────────
# CWE: 78, 89, 22, 338
scan_go() {
    local f="$1"
    local failed=false

    # CWE-78
    if grep_check '\bexec\.Command\s*\(' "$f"; then
        record_warn "$f" "CWE-78:OS_command_execution_exec_Command"
    fi

    # CWE-89 — SQL injection with fmt.Sprintf in queries
    if grep_check 'fmt\.Sprintf.*\b(SELECT|INSERT|UPDATE|DELETE)\b' "$f"; then
        record_fail "$f" "CWE-89:SQL_injection_fmt_Sprintf"
        failed=true
    fi

    # CWE-22 — path traversal
    if grep_check '(os\.Open|ioutil\.ReadFile|http\.ServeFile)\s*\(\s*(r\.URL|req\.URL|path)' "$f"; then
        record_warn "$f" "CWE-22:potential_path_traversal"
    fi

    # CWE-338 — math/rand used for security (use crypto/rand instead)
    if grep_check '"math/rand"' "$f"; then
        record_warn "$f" "CWE-338:math_rand_not_crypto_safe_use_crypto_rand"
    fi

    # G404 — CERT: TLS MinVersion not set
    if grep_check 'tls\.Config\s*\{' "$f" && ! grep_check 'MinVersion' "$f"; then
        record_warn "$f" "CWE-326:TLS_config_without_MinVersion"
    fi

    $failed || record_pass "$f"
}

# ── XML ───────────────────────────────────────────────────────────────────────
# CWE-611 — XXE
scan_xml() {
    local f="$1"
    local failed=false

    if grep_check '<!DOCTYPE' "$f"; then
        record_fail "$f" "CWE-611:XXE_DOCTYPE_declaration"
        failed=true
    fi
    if grep_check '<!ENTITY' "$f"; then
        record_fail "$f" "CWE-611:XXE_ENTITY_declaration"
        failed=true
    fi
    if grep_check 'SYSTEM\s+["'"'"'](file://|http://|https://|/etc/)' "$f"; then
        record_fail "$f" "CWE-611:XXE_SYSTEM_external_entity"
        failed=true
    fi

    # Check for inline credentials in XML config files
    if grep_check '(password|secret|token|apiKey)[^>]*>[^<]{4,}</\w' "$f"; then
        record_fail "$f" "CWE-798:hardcoded_credential_in_XML"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── YAML ─────────────────────────────────────────────────────────────────────
# OWASP A05 Misconfiguration · A02 Crypto Failures
scan_yaml() {
    local f="$1"
    local failed=false

    # Unpinned GitHub Actions (supply chain risk)
    if grep_check 'uses:\s+\S+/[^@]+$' "$f"; then
        record_fail "$f" "OWASP-A08:unpinned_action_supply_chain_risk"
        failed=true
    fi

    # Inline secrets in CI/CD config
    if grep_check '(password|secret|token|key|api_key)\s*:\s*[^${\s][^{]' "$f"; then
        record_fail "$f" "CWE-798:inline_credential_in_yaml"
        failed=true
    fi

    # SSTI pattern in templates (Jinja2 / Helm)
    if grep_check '\{\{[^}]*(request\.|user\.|\.env\.)' "$f"; then
        record_warn "$f" "CWE-94:potential_SSTI_template_injection"
    fi

    # Privileged container
    if grep_check 'privileged:\s*true' "$f"; then
        record_fail "$f" "OWASP-A05:privileged_container"
        failed=true
    fi

    # hostNetwork / hostPID
    if grep_check '(hostNetwork|hostPID|hostIPC):\s*true' "$f"; then
        record_fail "$f" "OWASP-A05:dangerous_host_namespace_sharing"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── Terraform / HCL ─────────────────────────────────────────────────────────
# OWASP A05 Misconfiguration · A02 Crypto
scan_terraform() {
    local f="$1"
    local failed=false

    if has_cmd checkov; then
        local out
        out=$(checkov -f "$f" --quiet 2>/dev/null || true)
        if echo "$out" | grep -q 'FAILED'; then
            local count
            count=$(echo "$out" | grep -c 'FAILED' || true)
            record_fail "$f" "checkov:${count}_CIS_IaC_findings"
            failed=true
        fi
    else
        record_warn "$f" "checkov missing"
    fi

    # CWE-798 — hardcoded secrets
    if grep_check '(password|secret|token)\s*=\s*"[^"]+"' "$f"; then
        record_fail "$f" "CWE-798:hardcoded_secret_in_terraform"
        failed=true
    fi

    # S3 public ACL
    if grep_check 'acl\s*=\s*"public-read' "$f"; then
        record_fail "$f" "OWASP-A05:S3_public_read_ACL"
        failed=true
    fi

    # Unrestricted security group
    if grep_check 'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]' "$f"; then
        record_warn "$f" "OWASP-A05:unrestricted_CIDR_0_0_0_0"
    fi

    # Encryption disabled
    if grep_check 'encrypted\s*=\s*false' "$f"; then
        record_fail "$f" "OWASP-A02:encryption_disabled"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── Dockerfile ───────────────────────────────────────────────────────────────
# OWASP A05 Misconfiguration · CWE-250
scan_docker() {
    local f="$1"
    local failed=false

    if has_cmd hadolint; then
        if ! hadolint "$f" 2>/dev/null; then
            record_fail "$f" "hadolint:dockerfile_issue"
            failed=true
        fi
    else
        record_warn "$f" "hadolint missing"
    fi

    # :latest tag — non-deterministic build
    if grep_check ':\s*latest\b' "$f"; then
        record_fail "$f" "OWASP-A05:unpinned_base_image_latest_tag"
        failed=true
    fi

    # ADD with remote URL — no integrity check
    if grep_check 'ADD\s+https?://' "$f"; then
        record_fail "$f" "CWE-494:ADD_remote_URL_no_integrity_check"
        failed=true
    fi

    # RUN curl|bash — supply chain
    if grep_check 'RUN\s+.*(curl|wget).*\|\s*(bash|sh)' "$f"; then
        record_fail "$f" "CWE-78:RUN_curl_pipe_bash_supply_chain"
        failed=true
    fi

    # CWE-250 — container runs as root (no USER instruction)
    if ! grep_check '^USER\s+[^r]' "$f"; then
        record_warn "$f" "CWE-250:no_USER_directive_container_runs_as_root"
    fi

    # Sensitive env vars in image layers
    if grep_check 'ENV\s+(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)' "$f"; then
        record_fail "$f" "CWE-798:sensitive_ENV_var_baked_into_image_layer"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── SQL ───────────────────────────────────────────────────────────────────────
# CWE-89, CWE-78
scan_sql() {
    local f="$1"
    local failed=false

    # CWE-78 — stored procedure for OS execution
    if grep_check '(xp_cmdshell|sp_OACreate|OPENROWSET|BULK INSERT)' "$f"; then
        record_fail "$f" "CWE-78:SQL_OS_execution_xp_cmdshell"
        failed=true
    fi

    # Destructive DDL
    if grep_check 'DROP\s+(TABLE|DATABASE|SCHEMA|VIEW|FUNCTION|PROCEDURE)' "$f"; then
        record_fail "$f" "CWE-89:destructive_DDL_statement"
        failed=true
    fi

    # CWE-89 — comment-based injection
    if grep_check "(;\s*--|'--|\b(OR|AND)\s+['\"]?1['\"]?\s*=\s*['\"]?1)" "$f"; then
        record_fail "$f" "CWE-89:SQL_injection_pattern"
        failed=true
    fi

    # UNION-based injection payload
    if grep_check '\bUNION\s+(ALL\s+)?SELECT\b' "$f"; then
        record_fail "$f" "CWE-89:SQL_UNION_injection_payload"
        failed=true
    fi

    $failed || record_pass "$f"
}

# ── Binaries ─────────────────────────────────────────────────────────────────
scan_binary() {
    local f="$1"
    record_fail "$f" "binary:unexpected_binary_in_AI_repo"
    if has_cmd strings; then
        local iocs
        iocs=$(strings "$f" 2>/dev/null \
            | grep -iE '(http://|https://|/etc/passwd|/bin/sh|exec|shell|reverse|c2server)' || true)
        if [[ -n "$iocs" ]]; then
            record_fail "$f" "binary:IOC_strings_detected"
        fi
    fi
}

# ── Archives ─────────────────────────────────────────────────────────────────
scan_archive() {
    local f="$1"
    record_fail "$f" "archive:requires_dedicated_rescan"
    # CWE-22 — zip-slip check on zip archives
    if has_cmd unzip && [[ "$f" == *.zip ]]; then
        local slip
        slip=$(unzip -l "$f" 2>/dev/null | grep '\.\.' || true)
        if [[ -n "$slip" ]]; then
            record_fail "$f" "CWE-22:zip_slip_path_traversal_in_archive"
        fi
    fi
}

# ── Unknown ───────────────────────────────────────────────────────────────────
scan_unknown() {
    local f="$1"
    if has_cmd file; then
        local mime
        mime=$(file --mime-type -b "$f" 2>/dev/null || echo "unknown")
        if echo "$mime" | grep -qE \
            '^(application/x-executable|application/x-sharedlib|application/x-dosexec)'; then
            record_fail "$f" "binary:unexpected_executable_mime:${mime}"
            return
        fi
    fi
    record_pass "$f"
}

# ── Classification ───────────────────────────────────────────────────────────
classify_file() {
    local f="$1"
    local base ext
    base=$(basename "$f")
    ext="${f##*.}"

    # Run universal patterns on every file first
    scan_universal_patterns "$f"

    case "$base" in
        Dockerfile*) scan_docker "$f"; return ;;
    esac

    case ".$ext" in
        .py)                              scan_python      "$f" ;;
        .js|.ts|.jsx|.tsx|.mjs|.cjs)    scan_javascript  "$f" ;;
        .java)                            scan_java        "$f" ;;
        .php)                             scan_php         "$f" ;;
        .rb)                              scan_ruby        "$f" ;;
        .go)                              scan_go          "$f" ;;
        .c|.cpp|.h|.hpp|.cc)            scan_c_cpp       "$f" ;;
        .sh|.bash|.zsh|.ps1|.psm1|.ksh) scan_shell      "$f" ;;
        .xml)                             scan_xml         "$f" ;;
        .yml|.yaml)                       scan_yaml        "$f" ;;
        .tf|.tfvars|.hcl)               scan_terraform   "$f" ;;
        .so|.dll|.dylib|.exe|.elf|.bin)  scan_binary     "$f" ;;
        .zip|.tar|.gz|.tgz|.bz2|.xz)    scan_archive    "$f" ;;
        .sql)                             scan_sql         "$f" ;;
        .json)
            if grep_check \
                '(password|secret|token|api_key|private_key)\s*"?\s*:\s*"[^"${\s]{4,}' "$f"; then
                record_fail "$f" "CWE-798:hardcoded_credential_in_JSON"
            else
                record_pass "$f"
            fi
            ;;
        .md|.txt|.rst)
            if grep_check \
                '(password|secret|api_key)\s*[:=]\s*[^${\s][^\s]{4,}' "$f"; then
                record_fail "$f" "CWE-798:hardcoded_credential_in_doc"
            else
                record_pass "$f"
            fi
            ;;
        *) scan_unknown "$f" ;;
    esac
}

# ── LAYER 5: Per-type scan ────────────────────────────────────────────────────
scan_by_type() {
    info "=== Layer 5: Per-type SAST ==="
    while IFS= read -r -d '' f; do
        [[ -f "$f" ]] || continue
        [[ "$(basename "$f")" == ".manifest_sha256.txt" ]] && continue
        classify_file "$f"
    done < <(find "$SCAN_DIR" -type f -print0)
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════
generate_report_json() {
    local findings_json="{"
    local first=true
    for path in "${!FINDINGS[@]}"; do
        local msg="${FINDINGS[$path]%' | '}"
        $first || findings_json+=","
        msg="${msg//\"/\\\"}"
        local path_esc="${path//\"/\\\"}"
        findings_json+="\"${path_esc}\":\"${msg}\""
        first=false
    done
    findings_json+="}"

    local file_results_json="{"
    first=true
    for path in "${!FILE_STATUS[@]}"; do
        local status="${FILE_STATUS[$path]}"
        local msg="${FILE_MSG[$path]:-}"
        msg="${msg%' | '}"
        msg="${msg//\"/\\\"}"
        local path_esc="${path//\"/\\\"}"
        $first || file_results_json+=","
        file_results_json+="\"${path_esc}\":{\"status\":\"${status}\",\"message\":\"${msg}\"}"
        first=false
    done
    file_results_json+="}"

    cat > "$REPORT_JSON" <<JSON
{
  "verdict": "${GLOBAL_VERDICT}",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "repo_input": "${REPO_INPUT:-}",
  "directory": "${SCAN_DIR}",
  "repo_hash": "$(find "$SCAN_DIR" -type f | sort | sha256sum | awk '{print $1}')",
  "standards": ["OWASP-Top10-2021", "CWE-Top25", "CERT-Secure-Coding", "SCA-CVE"],
  "summary": { "pass": ${PASS_COUNT}, "warn": ${WARN_COUNT}, "fail": ${FAIL_COUNT} },
  "findings": ${findings_json},
  "file_results": ${file_results_json}
}
JSON
}

generate_report_html() {
    local color
    [[ "$GLOBAL_VERDICT" == "PASS" ]] && color="#2ecc71" || color="#e74c3c"
    {
        echo "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        echo "<title>AI Transit Report — ${TIMESTAMP}</title>"
        echo "<style>
body{background:#0d1b2a;color:#eee;font-family:monospace;padding:2rem;max-width:1400px;margin:0 auto}
h1{color:${color}} h2{color:#00a8ff}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th{background:#1f3864;padding:.6rem;text-align:left}
td{border:1px solid #334;padding:.5rem;vertical-align:top}
tr:nth-child(even){background:#16213e}
.pass{color:#2ecc71;font-weight:bold} .fail{color:#e74c3c;font-weight:bold} .warn{color:#f39c12;font-weight:bold}
.tag{background:#1f3864;border-radius:4px;padding:2px 6px;font-size:.85em;margin:1px;display:inline-block}
.owasp{background:#c0392b} .cwe{background:#2980b9} .cert{background:#27ae60}
</style></head><body>"
        echo "<h1>Verdict: ${GLOBAL_VERDICT}</h1>"
        echo "<p>Directory: <code>${SCAN_DIR}</code> | Date: ${TIMESTAMP}</p>"
        echo "<p>Standards: <span class='tag owasp'>OWASP Top 10 2021</span>
              <span class='tag cwe'>CWE Top 25</span>
              <span class='tag cert'>CERT Secure Coding</span>
              <span class='tag'>SCA/CVE</span></p>"
        echo "<p>PASS: <span class='pass'>${PASS_COUNT}</span> |
              WARN: <span class='warn'>${WARN_COUNT}</span> |
              FAIL: <span class='fail'>${FAIL_COUNT}</span></p>"
        echo "<h2>Results by file</h2>"
        echo "<table><tr><th>File</th><th>Status</th><th>Finding</th></tr>"
        for path in "${!FILE_STATUS[@]}"; do
            local status="${FILE_STATUS[$path]}"
            local msg="${FILE_MSG[$path]:-}"
            local cls
            case "$status" in PASS) cls="pass";; FAIL) cls="fail";; *) cls="warn";; esac
            echo "<tr><td><code>${path}</code></td><td class='${cls}'>${status}</td><td>${msg}</td></tr>"
        done
        echo "</table></body></html>"
    } > "$REPORT_HTML"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
REPO_INPUT="${REPO_INPUT:-}"
info "Starting scan: $SCAN_DIR"
info "Standards: OWASP Top 10 2021 · CWE Top 25 · CERT Secure Coding · SCA"

scan_global             # Layer 1: AV + secrets + IOC
scan_owasp_cwe          # Layer 2: Semgrep OWASP/CWE rulesets
scan_dependencies       # Layer 3: SCA — vulnerable dependency CVEs
                        # Layer 4: universal patterns run inside classify_file()
scan_by_type            # Layer 5: per-language SAST

generate_report_json
generate_report_html

info "JSON report : $REPORT_JSON"
info "HTML report : $REPORT_HTML"
echo "$REPORT_JSON"
echo "$GLOBAL_VERDICT"
