#!/usr/bin/env bash
# AI Transit Pipeline — multi-layer security scanner
# Covers: OWASP Top 10 2021 · CWE Top 25 · CERT Secure Coding · SCA/CVE · Licence
set -euo pipefail

# Require bash 4+ for associative arrays
[[ ${BASH_VERSINFO[0]} -ge 4 ]] || { echo "[ERROR] bash 4+ required (on macOS: brew install bash)" >&2; exit 1; }

WORK_DIR="${WORK_DIR:-/opt/ai-transit}"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
VERBOSITY="${VERBOSITY:-normal}"    # quiet | normal | verbose
MIN_SEVERITY="${MIN_SEVERITY:-high}" # low | medium | high | critical

# Numeric severity threshold for record_fail — findings below this are WARNs
declare -A _SEV_NUM=([low]=1 [medium]=2 [high]=3 [critical]=4)
SEV_THRESHOLD="${_SEV_NUM[${MIN_SEVERITY,,}]:-3}"

# ── Log functions ────────────────────────────────────────────────────────────
# The Layer 5 progress indicator redraws one line on stderr with \r. Every log
# helper clears that line first (\r + erase-to-end) so messages never get
# printed on top of a partially-drawn progress line.
_clr()   { [[ -t 2 ]] && printf "\r\033[K" >&2 || true; }
log()    { [[ "$VERBOSITY" != "quiet" ]] && { _clr; echo "[$(date '+%H:%M:%S')] $*"; } || true; }
info()   { [[ "$VERBOSITY" != "quiet" ]] && { _clr; echo -e "\033[34m[INFO]\033[0m  $*"; } || true; }
warn()   { _clr; echo -e "\033[33m[WARN]\033[0m  $*" >&2; }
ok()     { [[ "$VERBOSITY" != "quiet" ]] && { _clr; echo -e "\033[32m[OK]\033[0m    $*"; } || true; }
fail()   { _clr; echo -e "\033[31m[FAIL]\033[0m  $*" >&2; exit 1; }
fail_f() { _clr; echo -e "\033[31m[FAIL]\033[0m  $*" >&2; GLOBAL_VERDICT="FAIL"; }

has_cmd() { command -v "$1" &>/dev/null; }

# ── Argument ─────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    fail "Usage: $0 <directory_to_scan>  [VERBOSITY=quiet|normal|verbose]"
fi

SCAN_DIR="$1"
[[ -d "$SCAN_DIR" ]] || fail "Directory not found: $SCAN_DIR"

# ── .transit-allow.json — exception allowlist ────────────────────────────────
# Structure: [{"rule": "CWE-78", "path": "scripts/legacy.sh", "reason": "..."}]
# Matched findings are downgraded from FAIL to WARN.
declare -A ALLOW_MAP    # "rule::relpath" → reason
ALLOWLIST_FILE="${SCAN_DIR}/.transit-allow.json"
if [[ -f "$ALLOWLIST_FILE" ]]; then
    info "Allowlist found: $ALLOWLIST_FILE"
    # IFS is a set of characters, not a delimiter string: IFS=':::' would be
    # identical to IFS=':' and split on every colon, leaving `path` empty.
    # Use a single control character that cannot occur in a path or reason.
    while IFS=$'\x01' read -r rule path reason; do
        [[ -z "$rule" ]] && continue
        ALLOW_MAP["${rule}::${path}"]="$reason"
    done < <(ALLOWLIST_PATH="$ALLOWLIST_FILE" python3 -c "
import json, os, sys
try:
    entries = json.load(open(os.environ['ALLOWLIST_PATH']))
except Exception as exc:
    print('PARSE_ERROR' + chr(1) + str(exc) + chr(1) + '', file=sys.stderr)
    raise SystemExit(0)
if not isinstance(entries, list):
    raise SystemExit(0)
for entry in entries:
    if not isinstance(entry, dict):
        continue
    print(entry.get('rule','') + chr(1) + entry.get('path','') + chr(1) + entry.get('reason',''))
" 2>/dev/null || true)
    info "Allowlist: ${#ALLOW_MAP[@]} exception(s) loaded"
fi

# ── Diff mode: restrict scan to changed files only ────────────────────────────
# When SINCE_COMMIT was set, fetch_repo.sh writes a colon-separated file list.
DIFF_FILES_ONLY=false
declare -A DIFF_FILES_SET
DIFF_FILES_PATH="${WORK_DIR}/.diff_files"
if [[ -f "$DIFF_FILES_PATH" ]]; then
    DIFF_FILES_ONLY=true
    while IFS= read -r -d ':' f; do
        [[ -f "$f" ]] && DIFF_FILES_SET["$f"]=1
    done < "$DIFF_FILES_PATH"
    info "Diff mode: ${#DIFF_FILES_SET[@]} file(s) will be scanned"
fi

# ── Default excluded directories (always pruned from find) ───────────────────
DEFAULT_EXCLUDE_DIRS=(
    node_modules .git vendor .tox __pycache__ .venv venv
    dist build .next .nuxt .cache target coverage
)

# ── .transitignore support ────────────────────────────────────────────────────
# Read repo-level exclusion file (gitignore syntax: one path/pattern per line)
TRANSITIGNORE="${SCAN_DIR}/.transitignore"
EXTRA_EXCLUDE_DIRS=()
if [[ -f "$TRANSITIGNORE" ]]; then
    info ".transitignore found — loading exclusions"
    while IFS= read -r pattern; do
        [[ -z "$pattern" || "$pattern" == \#* ]] && continue
        EXTRA_EXCLUDE_DIRS+=("$pattern")
    done < "$TRANSITIGNORE"
fi

# ── Build find prune arguments ────────────────────────────────────────────────
FIND_PRUNE_ARGS=()
for d in "${DEFAULT_EXCLUDE_DIRS[@]}" "${EXTRA_EXCLUDE_DIRS[@]}"; do
    FIND_PRUNE_ARGS+=(-path "*/${d}" -prune -o -path "*/${d}/*" -prune -o)
done

# ── Semgrep / clamscan exclude flags from combined list ───────────────────────
SEMGREP_EXCLUDES=()
CLAMSCAN_EXCLUDES=()
for d in "${DEFAULT_EXCLUDE_DIRS[@]}" "${EXTRA_EXCLUDE_DIRS[@]}"; do
    SEMGREP_EXCLUDES+=(--exclude-dir "$d")
    CLAMSCAN_EXCLUDES+=(--exclude-dir="$d")
done

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
    # WARN never downgrades an existing FAIL status.
    if [[ -z "${FILE_STATUS[$file]:-}" ]]; then
        FILE_STATUS["$file"]="WARN"
    fi
    # Accumulate with the same " | " delimiter record_fail uses so downstream
    # report parsers can split findings reliably. Each entry carries its own
    # [WARN]/[FAIL] tag: a file's overall status must not be attributed to every
    # individual message (a missing-tool WARN is not a HIGH severity finding).
    FILE_MSG["$file"]+="[WARN] $* | "
}

record_fail() {
    local file="$1"; shift
    local msg="$*"
    local rel_path="${file#"$SCAN_DIR/"}"

    # Allowlist: try every prefix of the message up to the first three colons as
    # the rule token, so both "CWE-78" and "semgrep[p/owasp]:CWE-78:…" match an
    # allowlist entry keyed on "CWE-78::path".
    local _token _matched_reason=""
    for _token in "${msg%%:*}" "${msg#*:}"; do
        _token="${_token%%:*}"
        local _key="${_token}::${rel_path}"
        if [[ -n "${ALLOW_MAP["$_key"]:-}" ]]; then
            _matched_reason="${ALLOW_MAP["$_key"]}"
            break
        fi
    done
    if [[ -n "$_matched_reason" ]]; then
        record_warn "$file" "ALLOWED:${msg} (reason: ${_matched_reason})"
        return
    fi

    # MIN_SEVERITY: extract severity from known embedded markers.
    # Non-semgrep grep findings have no marker → treated as HIGH (sev=3).
    # Semgrep embeds :INFO:, :LOW:, :MEDIUM:, :HIGH:, :CRITICAL: in the message.
    # Semgrep reports ERROR/WARNING/INFO; other layers use LOW/MEDIUM/
    # HIGH/CRITICAL. Map both vocabularies onto the same 1-4 scale.
    local sev=3  # HIGH by default (grep rules carry no explicit severity)
    if   echo "$msg" | grep -qiE ':(INFO|LOW):';        then sev=1
    elif echo "$msg" | grep -qiE ':(WARNING|MEDIUM):';  then sev=2
    elif echo "$msg" | grep -qiE ':(ERROR|HIGH):';      then sev=3
    elif echo "$msg" | grep -qiE ':CRITICAL:';          then sev=4
    fi
    if (( sev < SEV_THRESHOLD )); then
        record_warn "$file" "LOW_SEV(below --min-severity ${MIN_SEVERITY}):${msg}"
        return
    fi

    FINDINGS["$file"]+="${msg} | "
    FILE_STATUS["$file"]="FAIL"
    FILE_MSG["$file"]+="[FAIL] ${msg} | "
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
        local dsec_hits
        dsec_hits=$(echo "$dsec_out" | python3 -c \
            "import json,sys; d=json.load(sys.stdin); print(sum(len(v) for v in d.get('results',{}).values()))" \
            2>/dev/null || echo "0")
        if (( dsec_hits > 0 )); then
            record_fail "$SCAN_DIR" "detect-secrets:${dsec_hits}_high_entropy_string(s)"
        else
            record_pass "$SCAN_DIR"
            ok "detect-secrets: no secrets detected"
        fi
    else
        record_warn "__global__" "detect-secrets missing"
    fi

    if has_cmd clamscan; then
        info "clamscan…"
        if ! clamscan -r --quiet "${CLAMSCAN_EXCLUDES[@]}" "$SCAN_DIR" 2>/dev/null; then
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
        # Single run — parse JSON output once to avoid double execution (10-20 min saved)
        local out
        out=$(semgrep --config="${ruleset}" --quiet --json --no-autofix \
              "${SEMGREP_EXCLUDES[@]}" "$SCAN_DIR" 2>/dev/null || true)

        local ruleset_findings
        ruleset_findings=$(echo "$out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = []
for r in data.get('results', []):
    path = r.get('path','')
    rule = r.get('check_id','')
    msg  = r.get('extra',{}).get('message','')[:120]
    line = str(r.get('start',{}).get('line',''))
    sev  = r.get('extra',{}).get('severity','INFO')
    rows.append(chr(1).join((path, rule, msg, line, sev)))
print('\n'.join(rows))
" 2>/dev/null || true)

        if [[ -z "$ruleset_findings" ]]; then
            ok "  ${ruleset}: no findings"
        else
            # Single-character delimiter: IFS is a character SET, so a
            # multi-character value like '|||' would split on every '|' and
            # scatter the fields.
            while IFS=$'\x01' read -r path rule msg line sev; do
                [[ -z "$path" ]] && continue
                record_fail "$path" "semgrep[${ruleset}]:${rule}:line${line}:${sev}:${msg}"
            done < <(echo "$ruleset_findings")
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
            # Use process substitution (not pipe) to keep record_fail in the parent shell
            while read -r req; do
                [[ -z "$req" ]] && continue
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
            done < <(echo "$req_files")
        elif has_cmd safety; then
            info "safety check…"
            while read -r req; do
                [[ -z "$req" ]] && continue
                if ! safety check -r "$req" --quiet 2>/dev/null; then
                    record_fail "$req" "safety:vulnerable_python_dependency"
                fi
            done < <(echo "$req_files")
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
            # Use process substitution (not pipe) to keep record_fail in the parent shell
            while read -r pkg; do
                [[ -z "$pkg" ]] && continue
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
            done < <(echo "$pkg_files")
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

    # CWE-89 — SQL injection: f-string, concatenation, %-format or .format()
    # built into the query. A parameterised call — execute("… = ?", (v,)) — is
    # the correct safe form and must NOT be flagged.
    if grep_check '(execute|executemany)[[:space:]]*\([[:space:]]*(f["'"'"']|("[^"]*"|'"'"'[^'"'"']*'"'"')[[:space:]]*(\+|%|\.format\())' "$f"; then
        record_fail "$f" "CWE-89:SQL_injection_query_built_by_string_interpolation"
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

    # CWE-250 — container runs as root
    # Warn if no USER directive exists, or if the only USER is root / uid 0
    local has_nonroot_user=false
    while IFS= read -r line; do
        if [[ "$line" =~ ^USER[[:space:]]+ ]]; then
            local user_arg
            user_arg=$(echo "$line" | awk '{print $2}' | tr -d '"'"'" | cut -d: -f1)
            if [[ "$user_arg" != "root" && "$user_arg" != "0" && -n "$user_arg" ]]; then
                has_nonroot_user=true
                break
            fi
        fi
    done < "$f"
    if [[ "$has_nonroot_user" == false ]]; then
        record_warn "$f" "CWE-250:no_nonroot_USER_directive_container_may_run_as_root"
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

# ── PowerShell ───────────────────────────────────────────────────────────────
scan_powershell() {
    local f="$1"
    local failed=false
    # CWE-78: Invoke-Expression / cmd.exe exec
    if grep_check '(Invoke-Expression|iex\s*\(|Start-Process|cmd\.exe\s*/c)' "$f"; then
        record_fail "$f" "CWE-78:PowerShell_command_execution"; failed=true
    fi
    # CWE-798: hardcoded credential
    if grep_check '(\$password|\$secret|\$apikey|\$token)\s*=\s*["'"'"'][^"'"'"'$]{4,}' "$f"; then
        record_fail "$f" "CWE-798:hardcoded_credential"; failed=true
    fi
    # Encoded/obfuscated commands (common malware technique)
    if grep_check '-EncodedCommand\s' "$f"; then
        record_fail "$f" "CWE-78:PowerShell_EncodedCommand_obfuscation"; failed=true
    fi
    $failed || record_pass "$f"
}

# ── Rust ─────────────────────────────────────────────────────────────────────
scan_rust() {
    local f="$1"
    local failed=false
    # unsafe block — mandatory manual review
    if grep_check '\bunsafe\s*\{' "$f"; then
        record_fail "$f" "CWE-119:unsafe_block_requires_review"; failed=true
    fi
    # Command execution via std::process::Command
    if grep_check 'std::process::Command' "$f"; then
        record_fail "$f" "CWE-78:process_Command_exec"; failed=true
    fi
    # Hardcoded credentials
    if grep_check '(password|secret|api_key|token)\s*=\s*"[^"]{4,}"' "$f"; then
        record_fail "$f" "CWE-798:hardcoded_credential"; failed=true
    fi
    # Semgrep per-file if available
    # Semgrep coverage for this language is already provided by the L2 full-directory
    # scan (scan_owasp_cwe). Running it again per-file would duplicate findings and
    # add seconds of startup overhead per file.
    $failed || record_pass "$f"
}

# ── Kotlin ────────────────────────────────────────────────────────────────────
scan_kotlin() {
    local f="$1"
    local failed=false
    if grep_check 'Runtime\.getRuntime\(\)\.exec\(' "$f"; then
        record_fail "$f" "CWE-78:Runtime_exec_command_injection"; failed=true
    fi
    if grep_check '(password|secret|apiKey|api_key|token)\s*=\s*"[^"]{4,}"' "$f"; then
        record_fail "$f" "CWE-798:hardcoded_credential"; failed=true
    fi
    if grep_check 'MessageDigest\.getInstance\("(MD5|SHA-1)"' "$f"; then
        record_fail "$f" "CWE-327:weak_hash_MD5_or_SHA1"; failed=true
    fi
    # Semgrep coverage for this language is already provided by the L2 full-directory
    # scan (scan_owasp_cwe). Running it again per-file would duplicate findings and
    # add seconds of startup overhead per file.
    $failed || record_pass "$f"
}

# ── C# ────────────────────────────────────────────────────────────────────────
scan_csharp() {
    local f="$1"
    local failed=false
    if grep_check 'Process\.Start\s*\(' "$f"; then
        record_fail "$f" "CWE-78:Process_Start_command_injection"; failed=true
    fi
    if grep_check '(password|secret|apiKey|api_key|token)\s*=\s*"[^"]{4,}"' "$f"; then
        record_fail "$f" "CWE-798:hardcoded_credential"; failed=true
    fi
    if grep_check 'new\s+MD5CryptoServiceProvider\s*\(\)' "$f"; then
        record_fail "$f" "CWE-327:MD5_weak_hash_algorithm"; failed=true
    fi
    # SQL string concatenation
    if grep_check '"SELECT.*"\s*\+' "$f"; then
        record_fail "$f" "CWE-89:SQL_string_concatenation"; failed=true
    fi
    # Semgrep coverage for this language is already provided by the L2 full-directory
    # scan (scan_owasp_cwe). Running it again per-file would duplicate findings and
    # add seconds of startup overhead per file.
    $failed || record_pass "$f"
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
        .sh|.bash|.zsh|.ksh)            scan_shell       "$f" ;;
        .ps1|.psm1|.psd1)               scan_powershell  "$f" ;;
        .rs)                              scan_rust        "$f" ;;
        .kt|.kts)                         scan_kotlin      "$f" ;;
        .cs)                              scan_csharp      "$f" ;;
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

    # Collect the files to scan first, applying every skip rule, so the progress
    # denominator matches what is actually scanned (a separate `find | wc -l`
    # would count files that the loop then skips).
    local -a scan_files=()
    local f
    while IFS= read -r -d '' f; do
        [[ -f "$f" ]] || continue
        [[ "$(basename "$f")" == ".manifest_sha256.txt" ]] && continue
        # Diff mode: skip files not in the changed-file set
        if [[ "$DIFF_FILES_ONLY" == true && -z "${DIFF_FILES_SET["$f"]:-}" ]]; then
            continue
        fi
        scan_files+=("$f")
    done < <(find "$SCAN_DIR" "${FIND_PRUNE_ARGS[@]}" -type f -print0 2>/dev/null)

    local total_files=${#scan_files[@]}
    local current=0
    local short_f
    for f in "${scan_files[@]}"; do
        (( current++ )) || true
        # Only draw the live progress line on an interactive terminal; when
        # stderr is redirected to a file or pipe, \r and colour codes would be
        # written literally into the log.
        if [[ "$VERBOSITY" != "quiet" && -t 2 ]]; then
            short_f="${f#"$SCAN_DIR/"}"
            printf "\r\033[K\033[34m[L5]\033[0m  [%${#total_files}d/%d] %s" \
                "$current" "$total_files" "${short_f:0:80}" >&2
        fi
        classify_file "$f"
    done

    # Clear the progress line (_clr is a no-op when stderr is not a terminal)
    _clr
    ok "Layer 5: $current files scanned"
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════
scan_scancode() {
    info "=== Layer 6: ScanCode — licence, copyright & vulnerability ==="

    if ! has_cmd scancode; then
        record_warn "__global__" "scancode missing — licence/copyright layer skipped (pip install scancode-toolkit)"
        return
    fi

    local sc_report="${WORK_DIR}/reports/scancode_${TIMESTAMP}.json"

    info "Running scancode on ${SCAN_DIR} …"
    # --license   : detect licences (SPDX ids)
    # --copyright : detect copyright notices
    # --vulnerability : detect known CVEs in detected packages
    # --package   : detect package manifests
    # --json-pp   : pretty-printed JSON output
    # --quiet     : suppress progress bar
    # --timeout   : per-file timeout in seconds
    if ! scancode \
            --license \
            --copyright \
            --vulnerability \
            --package \
            --json-pp "$sc_report" \
            --quiet \
            --timeout 120 \
            "$SCAN_DIR" 2>/dev/null; then
        record_warn "__global__" "scancode:scan_error — check ${sc_report}"
        return
    fi

    [[ -f "$sc_report" ]] || { record_warn "__global__" "scancode:no_report_generated"; return; }

    # ── Parse findings ────────────────────────────────────────────────────────
    if ! has_cmd python3; then
        record_warn "__global__" "scancode:python3_missing — cannot parse report"
        return
    fi

    # ── Parse report and feed results into the pipeline ─────────────────────
    # Output is captured in sc_out to avoid polluting stdout (which ai_transit.sh
    # uses to extract the verdict and report path).
    local sc_out
    sc_out=$(python3 - "$sc_report" "$SCAN_DIR" <<'PYEOF2'
import json, sys, os

report_path = sys.argv[1]
scan_dir    = sys.argv[2]

with open(report_path) as fh:
    data = json.load(fh)

for file in data.get("files", []):
    path = file.get("path", "")
    rel  = os.path.relpath(path, scan_dir) if os.path.isabs(path) else path

    for lic in file.get("license_detections", []):
        for match in lic.get("matches", []):
            spdx  = match.get("spdx_license_expression") or match.get("license_expression", "unknown")
            score = match.get("score", 0)
            risky = any(k in spdx.upper() for k in (
                "GPL", "AGPL", "LGPL", "SSPL", "BUSL", "EUPL", "CDDL", "CC-BY-SA", "CC-BY-NC"
            ))
            if risky and score >= 70:
                print(f"WARN|{rel}|licence:{spdx}")

    for pkg in file.get("packages", []):
        for vuln in pkg.get("vulnerabilities", []):
            vid      = vuln.get("vulnerability_id", "?")
            severity = vuln.get("max_severity", "").upper()
            pkg_name = pkg.get("name", "?")
            pkg_ver  = pkg.get("version", "?")
            if severity in ("CRITICAL", "HIGH"):
                print(f"FAIL|{rel}|scancode_vuln:{vid}[{severity}] in {pkg_name}=={pkg_ver}")
            else:
                print(f"WARN|{rel}|scancode_vuln:{vid}[{severity}] in {pkg_name}=={pkg_ver}")
PYEOF2
    ) 2>/dev/null

    local warn_count=0 fail_count=0
    while IFS='|' read -r level sc_rel msg; do
        [[ -z "$level" ]] && continue
        local abs_path="${SCAN_DIR}/${sc_rel}"
        case "$level" in
            FAIL) record_fail "$abs_path" "$msg"; (( fail_count++ )) || true ;;
            WARN) record_warn "$abs_path" "$msg"; (( warn_count++ )) || true ;;
        esac
    done <<< "$sc_out"

    if (( fail_count > 0 )); then
        fail_f "scancode: ${fail_count} CRITICAL/HIGH vulnerability finding(s)"
    elif (( warn_count > 0 )); then
        warn "scancode: ${warn_count} licence/vulnerability warning(s) — review before enterprise use"
    else
        ok "scancode: no risky licences or vulnerabilities detected"
    fi

    ok "ScanCode report: ${sc_report}"
}

generate_report_json() {
    # Data is written to temp files so Python reads it safely — no bash variable
    # expansion inside the Python source avoids code injection via filenames or
    # finding messages that contain triple-quote sequences.
    local _tmp
    _tmp=$(mktemp -d)
    trap "rm -rf '$_tmp'" RETURN

    # NUL-delimited streams: key\x00value\x00key\x00value…
    local _findings_k="${_tmp}/fk" _findings_v="${_tmp}/fv"
    local _status_k="${_tmp}/sk"  _status_s="${_tmp}/ss" _status_m="${_tmp}/sm"
    for path in "${!FINDINGS[@]}"; do
        printf '%s\x00' "$path"                        >> "$_findings_k"
        printf '%s\x00' "${FINDINGS[$path]%' | '}"     >> "$_findings_v"
    done
    for path in "${!FILE_STATUS[@]}"; do
        printf '%s\x00' "$path"                        >> "$_status_k"
        printf '%s\x00' "${FILE_STATUS[$path]}"        >> "$_status_s"
        printf '%s\x00' "${FILE_MSG[$path]:-}"         >> "$_status_m"
    done

    local repo_hash
    repo_hash=$(find "$SCAN_DIR" -type f | sort | sha256sum | awk '{print $1}')

    # All dynamic values are passed as env vars or temp-file paths — never
    # interpolated into the Python source.
    REPORT_VERDICT="$GLOBAL_VERDICT" \
    REPORT_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    REPORT_REPO_INPUT="${REPO_INPUT:-}" \
    REPORT_SCAN_DIR="$SCAN_DIR" \
    REPORT_HASH="$repo_hash" \
    REPORT_PASS="$PASS_COUNT" \
    REPORT_WARN="$WARN_COUNT" \
    REPORT_FAIL="$FAIL_COUNT" \
    REPORT_OUT="$REPORT_JSON" \
    python3 - "$_findings_k" "$_findings_v" "$_status_k" "$_status_s" "$_status_m" <<'PYEOF'
import json, os, sys

def _read_nul(path):
    """Read a stream of NUL-terminated records, preserving empty ones.

    Every record is written with a trailing NUL, so splitting yields one
    trailing empty element that must be dropped -- but ONLY that one.
    Filtering all empties (`if p`) would silently drop files whose message is
    empty and shift every later element, attributing findings to the wrong
    file in the report.
    """
    if not os.path.exists(path):
        return []
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw:
        return []
    parts = raw.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    return [p.decode("utf-8", errors="replace") for p in parts]

fk = _read_nul(sys.argv[1]); fv = _read_nul(sys.argv[2])
sk = _read_nul(sys.argv[3]); ss = _read_nul(sys.argv[4]); sm = _read_nul(sys.argv[5])
while len(sm) < len(sk):
    sm.append("")

findings     = dict(zip(fk, fv))
file_results = {
    k: {"status": s, "message": m.rstrip(" | ")}
    for k, s, m in zip(sk, ss, sm)
}

report = {
    "verdict":      os.environ["REPORT_VERDICT"],
    "timestamp":    os.environ["REPORT_TS"],
    "repo_input":   os.environ["REPORT_REPO_INPUT"],
    "directory":    os.environ["REPORT_SCAN_DIR"],
    "repo_hash":    os.environ["REPORT_HASH"],
    "standards":    ["OWASP-Top10-2021", "CWE-Top25", "CERT-Secure-Coding",
                     "SCA-CVE", "ScanCode-Licence-Copyright"],
    "summary":      {"pass": int(os.environ["REPORT_PASS"]),
                     "warn": int(os.environ["REPORT_WARN"]),
                     "fail": int(os.environ["REPORT_FAIL"])},
    "findings":     findings,
    "file_results": file_results,
}

with open(os.environ["REPORT_OUT"], "w", encoding="utf-8") as fh:
    json.dump(report, fh, ensure_ascii=False, indent=2)
PYEOF
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
scan_scancode           # Layer 6: licence, copyright & vulnerability (ScanCode)

generate_report_json
generate_report_html

info "JSON report : $REPORT_JSON"
info "HTML report : $REPORT_HTML"
# Write verdict and report path to sidecar files so ai_transit.sh can read them
# reliably without grepping stdout (which may contain lines from scanned tools).
echo "$GLOBAL_VERDICT" > "${WORK_DIR}/.scan_verdict"
echo "$REPORT_JSON"    > "${WORK_DIR}/.scan_report_json"
echo "$GLOBAL_VERDICT"
