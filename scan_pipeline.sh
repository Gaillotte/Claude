#!/usr/bin/env bash
# Scan de sécurité multicouche d'un répertoire de code IA
set -euo pipefail

WORK_DIR="${WORK_DIR:-/opt/ai-transit}"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# ── Fonctions de log ────────────────────────────────────────────────────────
log()    { echo "[$(date '+%H:%M:%S')] $*"; }
info()   { echo -e "\033[34m[INFO]\033[0m  $*"; }
warn()   { echo -e "\033[33m[WARN]\033[0m  $*" >&2; }
ok()     { echo -e "\033[32m[OK]\033[0m    $*"; }
fail()   { echo -e "\033[31m[FAIL]\033[0m  $*" >&2; exit 1; }
# fail fichier : enregistre un finding sans quitter
fail_f() { echo -e "\033[31m[FAIL]\033[0m  $*" >&2; GLOBAL_VERDICT="FAIL"; }

has_cmd() { command -v "$1" &>/dev/null; }

# ── Argument ─────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    fail "Usage : $0 <répertoire_à_scanner>"
fi

SCAN_DIR="$1"
[[ -d "$SCAN_DIR" ]] || fail "Répertoire introuvable : $SCAN_DIR"

GLOBAL_VERDICT="PASS"
declare -A FINDINGS
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

mkdir -p "${WORK_DIR}/reports" "${WORK_DIR}/quarantine" "${WORK_DIR}/approved"
chmod 700 "${WORK_DIR}/quarantine"

REPORT_JSON="${WORK_DIR}/reports/report_${TIMESTAMP}.json"
REPORT_HTML="${WORK_DIR}/reports/report_${TIMESTAMP}.html"

# ── Helpers ──────────────────────────────────────────────────────────────────
record_pass() { (( PASS_COUNT++ )) || true; }
record_warn() { (( WARN_COUNT++ )) || true; warn "$*"; }
record_fail() {
    local file="$1"; shift
    local msg="$*"
    FINDINGS["$file"]+="${msg} | "
    (( FAIL_COUNT++ )) || true
    fail_f "[$file] $msg"
}

# ── COUCHE GLOBALE ───────────────────────────────────────────────────────────
scan_global() {
    info "=== Couche globale ==="

    # Gitleaks
    if has_cmd gitleaks; then
        info "gitleaks…"
        if ! gitleaks detect --source "$SCAN_DIR" --no-git -q 2>/dev/null; then
            record_fail "$SCAN_DIR" "gitleaks:secrets_detected"
        else
            record_pass
            ok "gitleaks : aucun secret"
        fi
    else
        record_warn "gitleaks absent — scan secrets ignoré"
    fi

    # detect-secrets
    if has_cmd detect-secrets; then
        info "detect-secrets…"
        DSEC_OUT=$(detect-secrets scan "$SCAN_DIR" 2>/dev/null || true)
        if echo "$DSEC_OUT" | grep -q '"type"'; then
            record_fail "$SCAN_DIR" "detect-secrets:high_entropy_string"
        else
            record_pass
            ok "detect-secrets : aucune anomalie"
        fi
    else
        record_warn "detect-secrets absent"
    fi

    # ClamAV
    if has_cmd clamscan; then
        info "clamscan…"
        if ! clamscan -r --quiet "$SCAN_DIR" 2>/dev/null; then
            record_fail "$SCAN_DIR" "clamav:malware_detected"
        else
            record_pass
            ok "ClamAV : propre"
        fi
    else
        record_warn "clamscan absent"
    fi

    # YARA
    if has_cmd yara && [[ -d "${WORK_DIR}/yara-rules" ]]; then
        YARA_FILES=( "${WORK_DIR}/yara-rules/"*.yar )
        if [[ -f "${YARA_FILES[0]:-}" ]]; then
            info "yara…"
            for rule in "${YARA_FILES[@]}"; do
                if yara -r "$rule" "$SCAN_DIR" 2>/dev/null | grep -q .; then
                    record_fail "$SCAN_DIR" "yara:ioc_match:$(basename "$rule")"
                fi
            done
            ok "YARA : aucun IOC"
        fi
    else
        record_warn "yara ou répertoire de règles absent"
    fi
}

# ── Scanners par type ────────────────────────────────────────────────────────
scan_python() {
    local f="$1"
    if has_cmd bandit; then
        local out
        out=$(bandit -q -ll "$f" 2>/dev/null || true)
        if echo "$out" | grep -qE 'Severity: (MEDIUM|HIGH)'; then
            record_fail "$f" "bandit:$(echo "$out" | grep -oE 'Severity: \w+' | head -1)"
        else
            record_pass
        fi
    else
        record_warn "bandit absent"
    fi
    if grep -qE '\beval\s*\(|\bexec\s*\(' "$f" 2>/dev/null; then
        record_fail "$f" "dynamic_exec:eval/exec"
    fi
    if grep -qE 'import\s+(os|subprocess|pty)\b' "$f" 2>/dev/null; then
        record_warn "[$f] import module système (os/subprocess/pty)"
    fi
}

scan_javascript() {
    local f="$1"
    if has_cmd semgrep; then
        local out
        out=$(semgrep --config=p/javascript --quiet --json "$f" 2>/dev/null || true)
        if echo "$out" | grep -q '"results":\s*\[.\]' 2>/dev/null; then
            record_fail "$f" "semgrep:js_finding"
        else
            record_pass
        fi
    else
        record_warn "semgrep absent"
    fi
    if grep -qE '\beval\s*\(|\bchild_process\b|require\s*\(\s*['\''"]child_process' "$f" 2>/dev/null; then
        record_fail "$f" "js_dangerous:eval/child_process"
    fi
}

scan_c_cpp() {
    local f="$1"
    if has_cmd cppcheck; then
        local out
        out=$(cppcheck --quiet "$f" 2>&1 || true)
        if echo "$out" | grep -qE 'error:|warning:'; then
            record_fail "$f" "cppcheck:$(echo "$out" | grep -oE 'error:[^$]+' | head -1)"
        else
            record_pass
        fi
    else
        record_warn "cppcheck absent"
    fi
    if grep -qE '\b(gets|strcpy|system|popen)\s*\(' "$f" 2>/dev/null; then
        record_fail "$f" "c_dangerous_func:gets/strcpy/system/popen"
    fi
}

scan_shell() {
    local f="$1"
    if has_cmd shellcheck; then
        if ! shellcheck -S warning "$f" 2>/dev/null; then
            record_fail "$f" "shellcheck:warnings"
        else
            record_pass
        fi
    else
        record_warn "shellcheck absent"
    fi
    if grep -qE 'curl\s+.*\|\s*bash|wget\s+.*\|\s*sh|eval\s+\$' "$f" 2>/dev/null; then
        record_fail "$f" "shell_dangerous:curl|bash or eval \$var"
    fi
}

scan_yaml() {
    local f="$1"
    if grep -qE 'uses:\s+\w+/[^@]+$' "$f" 2>/dev/null; then
        record_fail "$f" "yaml:unpinned_action"
    fi
    if grep -qE '(password|secret|token|key)\s*:\s*[^${\s]' "$f" 2>/dev/null; then
        record_fail "$f" "yaml:inline_secret"
    fi
    record_pass
}

scan_terraform() {
    local f="$1"
    if has_cmd checkov; then
        local out
        out=$(checkov -f "$f" --quiet 2>/dev/null || true)
        if echo "$out" | grep -q 'FAILED'; then
            record_fail "$f" "checkov:iac_finding"
        else
            record_pass
        fi
    else
        record_warn "checkov absent"
    fi
    if grep -qE '(password|secret|token)\s*=\s*"[^"]+"' "$f" 2>/dev/null; then
        record_fail "$f" "terraform:hardcoded_secret"
    fi
}

scan_docker() {
    local f="$1"
    if has_cmd hadolint; then
        if ! hadolint "$f" 2>/dev/null; then
            record_fail "$f" "hadolint:dockerfile_issue"
        else
            record_pass
        fi
    else
        record_warn "hadolint absent"
    fi
    if grep -qE ':\s*latest\b|ADD\s+https?://|RUN\s+curl.*\|\s*bash' "$f" 2>/dev/null; then
        record_fail "$f" "docker_dangerous::latest/ADD_http/curl|bash"
    fi
}

scan_binary() {
    local f="$1"
    # Les binaires sont toujours FAIL dans un repo IA
    record_fail "$f" "binary:unexpected_binary_in_ai_repo"
    if has_cmd strings; then
        local iocs
        iocs=$(strings "$f" 2>/dev/null | grep -iE '(http://|https://|/etc/passwd|/bin/sh|exec|shell)' || true)
        if [[ -n "$iocs" ]]; then
            record_fail "$f" "binary:ioc_strings_detected"
        fi
    fi
}

scan_archive() {
    local f="$1"
    record_fail "$f" "archive:requires_dedicated_rescan"
}

scan_sql() {
    local f="$1"
    if grep -qiE 'xp_cmdshell|DROP\s+(TABLE|DATABASE)|;\s*--' "$f" 2>/dev/null; then
        record_fail "$f" "sql:dangerous_statement"
    else
        record_pass
    fi
}

scan_unknown() {
    local f="$1"
    if has_cmd file; then
        local mime
        mime=$(file --mime-type -b "$f" 2>/dev/null || echo "unknown")
        if echo "$mime" | grep -qE '^(application/x-executable|application/x-sharedlib|application/x-dosexec)'; then
            record_fail "$f" "unknown:binary_mime:$mime"
        fi
    fi
    record_pass
}

# ── Classification ───────────────────────────────────────────────────────────
classify_file() {
    local f="$1"
    local base ext
    base=$(basename "$f")
    ext="${f##*.}"

    case "$base" in
        Dockerfile*) scan_docker "$f"; return ;;
    esac

    case ".$ext" in
        .py)                          scan_python      "$f" ;;
        .js|.ts|.jsx|.tsx)            scan_javascript  "$f" ;;
        .c|.cpp|.h|.hpp)             scan_c_cpp       "$f" ;;
        .sh|.bash|.zsh|.ps1|.psm1)  scan_shell       "$f" ;;
        .yml|.yaml)                   scan_yaml        "$f" ;;
        .tf|.tfvars|.hcl)            scan_terraform   "$f" ;;
        .so|.dll|.dylib|.exe|.elf|.bin) scan_binary   "$f" ;;
        .zip|.tar|.gz|.tgz|.bz2)    scan_archive     "$f" ;;
        .sql)                         scan_sql         "$f" ;;
        .json|.xml|.md|.txt)
            if grep -qE '(password|secret|token|api_key)\s*[=:]\s*[^${\s]' "$f" 2>/dev/null; then
                record_fail "$f" "docs:inline_secret"
            else
                record_pass
            fi
            ;;
        *)                            scan_unknown     "$f" ;;
    esac
}

# ── COUCHE PAR TYPE ──────────────────────────────────────────────────────────
scan_by_type() {
    info "=== Couche par type de fichier ==="
    while IFS= read -r -d '' f; do
        [[ -f "$f" ]] || continue
        [[ "$(basename "$f")" == ".manifest_sha256.txt" ]] && continue
        classify_file "$f"
    done < <(find "$SCAN_DIR" -type f -print0)
}

# ── Rapport JSON ─────────────────────────────────────────────────────────────
generate_report_json() {
    local findings_json="{"
    local first=true
    for path in "${!FINDINGS[@]}"; do
        local msg="${FINDINGS[$path]%' | '}"
        $first || findings_json+=","
        findings_json+="\"$path\":\"$msg\""
        first=false
    done
    findings_json+="}"

    cat > "$REPORT_JSON" <<JSON
{
  "verdict": "${GLOBAL_VERDICT}",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "directory": "${SCAN_DIR}",
  "summary": { "pass": ${PASS_COUNT}, "warn": ${WARN_COUNT}, "fail": ${FAIL_COUNT} },
  "findings": ${findings_json}
}
JSON
}

# ── Rapport HTML ─────────────────────────────────────────────────────────────
generate_report_html() {
    local color
    [[ "$GLOBAL_VERDICT" == "PASS" ]] && color="#2ecc71" || color="#e74c3c"
    {
        echo "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        echo "<title>AI Transit Report — ${TIMESTAMP}</title>"
        echo "<style>body{background:#1a1a2e;color:#eee;font-family:monospace;padding:2rem}"
        echo "h1{color:${color}} table{border-collapse:collapse;width:100%}"
        echo "th,td{border:1px solid #444;padding:.5rem} tr:nth-child(even){background:#16213e}</style>"
        echo "</head><body>"
        echo "<h1>Verdict : ${GLOBAL_VERDICT}</h1>"
        echo "<p>Répertoire : <code>${SCAN_DIR}</code></p>"
        echo "<p>Date : ${TIMESTAMP}</p>"
        echo "<p>PASS: ${PASS_COUNT} | WARN: ${WARN_COUNT} | FAIL: ${FAIL_COUNT}</p>"
        if (( ${#FINDINGS[@]} > 0 )); then
            echo "<h2>Findings</h2><table><tr><th>Fichier</th><th>Problème</th></tr>"
            for path in "${!FINDINGS[@]}"; do
                echo "<tr><td>${path}</td><td>${FINDINGS[$path]}</td></tr>"
            done
            echo "</table>"
        fi
        echo "</body></html>"
    } > "$REPORT_HTML"
}

# ── Main ──────────────────────────────────────────────────────────────────────
info "Démarrage du scan : $SCAN_DIR"
scan_global
scan_by_type
generate_report_json
generate_report_html

info "Rapport JSON : $REPORT_JSON"
info "Rapport HTML : $REPORT_HTML"
echo "$GLOBAL_VERDICT"
