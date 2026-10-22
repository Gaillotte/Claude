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

# ── Layer coverage tracking ──────────────────────────────────────────────────
# A verdict is only as meaningful as the layers that produced it. A layer can
# fail to run for two unrelated reasons — the tool is not installed, or (offline)
# its data was not staged — and both produce an empty result that is
# indistinguishable from a clean one. Recording coverage explicitly lets a
# consumer reject a PASS that rests on layers which never executed, instead of
# grepping warning prose for the two cases separately.
declare -A LAYER_COVERAGE
record_layer() { LAYER_COVERAGE["$1"]="$2"; }   # "ran" | "skipped:<reason>"

# ── Argument ─────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    fail "Usage: $0 <directory_to_scan>  [VERBOSITY=quiet|normal|verbose]"
fi

SCAN_DIR="$1"
[[ -d "$SCAN_DIR" ]] || fail "Directory not found: $SCAN_DIR"

# ── Offline / air-gapped operation ───────────────────────────────────────────
# Several scanners reach out to the network at SCAN time, not just install time:
# semgrep fetches rulesets from its registry, trivy downloads a vulnerability
# database, pip-audit/safety/npm audit query advisory services, and ScanCode's
# --vulnerability option queries VulnerableCode.
#
# Without OFFLINE=true those calls are still attempted on an isolated host. They
# do not crash the run (each is guarded), but they block on DNS and TCP timeouts
# and then yield nothing — so Layer 2 and Layer 3 quietly contribute no findings
# while the report still presents them as having run. A PASS produced that way
# means very little, which is the dangerous part.
#
# OFFLINE=true instead: points each tool at locally staged data, passes the
# flags that suppress update attempts and telemetry, and records an explicit
# WARN naming any layer that genuinely cannot run without a network.
OFFLINE="${OFFLINE:-false}"

# Locations of pre-staged offline assets (see INSTALL.md §10).
OFFLINE_CACHE="${OFFLINE_CACHE:-${WORK_DIR}/offline-cache}"
SEMGREP_RULES_DIR="${SEMGREP_RULES_DIR:-${OFFLINE_CACHE}/semgrep-rules}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-${OFFLINE_CACHE}/trivy-db}"
CLAMAV_DB_DIR="${CLAMAV_DB_DIR:-${OFFLINE_CACHE}/clamav}"

if [[ "$OFFLINE" == "true" ]]; then
    info "Offline mode: no scanner will attempt a network call"
    # Suppress telemetry that would otherwise block on a timeout.
    export SEMGREP_SEND_METRICS=off
    export DO_NOT_TRACK=1
    export CHECKPOINT_DISABLE=1        # Terraform/checkov version check
    export PIP_NO_INDEX=1
fi

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
# -e is not optional here. A pattern beginning with a dash — "-----BEGIN RSA
# PRIVATE KEY-----" is the one that matters — is otherwise parsed as options,
# and grep exits 2 with "unrecognized option". `if` reads 2 as false, so the
# rule becomes silently inert: it never fires and never complains. -e marks the
# argument as the pattern and ends the ambiguity.
grep_check() { grep -qE -e "$1" "$2" 2>/dev/null; }
# Case-insensitive variant. Needed where a convention fixes the case of the
# thing being matched rather than the rule: Makefile variables are upper-case by
# convention, so a lower-case PASSWORD pattern would never fire on one.
grep_check_i() { grep -qiE -e "$1" "$2" 2>/dev/null; }

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
        record_layer L1_secrets_betterleaks "ran"
    else
        record_warn "__global__" "betterleaks missing — secret scan skipped"
        record_layer L1_secrets_betterleaks "skipped:betterleaks not installed"
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
        record_layer L1_secrets_entropy "ran"
    else
        record_warn "__global__" "detect-secrets missing"
        record_layer L1_secrets_entropy "skipped:detect-secrets not installed"
    fi

    if has_cmd clamscan; then
        info "clamscan…"
        # clamscan reads a local signature DB, so it works offline — but only if
        # signatures were staged. An empty DB detects nothing while still
        # exiting 0, which would read as "clean".
        local -a clam_opts=()
        if [[ "$OFFLINE" == "true" ]]; then
            if compgen -G "${CLAMAV_DB_DIR}/*.c[vl]d" >/dev/null 2>&1; then
                clam_opts+=(--database="$CLAMAV_DB_DIR")
            elif ! compgen -G "/var/lib/clamav/*.c[vl]d" >/dev/null 2>&1; then
                record_warn "__global__" \
                    "OFFLINE:ClamAV signature database is empty — malware scan detected nothing because it has no signatures, not because the code is clean; stage a DB in ${CLAMAV_DB_DIR}"
                record_layer L1_malware "skipped:no ClamAV signatures available"
            fi
        fi
        if ! clamscan -r --quiet ${clam_opts[@]+"${clam_opts[@]}"} \
                "${CLAMSCAN_EXCLUDES[@]}" "$SCAN_DIR" 2>/dev/null; then
            record_fail "$SCAN_DIR" "clamav:malware_detected"
        else
            record_pass "$SCAN_DIR"
            ok "ClamAV: clean"
        fi
        [[ -z "${LAYER_COVERAGE[L1_malware]:-}" ]] && record_layer L1_malware "ran"
    else
        record_warn "__global__" "clamscan missing"
        record_layer L1_malware "skipped:clamav not installed"
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
        record_layer L1_ioc_yara "skipped:yara or rules directory missing"
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
        record_layer L2_owasp_cwe "skipped:semgrep not installed"
        return
    fi

    local rulesets=(
        "p/owasp-top-ten"    # OWASP Top 10 2021
        "p/cwe-top-25"       # CWE Top 25 Most Dangerous
        "p/security-audit"   # generic security audit
        "p/secrets"          # additional secret patterns
    )

    # Offline: "p/..." identifiers resolve against the semgrep registry over the
    # network. Substitute the pre-exported YAML for each ruleset instead. A
    # ruleset with no staged file is skipped loudly rather than silently
    # producing zero findings.
    local -a semgrep_extra=()
    if [[ "$OFFLINE" == "true" ]]; then
        semgrep_extra+=(--metrics=off)
        local -a staged=() missing=()
        local rs name
        for rs in "${rulesets[@]}"; do
            name="${rs#p/}"
            if [[ -f "${SEMGREP_RULES_DIR}/${name}.yaml" ]]; then
                staged+=("${SEMGREP_RULES_DIR}/${name}.yaml")
            else
                missing+=("$name")
            fi
        done
        if (( ${#missing[@]} > 0 )); then
            record_warn "__global__" \
                "OFFLINE:semgrep rulesets not staged (${missing[*]}) — those OWASP/CWE rules did NOT run; export them with 'semgrep --config p/<name> --dump-config' on a connected host into ${SEMGREP_RULES_DIR}"
            record_layer L2_owasp_cwe "partial:rulesets missing (${missing[*]})"
        fi
        if (( ${#staged[@]} == 0 )); then
            record_warn "__global__" \
                "OFFLINE:Layer 2 skipped entirely — no semgrep rulesets available in ${SEMGREP_RULES_DIR}"
            record_layer L2_owasp_cwe "skipped:no semgrep rulesets staged for offline use"
            return
        fi
        rulesets=("${staged[@]}")
    fi

    local found_any=false
    for ruleset in "${rulesets[@]}"; do
        info "  semgrep ${ruleset}…"
        # Single run — parse JSON output once to avoid double execution (10-20 min saved)
        local out
        out=$(semgrep --config="${ruleset}" --quiet --json --no-autofix \
              ${semgrep_extra[@]+"${semgrep_extra[@]}"} \
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
    # Do not overwrite a "partial" already recorded for missing rulesets.
    [[ -z "${LAYER_COVERAGE[L2_owasp_cwe]:-}" ]] && record_layer L2_owasp_cwe "ran"
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
        # Offline: forbid every update attempt and read the staged database.
        # --offline-scan additionally stops trivy from resolving dependencies
        # that would require a network round-trip (e.g. Java GAV lookups).
        local -a trivy_extra=()
        if [[ "$OFFLINE" == "true" ]]; then
            if [[ -d "$TRIVY_CACHE_DIR" ]] && compgen -G "${TRIVY_CACHE_DIR}/db/*" >/dev/null 2>&1; then
                trivy_extra+=(--skip-db-update --skip-java-db-update --offline-scan
                              --cache-dir "$TRIVY_CACHE_DIR")
            else
                record_warn "__global__" \
                    "OFFLINE:trivy database not staged in ${TRIVY_CACHE_DIR} — dependency CVE scan did NOT run; populate it with 'trivy fs --download-db-only --cache-dir <dir>' on a connected host"
                record_layer L3_dependency_cve "skipped:trivy database not staged for offline use"
                trivy_extra=()
            fi
        fi
        local trivy_out=""
        if [[ "$OFFLINE" != "true" || ${#trivy_extra[@]} -gt 0 ]]; then
            trivy_out=$(trivy fs --quiet --exit-code 0 --format json \
                        ${trivy_extra[@]+"${trivy_extra[@]}"} "$SCAN_DIR" 2>/dev/null || true)
            record_layer L3_dependency_cve "ran"
        fi
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
        record_layer L3_dependency_cve "skipped:trivy not installed"
    fi

    # pip-audit: Python requirements
    local req_files
    req_files=$(find "$SCAN_DIR" -name "requirements*.txt" -o -name "Pipfile.lock" \
                -o -name "pyproject.toml" 2>/dev/null | head -5)
    if [[ -n "$req_files" && "$OFFLINE" == "true" ]]; then
        # pip-audit and safety both resolve advisories from a remote service and
        # have no offline database. Say so explicitly: a silent skip here would
        # leave Python dependency CVEs unreported with nothing in the record.
        record_warn "__global__" \
            "OFFLINE:Python dependency CVE scan unavailable (pip-audit and safety both require a network advisory service) — rely on the staged trivy database for Python CVEs"
    elif [[ -n "$req_files" ]]; then
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
    if [[ -n "$pkg_files" && "$OFFLINE" == "true" ]]; then
        # npm audit always queries the registry advisory endpoint; there is no
        # offline equivalent.
        record_warn "__global__" \
            "OFFLINE:JavaScript dependency CVE scan unavailable (npm audit requires the registry) — rely on the staged trivy database for JS CVEs"
    elif [[ -n "$pkg_files" ]]; then
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

    # CWE-321 — private key material committed to the repository.
    #
    # Requires a real PEM header. The previous rule matched the bare words
    # PRIVATE KEY, CERTIFICATE, BEGIN RSA and friends, so any document that
    # merely *discussed* keys failed the repository — and a public certificate,
    # which is published by design and is not a secret, was reported as a
    # leaked key. tests/fixtures/rules/safe_key_prose.txt guards both.
    if grep_check '-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----' "$f"; then
        record_fail "$f" "CWE-321:hardcoded_private_key"
        triggered=true
    fi
    # Reported, not blocked: a certificate is the public half of the pair.
    if grep_check '-----BEGIN CERTIFICATE-----' "$f"; then
        record_warn "$f" "crypto:public_certificate_embedded"
    fi

    # CWE-22 — Path traversal.
    #
    # A literal "../" is a relative path, not an attack. Matching it failed 254
    # of 388 real HTML files on href="../commands" and 27 of 88 real Makefiles
    # on -I../include, quarantining repositories for containing ordinary
    # documentation and build rules. The rule therefore requires one of the
    # three contexts that do indicate traversal, and
    # tests/fixtures/rules/safe_relative_paths.txt guards the distinction.
    #
    # Encoded: percent-encoded ".." has no innocent reading.
    if grep_check_i '(%2e%2e|%252e%252e|\.\.%2f|\.\.%5c|%2f\.\.|%5c\.\.)' "$f"; then
        record_fail "$f" "CWE-22:path_traversal_encoded"
        triggered=true
    fi
    # Target: traversal that arrives somewhere it has no business reaching.
    if grep_check_i \
        '\.\.[/\\][^[:space:]"'"'"'`]*((etc/)?(passwd|shadow)|\.ssh/|\.aws/|id_rsa|system32|proc/self)' \
        "$f"; then
        record_fail "$f" "CWE-22:path_traversal_to_sensitive_path"
        triggered=true
    fi
    # Composed: traversal concatenated into a string, or interpolated inside a
    # format string, which is the shape the vulnerability actually takes.
    #
    # Two arms were measured out of this rule rather than reasoned out. A bare
    # ${VAR}/../ matched 21 of 1116 real CMake files and ../${VAR} another 2:
    # joining a known path variable with ".." is ordinary path arithmetic
    # (${CMAKE_CURRENT_SOURCE_DIR}/../common.cmake), not traversal. The f-string
    # and template-literal arms below keep the interpolated case that does
    # matter, because they require the format-string marker.
    #
    # The quote and the slash are both required in the concatenation arms;
    # leaving either optional makes an ellipsis ("...") match.
    if grep_check_i \
        '(["'"'"'`]\.\.[/\\]["'"'"'`][[:space:]]*[+.][[:space:]]*|[+.][[:space:]]*["'"'"'`]/?\.\.[/\\]|f["'"'"'][^"'"'"']*(\{[^}]*\}[^"'"'"']*\.\.[/\\]|\.\.[/\\][^"'"'"']*\{[^}]*\})|`[^`]*(\$\{[^}]*\}[^`]*\.\.[/\\]|\.\.[/\\][^`]*\$\{))' \
        "$f"; then
        record_fail "$f" "CWE-22:path_traversal_composed_with_input"
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
        # --skip-download prevents checkov fetching remote provider schemas.
        local -a ck_opts=()
        [[ "$OFFLINE" == "true" ]] && ck_opts+=(--skip-download)
        out=$(checkov -f "$f" --quiet ${ck_opts[@]+"${ck_opts[@]}"} 2>/dev/null || true)
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

# ── CMake ────────────────────────────────────────────────────────────────────
# Two things make CMake worth its own scanner.
#
#   file(DOWNLOAD …) and execute_process(…) run at CONFIGURE time. `cmake .` is
#   enough to fire them — there is no build step to decline. This is the same
#   hazard as a Makefile's $(shell …), one stage earlier.
#
#   set(NAME "value") is a function call, not an assignment, so the universal
#   CWE-798 rule — which expects key = "value" — cannot see a credential in a
#   CMake file at all. Hence the credential rule here.
#
# Rates below are measured against 1116 real CMake files from this host (the
# CMake 3.28 module tree, plus installed projects). Calibration mattered twice:
#
#   execute_process appears in 106 of 1116, so it cannot be a finding by
#   itself; only one that runs a downloader or a shell is.
#
#   "URL" is overloaded. set_package_properties(… URL "http://xmlsoft.org/")
#   is a project homepage, not something fetched, and a rule that could not
#   tell the difference failed two of CMake's own modules. The download rule
#   therefore requires either file(DOWNLOAD …) or a URL ending in an archive
#   extension.
scan_cmake() {
    local f="$1"
    local failed=false

    # CWE-798 — credential in a set() call. The value must not be a variable
    # reference: set(DROP_SITE_PASSWORD "${CTEST_…}") is the correct form, and
    # set(…_RPATH_ORIGIN_TOKEN "\$ORIGIN") is a name that merely contains
    # TOKEN. Both appear in real CMake, which is why the first value character
    # may be neither $ nor a backslash. 0 of 1116.
    if grep_check_i \
        'set[[:space:]]*\([[:space:]]*[A-Za-z_]*(PASSWORD|PASSWD|SECRET|API_?KEY|TOKEN|CREDENTIAL)[A-Za-z_]*[[:space:]]+["'"'"'][^$\\"'"'"'][^"'"'"']{5,}["'"'"']' \
        "$f"; then
        record_fail "$f" "CWE-798:cmake_hardcoded_credential"
        failed=true
    fi

    # CWE-319 — fetched over plaintext, so anyone on the path chooses the
    # contents. 1 of 1116, and that one is a plaintext archive URL in CMake's
    # own ExternalProject documentation. 0 after the archive-extension
    # requirement is applied to homepage URLs.
    if grep_check_i \
        '(file[[:space:]]*\([[:space:]]*DOWNLOAD[[:space:]]+["'"'"']?http://|^[[:space:]]*URL[[:space:]]+["'"'"']?http://[^[:space:]"'"'"']*\.(tar\.(gz|bz2|xz|zst)|tgz|tbz2|txz|zip|7z|jar|whl))' \
        "$f"; then
        record_fail "$f" "CWE-319:cmake_download_over_plaintext_http"
        failed=true
    fi

    # CWE-295 — certificate checking switched off. 0 of 1116.
    if grep_check_i '(CMAKE_)?TLS_VERIFY[[:space:]]+(OFF|0|FALSE)' "$f"; then
        record_fail "$f" "CWE-295:cmake_tls_verification_disabled"
        failed=true
    fi

    # CWE-78 — a download piped into a shell, at configure or build time.
    # 0 of 1116.
    if grep_check_i '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh' "$f"; then
        record_fail "$f" "CWE-78:cmake_curl_pipe_shell_supply_chain"
        failed=true
    fi

    # CWE-1188 — compiled-in defences removed. 0 of 1116; note the rule names
    # the negative forms, so -fstack-protector-strong does not match.
    if grep_check_i '(fno-stack-protector|_FORTIFY_SOURCE=0|-z[[:space:]]*execstack|fno-pie\b)' "$f"; then
        record_fail "$f" "CWE-1188:cmake_hardening_disabled"
        failed=true
    fi

    # CWE-912 — a build that writes outside its tree, into somewhere that runs
    # later. 0 of 1116.
    if grep_check_i \
        'file[[:space:]]*\([[:space:]]*(WRITE|APPEND)[^)]*(/etc/|\.ssh/|authorized_keys|/etc/cron)' \
        "$f"; then
        record_fail "$f" "CWE-912:cmake_writes_to_a_sensitive_path"
        failed=true
    fi

    # ── Review-worthy, but ordinary enough not to block ──────────────────
    # A build step that reaches the network: legitimate with a hash check, but
    # worth seeing. 0 of 1116.
    if grep_check_i 'COMMAND[[:space:]]+["'"'"']?(curl|wget)\b' "$f"; then
        record_warn "$f" "cmake:build_step_fetches_from_the_network"
    fi
    # A shell invoked with -c inside a build step. 1 of 1116.
    if grep_check_i 'COMMAND[[:space:]]+["'"'"']?(sh|bash)["'"'"']?[[:space:]]+-c' "$f"; then
        record_warn "$f" "cmake:build_step_runs_shell_dash_c"
    fi
    # Arbitrary code at install time — a real CMake feature, used for
    # post-install fixups. 2 of 1116.
    if grep_check_i 'install[[:space:]]*\([[:space:]]*(CODE|SCRIPT)' "$f"; then
        record_warn "$f" "cmake:install_runs_arbitrary_code"
    fi
    # A dependency tracked by a moving branch rather than a pinned commit:
    # whatever that branch holds at build time is what gets compiled in.
    # 0 of 1116.
    if grep_check_i 'GIT_TAG[[:space:]]+["'"'"']?(master|main|HEAD|develop)["'"'"']?[[:space:]]*$' "$f"; then
        record_warn "$f" "cmake:dependency_pinned_to_a_moving_branch"
    fi

    $failed || record_pass "$f"
}

# ── HTML ─────────────────────────────────────────────────────────────────────
# Inline <script> is entirely ordinary, so the rules cannot target script
# itself; they target the constructs that have no innocent explanation.
#
# Deciding which those are was done by measurement, not intuition: every rule
# below was counted against 388 real HTML files taken off this host (Go tool
# bundles, Playwright reports, gcloud and Python package documentation). The
# figures in the comments are that count, and they are what separates a FAIL
# from a WARN here. Two results in particular changed the design:
#
#   A bare unescape( appeared in real files as unescape(encodeURIComponent(x)),
#   the standard UTF-8-to-byte-string idiom present in most bundled JS. So the
#   rule requires a percent-encoded blob — unescape('%u9090…') — instead.
#
#   innerHTML appeared in 8 of 388. It is a genuine XSS sink but far too common
#   to block on, so it warns.
#
# Generated HTML is the main false-positive risk, and most of it is already out
# of scope: DEFAULT_EXCLUDE_DIRS prunes dist/, build/, coverage/ and
# node_modules/ before any of this runs.
scan_html() {
    local f="$1"
    local failed=false

    # CWE-95 — dynamic code execution. 2 of 388, both the bundled Go trace
    # viewer, which really does call eval; such a vendored file needs a
    # .transit-allow.json entry rather than a weaker rule.
    if grep_check_i '\beval[[:space:]]*\(' "$f"; then
        record_fail "$f" "CWE-95:html_eval_dynamic_code_execution"
        failed=true
    fi

    # CWE-95 — percent-encoded payload handed to unescape(). 0 of 388.
    if grep_check_i 'unescape[[:space:]]*\([[:space:]]*["'"'"']?%' "$f"; then
        record_fail "$f" "CWE-95:html_obfuscated_percent_encoded_payload"
        failed=true
    fi

    # CWE-79 — document.write() fed from a decoder. 0 of 388.
    if grep_check_i 'document\.write[[:space:]]*\([[:space:]]*(unescape|atob|String\.fromCharCode)' "$f"; then
        record_fail "$f" "CWE-79:html_obfuscated_document_write"
        failed=true
    fi

    # CWE-319 — script fetched over plaintext http://, so anyone on the path
    # chooses what executes. 0 of 388. Protocol-relative //host only warns
    # below, since on an https page it inherits https.
    if grep_check_i '<script[^>]+src=["'"'"']?http://' "$f"; then
        record_fail "$f" "CWE-319:html_remote_script_over_plaintext_http"
        failed=true
    fi

    # CWE-1021 — an iframe with no visible size, the drive-by shape. 0 of 388;
    # a bare display:none appeared in 8, hence the match is scoped to the tag.
    if grep_check_i '<iframe[^>]*(display:[[:space:]]*none|visibility:[[:space:]]*hidden|width=["'"'"']?0["'"'"' ]|height=["'"'"']?0["'"'"' ])' "$f"; then
        record_fail "$f" "CWE-1021:html_hidden_iframe"
        failed=true
    fi

    # CWE-319 — <base href> over plaintext repoints every relative URL on the
    # page, including scripts already loaded relatively. 0 of 388.
    if grep_check_i '<base[^>]+href=["'"'"']?http://' "$f"; then
        record_fail "$f" "CWE-319:html_base_href_plaintext_hijacks_relative_urls"
        failed=true
    fi

    # CWE-319 — form posting credentials over plaintext. 0 of 388.
    if grep_check_i '<form[^>]+action=["'"'"']?http://' "$f"; then
        record_fail "$f" "CWE-319:html_form_posts_over_plaintext_http"
        failed=true
    fi

    # CWE-798 — credential sitting in the markup. The universal rule cannot see
    # these: it expects key = "value", whereas HTML splits the name and the
    # value across two attributes. 0 of 388 for both forms.
    if grep_check_i '(name|id)=["'"'"'][^"'"'"']*(api[_-]?key|password|passwd|secret|token)[^"'"'"']*["'"'"'][^>]*value=["'"'"'][^"'"'"']{6,}' "$f"; then
        record_fail "$f" "CWE-798:html_hardcoded_credential_in_attribute"
        failed=true
    fi
    if grep_check_i '<meta[^>]+(api[_-]?key|secret|token|password)[^>]+content=["'"'"'][^"'"'"']{6,}' "$f"; then
        record_fail "$f" "CWE-798:html_hardcoded_credential_in_meta"
        failed=true
    fi

    # CWE-200 — a cookie read wired to a network sink. Matched in both orders,
    # because `new Image().src = '...' + document.cookie` puts the sink first,
    # and bounded to a single statement by [^;], so an ordinary page that reads
    # a cookie somewhere and calls fetch() elsewhere does not match. 0 of 388.
    if grep_check_i '(document\.cookie[^;]{0,150}(fetch[[:space:]]*\(|XMLHttpRequest|sendBeacon|\.src[[:space:]]*=)|(fetch[[:space:]]*\(|XMLHttpRequest|sendBeacon|\.src[[:space:]]*=)[^;]{0,150}document\.cookie)' "$f"; then
        record_fail "$f" "CWE-200:html_cookie_exfiltration_to_network_sink"
        failed=true
    fi

    # ── Review-worthy, but too common to block ───────────────────────────
    if grep_check_i '(innerHTML|outerHTML|insertAdjacentHTML)[[:space:]]*(=|\()' "$f"; then
        record_warn "$f" "CWE-79:html_unsanitised_html_sink"      # 8 of 388
    fi
    if grep_check_i 'new[[:space:]]+Function[[:space:]]*\(' "$f"; then
        record_warn "$f" "CWE-95:html_function_constructor"       # 2 of 388
    fi
    if grep_check_i '\batob[[:space:]]*\(' "$f"; then
        record_warn "$f" "html:base64_decode_inspect_payload"     # 5 of 388
    fi
    if grep_check_i '<script[^>]+src=["'"'"']?//[a-z0-9]' "$f"; then
        record_warn "$f" "html:protocol_relative_script_src"      # 1 of 388
    fi
    if grep_check_i '<meta[^>]+http-equiv=["'"'"']?refresh[^>]+url=[^"'"'"'>]*//' "$f"; then
        record_warn "$f" "html:meta_refresh_external_redirect"    # 2 of 388
    fi
    if grep_check_i '(href|src)=["'"'"']?javascript:[^"'"'"'>;]' "$f"; then
        record_warn "$f" "html:javascript_uri"                    # 0 of 388
    fi

    $failed || record_pass "$f"
}

# ── Makefile ─────────────────────────────────────────────────────────────────
# Recipe lines are shell, so the risks scan_shell covers apply here too. Two
# things make a Makefile a worse problem than a shell script:
#
#   `$(shell ...)` is evaluated when make READS the file, before any target
#   runs. `make -n`, or `make` with a mistyped target, is enough to fire it, so
#   a hostile Makefile does not need to be built to act.
#
#   Assignments are unquoted, so `PASSWORD = hunter2` is invisible to the
#   universal CWE-798 rule in scan_universal_patterns, which requires a quote
#   after the `=`. Hence the credential rule repeated here.
#
# False positives are the real difficulty: the dangerous commands look almost
# exactly like the ordinary ones. `rm -rf $(BUILD)` in a clean target and
# `curl -o file url` in a fetch target are the most common rules in any
# Makefile, and only `rm -rf /` and a download piped into a shell are findings.
# tests/fixtures/rules/safe.mk is the guard for that distinction.
scan_makefile() {
    local f="$1"
    local failed=false

    # CWE-78 — download piped straight into a shell (the classic supply chain)
    if grep_check '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|k)?sh\b' "$f"; then
        record_fail "$f" "CWE-78:make_curl_pipe_shell_supply_chain"
        failed=true
    fi

    # CWE-78 — a $(shell ...) that fetches. Runs at parse time, so it fires on
    # any make invocation at all. A $(shell git rev-parse) does not fetch and
    # must not be flagged, which is why this names the commands rather than
    # matching $(shell ...) generally.
    if grep_check '\$\(shell[^)]*\b(curl|wget|nc|ncat|ssh|scp)\b' "$f"; then
        record_fail "$f" "CWE-78:make_shell_function_fetches_at_parse_time"
        failed=true
    fi

    # CWE-78 — base64-decoded payload executed
    if grep_check 'base64[[:space:]]+(-d|-D|--decode)[^|]*\|[[:space:]]*(ba)?sh\b' "$f"; then
        record_fail "$f" "CWE-78:make_base64_decoded_payload_executed"
        failed=true
    fi

    # CWE-78 — reverse shell. The leading word boundary matters: without it the
    # "nc" alternative matches inside ordinary words such as `sync`.
    if grep_check '(\b(nc|ncat|netcat)[[:space:]]+-[A-Za-z]*e[A-Za-z]*[[:space:]]|/dev/tcp/)' "$f"; then
        record_fail "$f" "CWE-78:make_reverse_shell"
        failed=true
    fi

    # CWE-798 — credential written into a variable. A value that is a variable
    # reference ($(X), ${X}) or empty is the correct form and is excluded.
    if grep_check_i \
        '^[[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(password|passwd|secret|api_?key|token|credential)[A-Za-z0-9_]*[[:space:]]*[:+?!]?=[[:space:]]*[^[:space:]$]{6,}' \
        "$f"; then
        record_fail "$f" "CWE-798:make_hardcoded_credential"
        failed=true
    fi

    # CWE-494 — download with certificate verification switched off
    if grep_check '(curl[^|]*([[:space:]]-k\b|--insecure)|wget[^|]*--no-check-certificate)' "$f"; then
        record_fail "$f" "CWE-494:make_download_without_certificate_verification"
        failed=true
    fi

    # CWE-732 — setuid/setgid bit granted. `install -m 0755` is ordinary, so the
    # mode must start with 2 or 4 to match.
    if grep_check '(chmod[[:space:]]+[^;&|]*[ugo]*\+s|-m[[:space:]]*[24][0-7]{3})' "$f"; then
        record_fail "$f" "CWE-732:make_setuid_or_setgid_bit"
        failed=true
    fi

    # CWE-912 — persistence installed by a build step
    if grep_check '(crontab|/etc/cron\.|authorized_keys|/etc/systemd/system)' "$f"; then
        record_fail "$f" "CWE-912:make_persistence_cron_or_authorized_keys"
        failed=true
    fi

    # Destructive delete of root or of the home directory. Deliberately narrow:
    # the target must be exactly / or ~ or $HOME, so `rm -rf $(BUILD)` and
    # `rm -rf dist` — the ordinary clean-target forms — are not matched.
    if grep_check 'rm[[:space:]]+-[A-Za-z]*[rR][A-Za-z]*[[:space:]]+(/|~|\$\{?HOME\}?)([[:space:]]|/\*|$)' "$f"; then
        record_fail "$f" "make:destructive_recursive_delete_of_root_or_home"
        failed=true
    fi

    # ── Review-worthy, but ordinary enough not to block ──────────────────
    if grep_check '(^[[:space:]]*sudo[[:space:]]|[[:space:]]sudo[[:space:]])' "$f"; then
        record_warn "$f" "make:sudo_in_recipe_runs_as_root"
    fi
    if grep_check 'chmod[[:space:]]+(-[A-Za-z]+[[:space:]]+)*777' "$f"; then
        record_warn "$f" "CWE-732:make_world_writable_chmod_777"
    fi
    if grep_check '(curl|wget)[^|]*http://' "$f"; then
        record_warn "$f" "make:plaintext_http_download_no_transport_integrity"
    fi
    # No rule for a bare $(eval ...): it fired on 7 of 88 real Makefiles taken
    # off this host — dpkg and java build fragments use it as ordinary
    # metaprogramming — and it carries no security signal of its own, because
    # the dangerous composition $(eval $(shell curl ...)) is already a FAIL
    # under the parse-time fetch rule above.
    if grep_check 'git[[:space:]]+clone[^;&|]*(http|git@)' "$f"; then
        record_warn "$f" "make:clones_and_builds_from_a_remote_repository"
    fi

    $failed || record_pass "$f"
}

# ── PDF ───────────────────────────────────────────────────────────────────────
# A PDF is a container, not a flat document: the format can auto-run JavaScript
# the moment the file is opened, start an external program, and carry an embedded
# executable. Before this existed, .pdf had no entry in classify_file() and fell
# through to scan_unknown, where application/pdf is not one of the dangerous
# MIME types — so a PDF wiring /OpenAction to /JavaScript and embedding an MZ
# payload was recorded PASS with no findings, while a .zip was failed outright
# for merely needing a rescan.
#
# Two properties of the format make a pattern rule harder than it looks.
#
#   Compression. From PDF 1.5 an object dictionary may live inside a FlateDecode
#   /ObjStm, so none of the names below need appear in the file's plaintext at
#   all. Greping raw bytes finds nothing in a PDF built that way, which is what
#   tests/fixtures/rules/pdf_compressed_js.pdf pins down. _pdf_searchable()
#   inflates every stream it can and searches that too.
#
#   Name escaping. /JavaScript and /J#61vaScript are the same name to a reader,
#   so escapes are decoded before matching.
#
# Anchoring matters as much as the patterns. TrueType subsetting produces font
# tags such as /AAAAAA+DejaVuSans, and an unanchored /AA rule reads those as an
# AdditionalActions key — a false positive that flags this project's own
# installation guide. Every short name below is therefore matched only where the
# next byte cannot continue a PDF name.
_pdf_has() { grep -qaE "$2" "$1" 2>/dev/null; }    # _pdf_has <file> <pattern>

# Emit a searchable rendering of a PDF on stdout: the raw bytes with hex-escaped
# name characters decoded, then every FlateDecode stream that inflates.
_pdf_searchable() {
    python3 - "$1" "$2" "$3" <<'PYEOF' 2>/dev/null
import base64, re, sys, zlib

MAX_INFLATE = 64 * 1024 * 1024       # decompression-bomb ceiling
MAX_READ    = 512 * 1024 * 1024      # repository size limit is 500 MB
MAX_STRING  = 64 * 1024              # longest plausible PDF string literal

_HEX    = re.compile(rb"#([0-9A-Fa-f]{2})")
_NAME   = re.compile(rb"/([A-Za-z0-9#]{1,64})")
_STREAM = re.compile(rb"(?<!end)stream\r?\n?")
_FILTER = re.compile(rb"/Filter\s*(/[A-Za-z0-9]+|\[[^\]]{0,512}\])")

# Filters that can conceal an object dictionary. Decoding these is the whole
# point: a /JavaScript action behind ASCII85 is as invisible to a text rule as
# one behind Flate.
#
# Image filters are deliberately absent. They carry pixels, never dictionaries,
# so failing to decode one is not a coverage gap — and reporting it as one would
# warn on every PDF containing a photograph.
_IMAGE_FILTERS = frozenset((
    "DCTDecode", "JPXDecode", "CCITTFaxDecode", "JBIG2Decode",
))


def _flate(data, budget):
    return zlib.decompressobj().decompress(data, budget)


def _asciihex(data, budget):
    h = re.sub(rb"[^0-9A-Fa-f>]", b"", data).split(b">")[0]
    if len(h) % 2:
        h += b"0"
    return bytes.fromhex(h.decode("ascii"))


def _ascii85(data, budget):
    s = re.sub(rb"\s", b"", data)
    if s.startswith(b"<~"):
        s = s[2:]
    if s.endswith(b"~>"):
        s = s[:-2]
    return base64.a85decode(s)


def _runlength(data, budget):
    out = bytearray()
    i = 0
    while i < len(data):
        n = data[i]
        i += 1
        if n == 128:                    # EOD
            break
        if n < 128:
            out += data[i:i + n + 1]
            i += n + 1
        else:
            if i >= len(data):
                break
            out += bytes([data[i]]) * (257 - n)
            i += 1
        if len(out) > budget:
            break
    return bytes(out)


def _lzw(data, budget, early=1):
    """PDF/TIFF-variant LZW: 9-bit codes growing to 12, 256=clear, 257=EOD."""
    def fresh():
        return [bytes([i]) for i in range(256)] + [b"", b""]

    table = fresh()
    out = bytearray()
    bitpos, nbits, prev = 0, 9, None
    total = len(data) * 8
    while bitpos + nbits <= total:
        i = bitpos >> 3
        chunk = data[i:i + 3]
        if len(chunk) < 3:
            chunk = chunk + b"\x00" * (3 - len(chunk))
        code = (((chunk[0] << 16) | (chunk[1] << 8) | chunk[2])
                >> (24 - (bitpos & 7) - nbits)) & ((1 << nbits) - 1)
        bitpos += nbits

        if code == 256:
            table, nbits, prev = fresh(), 9, None
            continue
        if code == 257:
            break

        if prev is None:
            if code >= len(table):
                break
            entry = table[code]
        elif code < len(table):
            entry = table[code]
            table.append(prev + entry[:1])
        else:
            entry = prev + prev[:1]
            table.append(entry)

        out += entry
        if len(out) > budget:
            break
        prev = entry
        if len(table) + early >= (1 << nbits) and nbits < 12:
            nbits += 1
    return bytes(out)


_DECODERS = {
    "FlateDecode":     _flate,
    "LZWDecode":       _lzw,
    "ASCIIHexDecode":  _asciihex,
    "ASCII85Decode":   _ascii85,
    "RunLengthDecode": _runlength,
}


def blank_strings(data):
    """Blank the interior of every ( ... ) literal, leaving structure intact.

    A name token cannot occur inside a PDF string, so this is what separates a
    real /JavaScript key from the words "Python/JavaScript" set in a paragraph.
    This project's own installation guide contains that phrase, and matching it
    failed the guide against its own scanner — invisibly until stream decoding
    improved enough to expose the text.

    Anchoring alone cannot do this job: requiring a non-name byte before the
    slash would also reject /S/JavaScript, which is valid PDF, because names
    self-delimit and need no separator.
    """
    out = bytearray(data)
    i, n = 0, len(data)
    while i < n:
        if data[i] != 0x28:                 # '('
            i += 1
            continue
        depth, j = 1, i + 1
        limit = min(n, i + MAX_STRING)
        while j < limit and depth:
            c = data[j]
            if c == 0x5C:                   # backslash escapes the next byte
                j += 2
                continue
            if c == 0x28:
                depth += 1
            elif c == 0x29:                 # ')'
                depth -= 1
            j += 1
        if depth:
            # Never closed within a plausible string length, so this "(" is
            # data, not a string opener. Blanking onward from here would let a
            # stray 0x28 in a binary stream swallow a later dictionary and hide
            # the /OpenAction in it.
            i += 1
            continue
        for k in range(i + 1, min(j - 1, n)):
            out[k] = 0x20
        i = max(j, i + 1)
    return bytes(out)


def blank_stream_bodies(data):
    """Replace raw stream bodies with spaces.

    Only used for the raw copy of the file. Object dictionaries live outside
    streams, so nothing searchable is lost, while the binary payloads that
    would otherwise confuse string tracking are removed. Stream contents still
    reach the rules via the decoded chunks, which are emitted separately.
    """
    out = bytearray(data)
    for m in _STREAM.finditer(data):
        end = data.find(b"endstream", m.end())
        if end == -1:
            end = len(data)
        for k in range(m.end(), end):
            out[k] = 0x20
    return bytes(out)


def declared_filters(dict_text):
    """Filter names from a stream's dictionary, in application order."""
    m = _FILTER.search(dict_text)
    if not m:
        return []
    return [n.decode("latin-1")
            for n in re.findall(rb"/([A-Za-z0-9]+)", m.group(1))]


def apply_chain(body, filters, budget):
    """Returns (decoded, undecodable_filter_name).

    A filter chain is applied in order. An image filter ends the chain with no
    gap recorded; anything else we cannot handle is reported by name so the
    operator learns which stream went uninspected.
    """
    data = body
    for name in filters:
        if name in _IMAGE_FILTERS:
            return None, None
        fn = _DECODERS.get(name)
        if fn is None:
            return None, name           # /Crypt, or a filter we do not know
        try:
            data = fn(data, budget)
        except Exception:
            return None, name
    return data, None

# A bare "MZ" says nothing here — compressed PDF bytes contain it by chance in
# every real document. An embedded executable starts with MZ *and* carries the
# PE signature a little further in, which arbitrary data does not.
def looks_like_pe(buf):
    return buf[:2] == b"MZ" and b"PE\x00\x00" in buf[:4096]

# Escaping is only evidence of evasion when it hides one of these. A #xx
# sequence on its own is not: inside a compressed stream it is ordinary binary
# noise, and matching it flagged two of this project's own PDFs, where
# "/#A57Sg" decodes to "\xa57Sg" and means nothing at all.
_DANGEROUS_NAMES = frozenset((
    b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile",
    b"RichMedia", b"Flash", b"SubmitForm", b"ImportData", b"XFA",
    b"GoToR", b"GoToE", b"ObjStm", b"Encrypt",
))

obfuscated = False


def decode_names(data, track=False):
    """Decode #xx escapes, but only inside name tokens.

    track=True additionally records whether an escape concealed a dangerous
    name. Only the string-blanked view passes it: this project's installation
    guide documents the evasion by writing /J#61vaScript in prose, and counting
    that as an attack failed the guide against its own scanner.
    """
    global obfuscated

    def repl(m):
        global obfuscated
        name = m.group(1)
        if b"#" not in name:
            return m.group(0)
        try:
            dec = _HEX.sub(lambda h: bytes([int(h.group(1), 16)]), name)
        except Exception:
            return m.group(0)
        if track and dec != name and dec in _DANGEROUS_NAMES:
            obfuscated = True
        return b"/" + dec
    return _NAME.sub(repl, data)

try:
    with open(sys.argv[1], "rb") as fh:
        raw = fh.read(MAX_READ)
except Exception:
    raise SystemExit(0)

# Two renderings, because the rules need different things. The "names" view has
# string literals blanked and is where key rules (/JavaScript, /OpenAction, …)
# run. The "full" view keeps everything and is where payload rules run, since
# the script itself lives inside the /JS ( ... ) string.
try:
    names_out = open(sys.argv[2], "wb")
    out = open(sys.argv[3], "wb")
except Exception:
    raise SystemExit(0)


def emit(chunk, is_raw=False):
    out.write(decode_names(chunk))
    out.write(b"\n")
    # Blank strings before decoding names, not after: decoding first could turn
    # an escaped #28 into a "(" and derail string tracking.
    blanked = blank_stream_bodies(chunk) if is_raw else chunk
    names_out.write(decode_names(blank_strings(blanked), track=True))
    names_out.write(b"\n")


emit(raw, is_raw=True)

# A PE signature cannot be expressed as a grep pattern from bash, because a
# bash string cannot hold the NUL bytes it contains. Detect it here and leave
# a plain-text marker for the shell rules to match instead.
pe = looks_like_pe(raw)

budget = MAX_INFLATE
undecoded = set()

for m in _STREAM.finditer(raw):
    if budget <= 0:
        break
    end = raw.find(b"endstream", m.end())
    if end == -1:
        continue
    body = raw[m.end():end]
    if not body:
        continue

    # The stream's own dictionary says how it is encoded. Look back for it
    # rather than guessing, so an undecodable filter can be named.
    head = raw[max(0, m.start() - 2048):m.start()]
    cut = head.rfind(b"<<")
    filters = declared_filters(head[cut:] if cut != -1 else head)

    if filters:
        decoded, bad = apply_chain(body, filters, budget)
        if bad:
            undecoded.add(bad)
    else:
        # No /Filter means the stream is already plaintext and the raw copy
        # above covers it. Still try Flate, because some producers omit the
        # declaration — but a failure here is not a coverage gap.
        try:
            decoded = _flate(body, budget)
        except Exception:
            decoded = None

    if decoded:
        budget -= len(decoded)
        pe = pe or looks_like_pe(decoded)
        emit(decoded)

# Markers go to the full view only; the rules that read them are routed there.
if pe:
    out.write(b"\nAITRANSIT-MARKER-EMBEDDED-PE\n")
if obfuscated:
    out.write(b"\nAITRANSIT-MARKER-NAME-OBFUSCATION\n")
for name in sorted(undecoded):
    out.write(b"\nAITRANSIT-MARKER-UNDECODED-FILTER " + name.encode("latin-1") + b"\n")
out.write(b"\n")
out.close()
names_out.close()
PYEOF
}

scan_pdf() {
    local f="$1"
    local failed=false

    # A .pdf that is not a PDF at all is worth saying out loud.
    if ! head -c 1024 "$f" 2>/dev/null | grep -qa '%PDF-'; then
        record_warn "$f" "pdf:no_PDF_header_extension_may_be_misleading"
    fi

    # Search the inflated, name-decoded rendering where one can be built, and
    # say so where it cannot: a PDF whose objects are all compressed and could
    # not be inflated has not been inspected, and that must not read as clean.
    # Two views: $names has string literals blanked and carries the key rules;
    # $searchable keeps everything and carries the payload rules, because the
    # script itself sits inside the /JS ( ... ) string.
    local searchable="$f" names="$f" tmp="" tmpn=""
    if has_cmd python3; then
        tmp=$(mktemp "${TMPDIR:-/tmp}/aitransit_pdf_XXXXXX" 2>/dev/null) || tmp=""
        tmpn=$(mktemp "${TMPDIR:-/tmp}/aitransit_pdfn_XXXXXX" 2>/dev/null) || tmpn=""
    fi
    if [[ -n "$tmp" && -n "$tmpn" ]]; then
        # Cleaned up explicitly at the single exit point below rather than with
        # a RETURN trap: such a trap is not scoped to the function that sets it,
        # so it goes on firing as later functions return, and a trap body that
        # defers expansion ('...$tmp...') then dies on set -u once $tmp is out
        # of scope. scan_pdf has no early return, so one rm is enough.
        _pdf_searchable "$f" "$tmpn" "$tmp" 2>/dev/null || true
        [[ -s "$tmp" ]]  && searchable="$tmp"
        [[ -s "$tmpn" ]] && names="$tmpn"
    fi
    if [[ "$searchable" == "$f" ]] && _pdf_has "$f" '/ObjStm'; then
        record_warn "$f" \
            "pdf:compressed_object_streams_not_inspected(install python3 so scan_pdf can inflate them)"
    fi

    # ── Active content ───────────────────────────────────────────────────
    # CWE-94 — an embedded script at all. Held in a variable because the
    # shellcode and known-exploit rules below are only meaningful alongside it:
    # a PDF that merely *documents* unescape() is not an attack.
    local has_js=false
    if _pdf_has "$names" '/(JavaScript|JS)[^A-Za-z0-9#]'; then
        record_fail "$f" "CWE-94:PDF_javascript_embedded"
        has_js=true
        failed=true
    fi

    # /OpenAction and /AA run without the reader clicking anything
    if _pdf_has "$names" '/(OpenAction|AA)[^A-Za-z0-9#]'; then
        record_fail "$f" "CWE-94:PDF_auto_execute_action_on_open"
        failed=true
    fi

    # CWE-78 — /Launch starts an external program
    if _pdf_has "$names" '/Launch[^A-Za-z0-9#]'; then
        record_fail "$f" "CWE-78:PDF_launch_action_starts_external_program"
        failed=true
    fi

    # CWE-506 — embedded payload
    if _pdf_has "$names" '/EmbeddedFile'; then
        record_fail "$f" "CWE-506:PDF_embedded_file_payload"
        failed=true
    fi
    if _pdf_has "$searchable" 'AITRANSIT-MARKER-EMBEDDED-PE|This program cannot be run in DOS mode'; then
        record_fail "$f" "CWE-506:PDF_embedded_windows_executable"
        failed=true
    fi

    # Writing /OpenAction as /OpenAc#74ion reads identically to a PDF viewer and
    # defeats a plain-text rule. The marker is only emitted where an escape
    # actually decodes to one of the names above, so ordinary escaping — and the
    # binary noise that superficially resembles it — does not reach here.
    if _pdf_has "$searchable" 'AITRANSIT-MARKER-NAME-OBFUSCATION'; then
        record_fail "$f" "CWE-94:PDF_name_hex_obfuscation_hides_active_content"
        failed=true
    fi

    # Rich media players carry their own exploit history
    if _pdf_has "$names" '/(RichMedia|Flash)[^A-Za-z0-9#]'; then
        record_fail "$f" "CWE-94:PDF_rich_media_active_content"
        failed=true
    fi

    # CWE-200 — a form that posts elsewhere, or pulls data in
    if _pdf_has "$names" '/(SubmitForm|ImportData)[^A-Za-z0-9#]'; then
        record_fail "$f" "CWE-200:PDF_form_submits_or_imports_data"
        failed=true
    fi

    if [[ "$has_js" == true ]]; then
        # Acrobat JavaScript entry points with a public exploit history
        if _pdf_has "$searchable" \
            '(util\.printf|collab\.getIcon|media\.newPlayer|spell\.customDictionaryOpen|this\.exportDataObject|app\.launchURL|getAnnots)[[:space:]]*\('; then
            record_fail "$f" "CWE-94:PDF_javascript_known_exploit_api"
            failed=true
        fi
        # Heap-spray and shellcode shapes
        if _pdf_has "$searchable" \
            '(unescape[[:space:]]*\(|%u[0-9A-Fa-f]{4}%u[0-9A-Fa-f]{4}|String\.fromCharCode[[:space:]]*\()'; then
            record_fail "$f" "CWE-94:PDF_javascript_shellcode_pattern"
            failed=true
        fi
    fi

    # ── Opaque or review-worthy, but not active content on its own ───────
    if _pdf_has "$names" '/Encrypt[^A-Za-z0-9#]'; then
        record_warn "$f" "pdf:encrypted_content_could_not_be_inspected"
    fi
    if _pdf_has "$names" '/XFA[^A-Za-z0-9#]'; then
        record_warn "$f" "pdf:XFA_form_attack_surface"
    fi
    if _pdf_has "$names" '/(GoToR|GoToE)[^A-Za-z0-9#]'; then
        record_warn "$f" "pdf:remote_or_embedded_destination"
    fi
    # A stream behind a filter we could not decode has not been inspected, and
    # that must be said rather than left to read as clean. Only filters capable
    # of concealing an object dictionary reach here — image filters carry
    # pixels, so reporting those would warn on every PDF with a photograph.
    local undecoded
    undecoded=$(grep -ao 'AITRANSIT-MARKER-UNDECODED-FILTER [A-Za-z0-9]*' "$searchable" 2>/dev/null \
                | awk '{print $2}' | sort -u | paste -sd, - || true)
    if [[ -n "$undecoded" ]]; then
        record_warn "$f" \
            "pdf:stream_filter_not_decoded(${undecoded})_those_streams_were_not_inspected"
    fi

    # Incremental updates: what a reader shows need not be the only revision.
    # -o then wc -l, because grep -c counts matching *lines* and a PDF may hold
    # several revisions with barely a newline between them.
    if (( $(grep -ao '%%EOF' "$f" 2>/dev/null | wc -l) > 1 )); then
        record_warn "$f" "pdf:incremental_updates_multiple_revisions"
    fi

    [[ -n "$tmp" ]]  && rm -f "$tmp"
    [[ -n "$tmpn" ]] && rm -f "$tmpn"
    $failed || record_pass "$f"
}

# ── Unknown ───────────────────────────────────────────────────────────────────
scan_unknown() {
    local f="$1"

    # Extensionless scripts are common (entrypoint, run, hooks). Route them to
    # the right scanner by shebang instead of skipping per-type analysis.
    local first_line
    IFS= read -r first_line < "$f" 2>/dev/null || first_line=""
    case "$first_line" in
        '#!'*python*) scan_python     "$f"; return ;;
        '#!'*/bash|'#!'*/sh|'#!'*env\ bash|'#!'*env\ sh|'#!'*/zsh|'#!'*/ksh)
                      scan_shell      "$f"; return ;;
        '#!'*ruby*)   scan_ruby       "$f"; return ;;
        '#!'*node*)   scan_javascript "$f"; return ;;
        '#!'*php*)    scan_php        "$f"; return ;;
        '#!'*pwsh*)   scan_powershell "$f"; return ;;
    esac

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

    # Basename dispatch, for build files that carry no extension. `Makefile`
    # has no dot at all, so ${f##*.} yields the whole path and the extension
    # branch below cannot route it.
    case "$base" in
        Dockerfile*)                          scan_docker   "$f"; return ;;
        Makefile*|makefile*|GNUmakefile*)     scan_makefile "$f"; return ;;
        # CMakeLists.txt ends in .txt, so without this it is routed to the
        # plain-text scanner and gets no CMake analysis at all.
        CMakeLists.txt|CMakeLists.*.txt)      scan_cmake    "$f"; return ;;
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
        .pdf)                             scan_pdf         "$f" ;;
        .mk|.mak|.make)                 scan_makefile    "$f" ;;
        .html|.htm|.xhtml)              scan_html        "$f" ;;
        .cmake)                           scan_cmake       "$f" ;;
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
    record_layer L4_patterns "ran"
    record_layer L5_per_language_sast "ran"
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════
scan_scancode() {
    info "=== Layer 6: ScanCode — licence, copyright & vulnerability ==="

    if ! has_cmd scancode; then
        record_warn "__global__" "scancode missing — licence/copyright layer skipped (pip install scancode-toolkit)"
        record_layer L6_licence "skipped:scancode not installed"
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
    # --vulnerability resolves CVEs against the VulnerableCode service. Licence
    # and copyright detection are fully local, so offline we keep those and drop
    # only the part that needs a network.
    local -a sc_opts=(--license --copyright --package)
    if [[ "$OFFLINE" == "true" ]]; then
        record_warn "__global__" \
            "OFFLINE:scancode CVE lookup disabled (--vulnerability queries VulnerableCode) — licence and copyright detection still run"
    else
        sc_opts+=(--vulnerability)
    fi

    if ! scancode \
            "${sc_opts[@]}" \
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

    record_layer L6_licence "ran"
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

    local _cov_k="${_tmp}/ck" _cov_v="${_tmp}/cv"
    local layer
    for layer in "${!LAYER_COVERAGE[@]}"; do
        printf '%s\x00' "$layer"                       >> "$_cov_k"
        printf '%s\x00' "${LAYER_COVERAGE[$layer]}"    >> "$_cov_v"
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
    python3 - "$_findings_k" "$_findings_v" "$_status_k" "$_status_s" "$_status_m" \
             "$_cov_k" "$_cov_v" <<'PYEOF'
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
ck = _read_nul(sys.argv[6]); cv = _read_nul(sys.argv[7])
while len(sm) < len(sk):
    sm.append("")

findings     = dict(zip(fk, fv))
file_results = {
    k: {"status": s, "message": m.rstrip(" | ")}
    for k, s, m in zip(sk, ss, sm)
}

coverage = dict(zip(ck, cv))
# A layer is "covered" when it ran in full. "partial" and "skipped" both mean
# the verdict rests on less analysis than it appears to.
incomplete = sorted(k for k, v in coverage.items() if not v.startswith("ran"))

report = {
    "verdict":      os.environ["REPORT_VERDICT"],
    "coverage":           coverage,
    "coverage_complete":  not incomplete,
    "coverage_gaps":      incomplete,
    "timestamp":    os.environ["REPORT_TS"],
    "repo_input":   os.environ["REPORT_REPO_INPUT"],
    "directory":    os.environ["REPORT_SCAN_DIR"],
    "repo_hash":    os.environ["REPORT_HASH"],
    "standards":    ["OWASP-Top10-2021", "CWE-Top25", "CERT-Secure-Coding",
                     "SCA-CVE", "ScanCode-Licence-Copyright",
                     "PDF-Active-Content", "Build-Script-Hardening",
                     "HTML-Active-Content"],
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
