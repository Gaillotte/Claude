#!/usr/bin/env bash
# AI Transit Pipeline — multi-layer security scanner
# Covers: OWASP Top 10 2021 · CWE Top 25 · CERT Secure Coding · SCA/CVE · Licence

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

# ── Utility Functions ─────────────────────────────────────────────────────────────────
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

# grep helper: returns 0 if pattern found, never fails the script
grep_check() { grep -qE "$1" "$2" 2>/dev/null; }

declare -A LAYER_COVERAGE
declare -A LAYER_TOOL    # layer_id → tool name (e.g. "L1_secrets_entropy" → "detect-secrets")
record_layer() { LAYER_COVERAGE["$1"]="$2"; }   # "ran" | "skipped:<reason>"
record_layer_tool() { LAYER_TOOL["$1"]="$2"; }  # set tool name for a layer

GLOBAL_VERDICT="PASS"
declare -A FINDINGS      # path → concatenated FAIL messages (kept for backward compat)
declare -A FILE_STATUS   # path → PASS | FAIL | WARN
declare -A FILE_MSG      # path → message
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

# Structured finding records — JSON lines file created before scan starts
FINDINGS_JL=""


# ── Helpers ──────────────────────────────────────────────────────────────────
record_pass() {
    local file="${1:-}"
    (( PASS_COUNT++ )) || true
    if [[ -n "$file" && -z "${FILE_STATUS[$file]:-}" ]]; then
        FILE_STATUS["$file"]="PASS"
        FILE_MSG["$file"]=""
    fi
}

# Write a structured finding record as a JSON line to the findings file.
# Args: tool category severity rule_id rule_name file line column message [references...]
_write_finding() {
    local tool="$1" category="$2" severity="$3" rule_id="$4" rule_name="$5"
    local file="$6" line="$7" column="$8" message="$9"
    shift 9
    local refs="${*:-}"
    # Use Python to produce a single valid JSON line (safe for any content)
    python3 -c "
import json, sys
rec = dict(tool=sys.argv[1], category=sys.argv[2], severity=sys.argv[3],
           rule_id=sys.argv[4], rule_name=sys.argv[5], file=sys.argv[6],
           line=int(sys.argv[7]) if sys.argv[7] else None,
           column=int(sys.argv[8]) if sys.argv[8] else None,
           message=sys.argv[9],
           references=sys.argv[10].split(',') if sys.argv[10] else [])
print(json.dumps(rec, ensure_ascii=False))
" "$tool" "$category" "$severity" "$rule_id" "$rule_name" "$file" \
      "${line:-}" "${column:-}" "$message" "$refs" >> "$FINDINGS_JL" 2>/dev/null || true
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

    # ── Emit structured finding record ──────────────────────────────────
    # Parse the message to extract tool, rule_id, severity, etc.
    # Format varies: "tool:rule:detail", "CWE-NNN:description", "semgrep[rs]:rule:lineN:sev:msg"
    local _tool="" _rule_id="" _rule_name="" _severity="HIGH" _category="security"
    local _line="" _column="" _refs=""

    # Detect tool from message prefix
    if [[ "$msg" == semgrep\[* ]]; then
        _tool="semgrep"
        _rule_id="${msg#*:]}"  # everything after first colon
        _rule_id="${_rule_id%%:*}"  # up to next colon
        # Extract severity if embedded as :WORD:
        if [[ "$msg" == *":HIGH:"* ]]; then _severity="HIGH"
        elif [[ "$msg" == *":CRITICAL:"* ]]; then _severity="CRITICAL"
        elif [[ "$msg" == *":MEDIUM:"* ]]; then _severity="MEDIUM"
        elif [[ "$msg" == *":LOW:"* ]]; then _severity="LOW"
        elif [[ "$msg" == *":INFO:"* ]]; then _severity="INFO"
        fi
        # Extract line number if present as lineN
        if [[ "$msg" =~ line([0-9]+) ]]; then _line="${BASH_REMATCH[1]}"; fi
        _category="sast"
    elif [[ "$msg" == detect-secrets:* ]]; then
        _tool="detect-secrets"
        _rule_id="high_entropy_string"
        _rule_name="High Entropy String"
        _severity="HIGH"
        _category="secret"
        _refs="CWE-798"
    elif [[ "$msg" == clamav:* ]]; then
        _tool="clamav"
        _rule_id="${msg#clamav:}"
        _rule_name="Malware Detected"
        _severity="CRITICAL"
        _category="malware"
    elif [[ "$msg" == gitleaks:* ]]; then
        _tool="gitleaks"
        _rule_id="${msg#gitleaks:}"
        _rule_name="Secret Detected"
        _severity="CRITICAL"
        _category="secret"
    elif [[ "$msg" == yara:* ]]; then
        _tool="yara"
        _rule_id="${msg#yara:}"
        _rule_name="IOC Match"
        _severity="HIGH"
        _category="ioc"
    elif [[ "$msg" == bandit:* ]]; then
        _tool="bandit"
        _rule_id="${msg#bandit:*:}"  # bandit:SEVERITY:B123
        _rule_name="Bandit Finding"
        if [[ "$msg" == *":HIGH:"* ]]; then _severity="HIGH"
        elif [[ "$msg" == *":MEDIUM:"* ]]; then _severity="MEDIUM"
        fi
        _category="sast"
    elif [[ "$msg" == cppcheck:* ]]; then
        _tool="cppcheck"
        _rule_id="${msg#cppcheck:}"
        _rule_name="Cppcheck Finding"
        _severity="MEDIUM"
        _category="sast"
    elif [[ "$msg" == CWE-*:* ]]; then
        _tool="grep-pattern"
        _rule_id="${msg%%:*}"
        _rule_name="${msg#*:}"
        _severity="HIGH"
        _category="cwe"
        _refs="${msg%%:*}"
    elif [[ "$msg" == OWASP-*:* ]]; then
        _tool="grep-pattern"
        _rule_id="${msg%%:*}"
        _rule_name="${msg#*:}"
        _severity="MEDIUM"
        _category="owasp"
    elif [[ "$msg" == classify_file*:* ]]; then
        _tool="File scanner detection"
        _rule_id="${msg%%:*}"
        _rule_name="${msg#*:}"
        _severity="HIGH"
        _category="classification"
    fi

    # Fallback: use raw message as rule_name if not parsed
    [[ -z "$_rule_name" ]] && _rule_name="$msg"
    [[ -z "$_tool" ]] && _tool="unknown"

    # Derive relative file path for the finding
    local _rel_file="${file#"$SCAN_DIR/"}"
    [[ "$_rel_file" == "$file" ]] && _rel_file="$file"

    _write_finding "$_tool" "$_category" "$_severity" "$_rule_id" "$_rule_name" \
                   "$_rel_file" "$_line" "$_column" "$_msg" "$_refs"
    # ── End structured finding record ───────────────────────────────────

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

generate_report_json() {
    # Data is written to temp files so Python reads it safely — no bash variable
    # expansion inside the Python source avoids code injection via filenames or
    # finding messages that contain triple-quote sequences.
    local _tmp
    _tmp=$(mktemp -d)
    trap "rm -rf '$_tmp'" RETURN

    # NUL-delimited streams for file status
    local _status_k="${_tmp}/sk"  _status_s="${_tmp}/ss" _status_m="${_tmp}/sm"
    for path in "${!FILE_STATUS[@]}"; do
        printf '%s\x00' "$path"                        >> "$_status_k"
        printf '%s\x00' "${FILE_STATUS[$path]}"        >> "$_status_s"
        printf '%s\x00' "${FILE_MSG[$path]:-}"         >> "$_status_m"
    done

    # NUL-delimited streams for coverage
    local _cov_k="${_tmp}/ck" _cov_v="${_tmp}/cv" _cov_t="${_tmp}/ct"
    local layer
    for layer in "${!LAYER_COVERAGE[@]}"; do
        printf '%s\x00' "$layer"                       >> "$_cov_k"
        printf '%s\x00' "${LAYER_COVERAGE[$layer]}"    >> "$_cov_v"
        printf '%s\x00' "${LAYER_TOOL[$layer]:-}"      >> "$_cov_t"
    done

    local repo_hash
    repo_hash=$(find "$SCAN_DIR" -type f | sort | sha256sum | awk '{print $1}')

    # All dynamic values are passed as env vars or temp-file paths — never
    # interpolated into the Python source.
    decision="REJECTED"
    status_color="#B02A37"
    status_background="#F8D7DA"

    if [[ "$GLOBAL_VERDICT" == "PASS" ]]; then
        decision="APPROVED"
        status_color="#198754"
        status_background="#D1E7DD"
        
        
    fi

    REPORT_VERDICT="$GLOBAL_VERDICT" \
    REPORT_DECISION="$decision" \
    REPORT_STATUS_COLOR="$status_color" \
    REPORT_STATUS_BG="$status_background" \
    REPORT_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    REPORT_SCAN_DIR="$SCAN_DIR" \
    REPORT_SCANNING_NAME="${SCANNING_NAME}"\
    REPORT_HASH="$repo_hash" \
    REPORT_PASS="$PASS_COUNT" \
    REPORT_WARN="$WARN_COUNT" \
    REPORT_FAIL="$FAIL_COUNT" \
    REPORT_OUT="$REPORT_JSON" \
    REPORT_FINDINGS_JL="$FINDINGS_JL" \
    python3 - "$_status_k" "$_status_s" "$_status_m" \
             "$_cov_k" "$_cov_v" "$_cov_t" <<'PYEOF'
import json, os, sys

def _read_nul(path):
    """Read a stream of NUL-terminated records, preserving empty ones."""
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


# ── Read structured findings (JSON lines) ────────────────────────────────
findings = []
_fjl = os.environ.get("REPORT_FINDINGS_JL", "")
if _fjl and os.path.exists(_fjl):
    with open(_fjl, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

# ── Read file status ─────────────────────────────────────────────────────
sk = _read_nul(sys.argv[1]); ss = _read_nul(sys.argv[2]); sm = _read_nul(sys.argv[3])
ck = _read_nul(sys.argv[4]); cv = _read_nul(sys.argv[5]); ct = _read_nul(sys.argv[6])
while len(sm) < len(sk):
    sm.append("")

file_results = {
    k: {"status": s, "message": m.rstrip(" | ")}
    for k, s, m in zip(sk, ss, sm)
}

# ── Build coverage structure ─────────────────────────────────────────────
# Map layer IDs to human-friendly tool names when available.
_layer_tool_map = {
    "L1_secrets_entropy": "detect-secrets",
    "L1_ioc_yara": "yara",
    "L1_malware": "clamav",
    "L2_owasp_cwe": "semgrep",
    "L4_patterns": "grep-patterns",
    "L5_per_language_sast": "sast",
    "L1_secrets_gitleaks": "gitleaks",
    
}

checks = []
gaps = []
for k, v, t in zip(ck, cv, ct):
    check = {"id": k}
    # Prefer the tool name passed from bash, then the static map
    _tool = t or _layer_tool_map.get(k, "")
    if _tool:
        check["tool"] = _tool

    if v == "ran":
        check["status"] = "ran"
    elif v.startswith("skipped:"):
        check["status"] = "skipped"
        check["reason"] = v.split(":", 1)[1]
        gaps.append(k)
    elif v.startswith("partial:"):
        check["status"] = "partial"
        check["reason"] = v.split(":", 1)[1]
        gaps.append(k)
    else:
        check["status"] = v
        gaps.append(k)

    checks.append(check)

gaps.sort()

report = {
    "scan_name":    os.environ["REPORT_SCANNING_NAME"],
    "timestamp":    os.environ["REPORT_TS"],
    "source": {
        "directory": os.environ["REPORT_SCAN_DIR"],
        "sha256":    os.environ["REPORT_HASH"],
    },
    "coverage": {
        "complete": len(gaps) == 0,
        "checks":   checks,
        "gaps":     gaps,
    },
    "summary": {
        "total_findings":    len(findings),
        "blocking_findings": sum(
            1 for f in findings if f.get("severity", "").upper() in ("HIGH", "CRITICAL")
        ),
    },
    "findings": findings,
    "verdict":  os.environ["REPORT_VERDICT"],
    "decision":  os.environ["REPORT_DECISION"],
    "status_background":  os.environ["REPORT_STATUS_BG"],
    "status_color":  os.environ["REPORT_STATUS_COLOR"],
}

with open(os.environ["REPORT_OUT"], "w", encoding="utf-8") as fh:
    json.dump(report, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
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


# ── Default excluded directories (always pruned from find) ───────────────────
DEFAULT_EXCLUDE_DIRS=(
    node_modules .git vendor .tox __pycache__ .venv venv
    dist build .next .nuxt .cache target coverage
)

# ── Semgrep / clamscan exclude flags from combined list ───────────────────────
SEMGREP_EXCLUDES=()
CLAMSCAN_EXCLUDES=()
for d in "${DEFAULT_EXCLUDE_DIRS[@]}"; do
    SEMGREP_EXCLUDES+=(--exclude-dir "$d")
    CLAMSCAN_EXCLUDES+=(--exclude-dir="$d")
done

# ── Argument ─────────────────────────────────────────────────────────────────
if [[ $# -lt 3 ]]; then
    fail "Usage: $0 <directory_to_scan> <directory_for_report> <scanning_name> [VERBOSITY=quiet|normal|verbose]"
fi

OFFLINE="${OFFLINE:-true}"

SCAN_DIR="$1"
[[ -d "$SCAN_DIR" ]] || fail "Directory not found: $SCAN_DIR"

REPORT_DIR="$2"
[[ -d "$REPORT_DIR" ]] || fail "Directory not found: $REPORT_DIR"

SCANNING_NAME="$3"

# ── Working variables ────────────────────────────────────────────────────────────
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
WORK_DIR="${WORK_DIR:-/home/jenkins/agent}"

CLAMAV_DB_DIR="${CLAMAV_DB_DIR:-${WORK_DIR}/clamav-rules}"
SEMGREP_RULES_DIR="${SEMGREP_RULES_DIR:-${WORK_DIR}/semgrep-rules}"

mkdir -p "${WORK_DIR}/reports" "${WORK_DIR}/quarantine" "${WORK_DIR}/approved"
chmod 700 "${WORK_DIR}/quarantine"

REPORT_JSON="${REPORT_DIR}/report_scan_${SCANNING_NAME}.json"
REPORT_HTML="${REPORT_DIR}/report_scan_${SCANNING_NAME}.html"

# Initialize structured findings file (JSON lines)
FINDINGS_JL=$(mktemp "${WORK_DIR}/findings_XXXXXX.jsonl")

# update the path to add python virtual env
# should be remove for production
# PATH="python_venv_test/.venv/bin:$PATH"


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — GLOBAL (malware, secrets, AV)
# ═══════════════════════════════════════════════════════════════════════════════
scan_global() {
    info "=== Layer 1: Global (AV, secrets, IOC) ==="
    
    if has_cmd gitleaks; then
        info "gitleaks"
        #if ! gitleaks dir "$SCAN_DIR" -v 2>/dev/null; then
        if ! gitleaks detect --no-git --source "$SCAN_DIR" -v; then
            record_fail "$SCAN_DIR" "gitleaks:secrets_detected"
        else
            record_pass "$SCAN_DIR"
            ok "gitleaks: no secrets"
        fi
        record_layer L1_secrets_gitleaks "ran"
    else
        record_warn "__global__" "gitleaks missing — secret scan skipped"
        record_layer L1_secrets_gitleaks "skipped:gitleaks not installed"
    fi
    # ══════════════════════════════════════════════════════════════════════════════
    if has_cmd detect-secrets; then
        info "detect-secrets…"
        local dsec_out
        dsec_out=$(detect-secrets scan --all-files "$SCAN_DIR" 2>/dev/null || true)
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
    # ══════════════════════════════════════════════════════════════════════════════
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
    
    # ══════════════════════════════════════════════════════════════════════════════
    if has_cmd clamscan; then
        info "clamscan…"
        # clamscan reads a local signature DB, so it works offline — but only if
        # signatures were staged. An empty DB detects nothing while still
        # exiting 0, which would read as "clean".
        local -a clam_opts=()
        
        if compgen -G "${CLAMAV_DB_DIR}/*.c[vl]d" >/dev/null 2>&1; then
            clam_opts+=(--database="$CLAMAV_DB_DIR")
        elif ! compgen -G "/var/lib/clamav/*.c[vl]d" >/dev/null 2>&1; then
            record_warn "__global__" \
                "OFFLINE:ClamAV signature database is empty — malware scan detected nothing because it has no signatures, not because the code is clean; stage a DB in ${CLAMAV_DB_DIR}"
            record_layer L1_malware "skipped:no ClamAV signatures available"
        fi

        if ! clamscan -r ${clam_opts[@]+"${clam_opts[@]}"} \
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
        out=$(semgrep --config="${ruleset}"  --json --no-autofix \
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
# LAYER 5 — Per-type SAST scanners
# ═══════════════════════════════════════════════════════════════════════════════

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
        # Hugo: add failed if files have no scanner
        *) 
            record_fail "$base.$ext" "classify_file:File have no scanner"
            
            
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
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
info "Starting scan: $SCAN_DIR"
info "Standards: OWASP Top 10 2021 · CWE Top 25 · CERT Secure Coding · SCA"

scan_global             # Layer 1: AV + secrets + IOC
scan_owasp_cwe          # Layer 2: Semgrep OWASP/CWE rulesets
# scan_dependencies       # Layer 3: SCA — vulnerable dependency CVEs
                        # Layer 4: universal patterns run inside classify_file()
scan_by_type            # Layer 5: per-language SAST
# scan_scancode           # Layer 6: licence, copyright & vulnerability (ScanCode)

generate_report_json
generate_report_html

info "JSON report : $REPORT_JSON"
info "HTML report : $REPORT_HTML"
# Write verdict and report path to sidecar files so ai_transit.sh can read them
# reliably without grepping stdout (which may contain lines from scanned tools).
echo "$GLOBAL_VERDICT" > "${WORK_DIR}/.scan_verdict"
echo "$REPORT_JSON"    > "${WORK_DIR}/.scan_report_json"
echo "$GLOBAL_VERDICT"

if [[ "$GLOBAL_VERDICT" != "PASS" ]]; then
    fail 
fi