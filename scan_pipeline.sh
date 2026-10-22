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
# Match $1 on a line that does NOT also match the exclusion $2. POSIX ERE has
# no negative lookahead, and the exclusions that matter here cannot be folded
# into the pattern: a ${...} reference, a Maven-encrypted {...} value, a
# documentation placeholder, a path to a key rather than the key itself.
# Usage: grep_check_excl <pattern> <exclusion> <file>
#
# The downstream grep deliberately writes to /dev/null instead of using -q. Under
# `set -o pipefail`, -q exits on the first hit and the upstream grep can then die
# of SIGPIPE; the pipeline reports 141 and a genuine match reads as no match.
grep_check_excl() { grep -hiE -e "$1" "$3" 2>/dev/null | grep -viE -e "$2" >/dev/null; }
# Same test over the file with newlines folded to spaces, for constructs that can
# legally be split across lines (an <!ENTITY …> declaration). Without this a
# payload evades every line-based rule by adding a line break.
# Bounded to 5 MB so a large file is not slurped into one line.
grep_flat() {
    [[ "$(wc -c < "$2" 2>/dev/null || echo 0)" -le 5242880 ]] || return 1
    tr '\r\n\t' '   ' < "$2" | grep -iE -e "$1" >/dev/null
}

# ── Known credential formats ─────────────────────────────────────────────────
# Providers issue tokens with a fixed, distinctive shape — a literal prefix plus a
# body of known length and alphabet. Matching the shape is a different and much
# more precise test than matching a *name* such as `password`, and it works in any
# file type, quoted or not: `export GITHUB_TOKEN=ghp_…`, a TOML value, a URL, a
# comment. That is what the per-type credential rules cannot do. Those expect
# `key = "value"`, so an unquoted value in a Makefile, a .properties file, a CMake
# set() call or an HTML attribute is invisible to them, and the same gap had to be
# patched separately in each scanner.
#
# This is deliberately NOT a generic `name = value` rule. That one was measured
# and rejected: it fires on 34 of 800 real .py files (`token = tokens.pop(0)`),
# because in a programming language `name = expr` is an expression. A fixed
# prefix and length has no such reading.
#
# Calibration. Across 100,052 files of source, docs and tests (gradle, spring-boot,
# kafka, elasticsearch), the 6,600 other real files collected here, and the host's
# /usr /opt /etc /var /mnt, the only matches were: AWS's own documentation key
# AKIAIOSFODNN7EXAMPLE (18, removed by the EXAMPLE exclusion), and three genuine
# Google API keys hardcoded in gcloud and gsutil. No false positive on a real
# file. What the host cannot test is recall — it holds almost no real tokens — so
# every format has a positive case in the test suite, built at run time.
#
# Formats chosen are the ones with a distinctive prefix. Heroku, Mailgun, Twilio
# and the like are bare hex or base64 with no prefix and are not matched; that is
# a limit, not an oversight, since nothing distinguishes them from a hash.
KNOWN_CRED_NAMES=(
    aws_access_key_id aws_secret_access_key github_token github_fine_grained_pat
    gitlab_pat stripe_live_key slack_token google_api_key google_oauth_token
    sendgrid_key npm_token pypi_token huggingface_token anthropic_key
    openai_project_key openai_legacy_key shopify_token digitalocean_token
)
KNOWN_CRED_PATS=(
    '(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}'
    '[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy][[:space:]]*["'"'"']?[[:space:]]*[=:][[:space:]]*["'"'"']?[A-Za-z0-9/+=]{40}'
    'gh[pousr]_[A-Za-z0-9]{36,255}'
    'github_pat_[A-Za-z0-9_]{50,}'
    'glpat-[A-Za-z0-9_-]{20,}'
    '[sr]k_live_[A-Za-z0-9]{24,}'
    'xox[bpars]-[0-9]{8,14}-[0-9]{8,14}(-[0-9]{8,14})?-[A-Za-z0-9]{20,}'
    'AIza[0-9A-Za-z_-]{35}'
    'ya29\.[0-9A-Za-z_-]{30,}'
    'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'
    'npm_[A-Za-z0-9]{36}'
    'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}'
    'hf_[A-Za-z0-9]{34,}'
    'sk-ant-(api|admin)[0-9]{2}-[A-Za-z0-9_-]{60,}'
    'sk-proj-[A-Za-z0-9_-]{40,}'
    'sk-[A-Za-z0-9]{48}'
    'shp(at|ca|pa|ss)_[a-f0-9]{32}'
    'dop_v1_[a-f0-9]{64}'
)
# One alternation for the cheap pre-check, so a file with no credential costs a
# single grep rather than eighteen. Each pattern is bounded on both sides so a
# token embedded in a longer identifier or a base64 blob does not count.
KNOWN_CRED_ALL=""
for _i in "${!KNOWN_CRED_PATS[@]}"; do
    KNOWN_CRED_ALL+="${KNOWN_CRED_ALL:+|}(^|[^A-Za-z0-9])(${KNOWN_CRED_PATS[$_i]})([^A-Za-z0-9]|\$)"
done
unset _i
# Documentation tokens and placeholders. The first run of the rule over the host
# found AWS's example key 18 times; the GitHub documentation example is split so
# this file never holds the whole string.
KNOWN_CRED_EXCL='EXAMPLE|SAMPLE|DUMMY|PLACEHOLDER|YOUR|REDACTED|FAKE|CHANGEME|x{6,}|0{10,}|\*{3,}|\.{3}|1234567890|abcdefgh|([A-Za-z0-9])\1{9,}|ghp_16C7e42F''292c6912E7710c838347Ae178B4a'

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

    # pip-audit: Python requirements.
    # The first few files are enough to decide whether to run, and `sed -n 1,5p`
    # reads its whole input where `head -5` exits early. Under `set -o pipefail`
    # head's early exit kills find with SIGPIPE once its output exceeds one
    # 4 KB write, the pipeline returns 141, and `set -e` aborts the scan with no
    # verdict and no report — a monorepo with a few dozen requirements files
    # was quarantined for that. See the monorepo tests in tests/run_tests.sh.
    local req_files
    req_files=$(find "$SCAN_DIR" -name "requirements*.txt" -o -name "Pipfile.lock" \
                -o -name "pyproject.toml" 2>/dev/null | sed -n '1,5p')
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
    pkg_files=$(find "$SCAN_DIR" -name "package-lock.json" -o -name "yarn.lock" 2>/dev/null | sed -n '1,3p')
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

# ── Shared by scan_universal_patterns and scan_jar ───────────────────────────
# $1 is the file a finding is recorded against; $2 is the file that is searched.
# They are the same for an ordinary file. For an archive, scan_jar writes the
# text of the entries to a view and searches that, while the finding must still
# land on the archive. Returns 0 only if it recorded a FAIL.

# Known credential formats. -I skips binary files: a fixed-shape token in an
# image is noise, and the base64 inside one is the only realistic source of a
# false match. One alternation decides whether any provider is present; only
# then is each named, so an ordinary file costs a single grep.
_known_cred_check() {
    local report="$1" target="$2" hit=1 _k
    if grep -qIE -e "$KNOWN_CRED_ALL" "$target" 2>/dev/null; then
        for _k in "${!KNOWN_CRED_NAMES[@]}"; do
            if grep -ohIE -e "(^|[^A-Za-z0-9])(${KNOWN_CRED_PATS[$_k]})([^A-Za-z0-9]|\$)" "$target" 2>/dev/null \
                 | grep -viE -e "$KNOWN_CRED_EXCL" >/dev/null; then
                record_fail "$report" "CWE-798:known_credential_format_${KNOWN_CRED_NAMES[$_k]}"
                hit=0
            fi
        done
    fi
    # A JWT is a signed token, not necessarily a secret: Supabase's anon key is
    # one and is public by design. Common in tests and documentation (3 in
    # 100,052 files here), so it warns.
    if grep -qIE -e '(^|[^A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}([^A-Za-z0-9]|$)' "$target" 2>/dev/null; then
        record_warn "$report" "CWE-798:jwt_embedded_review_whether_it_is_a_live_credential"
    fi
    return $hit
}

# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — Universal security patterns (all file types)
# Covers: CWE-259, CWE-321, CWE-798, CWE-22, CWE-918, CWE-327, CWE-338
# ═══════════════════════════════════════════════════════════════════════════════
scan_universal_patterns() {
    local f="$1"
    local triggered=false

    # CWE-798 / CWE-259 — Hardcoded credentials.
    #
    # The value class is [:space:], NOT \s. GNU grep reads \s as a shorthand class
    # only OUTSIDE a bracket expression; inside one, [^"\s] is a negated set of the
    # literal characters \ and s. This rule therefore required four characters none
    # of which was an "s" — it missed password = "sup3rs3cret" and every other
    # secret with an s near the front, and, by accident, the placeholders "secret"
    # and "password" too. The same slip was at three other sites below. A lint rule
    # in tests/run_tests.sh now forbids a backslash class inside a bracket.
    if grep_check \
        '(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["'"'"'][^${"'"'"'[:space:]]{4,}' \
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
    #
    # The header alone is not enough: it also appears as a file-type SIGNATURE,
    # describing how to recognise a key file rather than containing one. The
    # shared-mime-info database has magic="-----BEGIN PGP PRIVATE KEY BLOCK-----",
    # and two of 3362 real XML files failed on it. A key has a base64 body right
    # after the header — 64 characters a line in PEM, 70 in OpenSSH — so the
    # test is the header followed within a few lines by a run of 60 or more.
    # That also covers a key held on one line as a JSON string, where the
    # newlines are the two characters \n, and a PGP block, whose armor headers
    # push the body a line or two down.
    if grep -E -A5 -e '-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----' "$f" 2>/dev/null \
         | tr '\r\n\t' '   ' \
         | grep -E -e '-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.{0,200}[A-Za-z0-9+/]{60,}' \
         >/dev/null; then
        record_fail "$f" "CWE-321:hardcoded_private_key"
        triggered=true
    fi

    # Known credential formats and the JWT warning: see _known_cred_check.
    if _known_cred_check "$f" "$f"; then
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
    local failed=false base x="$f" tmp=""
    base=$(basename "$f")

    # Work on a view with <!-- comments --> removed. A line-based rule cannot
    # see a comment boundary, and commented-out examples are how XML config
    # normally documents itself: Maven's own shipped settings.xml holds real-
    # looking <password> values inside a comment block, and an `<!ENTITY` in a
    # comment is not a declaration at all. Without python3 the raw file is
    # scanned instead, which errs towards reporting.
    if has_cmd python3; then
        tmp=$(mktemp "${TMPDIR:-/tmp}/aitransit_xml_XXXXXX" 2>/dev/null) || tmp=""
        if [[ -n "$tmp" ]]; then
            python3 -c '
import re, sys
d = open(sys.argv[1], "rb").read()
sys.stdout.buffer.write(re.sub(rb"<!--.*?-->", b" ", d, flags=re.S))
' "$f" > "$tmp" 2>/dev/null || true
            [[ -s "$tmp" ]] && x="$tmp"
        fi
    fi

    # ── XXE ──────────────────────────────────────────────────────────────
    # The primitive is an ENTITY that points at something, not a DOCTYPE. A bare
    # <!DOCTYPE failed 736 of 3362 real XML files (22%) — toolbar 390, feature
    # 82, rss 50, node 45 — and pom.xml and Ant's build.xml both route here, so
    # Maven and Ant repositories were quarantined over a doctype. A bare
    # <!ENTITY failed 8 more, and every one was a text shortcut (&nbsp;) or a W3C
    # HTML DTD reference, never an attack. Matched with newlines folded, because
    # a declaration split across lines is still a declaration.
    if grep_flat '<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+["'"'"'](file:|expect:|php:|gopher:|jar:|netdoc:|ftp:|https?:|/|\\\\)' "$x"; then
        record_fail "$f" "CWE-611:xxe_external_entity_references_a_resource"
        failed=true
    fi
    # Four or more entity references inside one entity value is the shape of an
    # expansion bomb; ordinary shortcuts such as &#160; are not named references.
    if grep_flat '<!ENTITY[[:space:]]+[%]?[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]+["'"'"'][^"'"'"']*(&[A-Za-z0-9_.-]+;[^"'"'"'&]*){4,}' "$x"; then
        record_fail "$f" "CWE-776:xml_entity_expansion_bomb"
        failed=true
    fi
    # An external entity that is not an obvious attack: a relative SYSTEM include
    # (DocBook uses them) or a PUBLIC DTD reference. 4 of 3362, all W3C ones.
    if grep_flat '<!ENTITY[^>]*[[:space:]](SYSTEM|PUBLIC)[[:space:]]' "$x"; then
        record_warn "$f" "CWE-611:xml_declares_an_external_entity"
    fi

    # ── Credentials ──────────────────────────────────────────────────────
    # The ELEMENT NAME is the credential word. The earlier rule let [^>]*> run
    # from a `token`-ish attribute name across the rest of the tag into a later
    # element's closing tag, so checkstyle's tokens="LITERAL_DO,…" and the
    # sentence "password manager! Thanks</p>" both matched. 11 raw matches on
    # 3362 files, 2 after the exclusions below, and one of those is a genuine
    # plaintext token in a POM.
    #
    # Excluded values are the correct forms: a ${…} reference, a Maven-encrypted
    # {…} value, a path to a key (as opposed to the key), and the placeholder
    # words that documentation uses, and a value cut short with "...".
    if grep_check_excl \
        '<(password|passphrase|secret|apiKey|api-key|accessKey|privateKey|token)>[[:space:]]*[^<[:space:]]{6,}' \
        '>[[:space:]]*(\$\{|\{|/|~|[A-Za-z]:\\)|>[[:space:]]*(changeit|changeme|password|passwd|secret|somepassword|proxypass|repopwd|example|placeholder|optional|x{3,}|\*+|your[-_a-z]*)[[:space:]]*<|\.\.\.[[:space:]]*<' \
        "$x"; then
        record_fail "$f" "CWE-798:hardcoded_credential_in_XML"
        failed=true
    fi

    # ── Maven ────────────────────────────────────────────────────────────
    case "$base" in
    pom.xml|*.pom)
        # A repository over plaintext http://, so anyone on the path chooses
        # what is resolved and then run. Scoped to <repository> blocks: the
        # default Maven archetype writes <url>http://maven.apache.org</url> as a
        # project HOMEPAGE, and an unscoped rule would fail every generated POM.
        # 5 of 221 real poms, all of them Gradle's own insecureProtocol* test
        # fixtures — true positives by content.
        if awk '
            /<(repository|pluginRepository|snapshotRepository)>/ { r = 1 }
            r && /<url>[ \t]*http:\/\// { found = 1 }
            /<\/(repository|pluginRepository|snapshotRepository)>/ { r = 0 }
            END { exit !found }' "$x"; then
            record_fail "$f" "CWE-319:maven_repository_over_plaintext_http"
            failed=true
        fi
        # exec-maven-plugin / antrun invoking a shell or a downloader, at build
        # time. 0 of 221. The plugins themselves are ordinary (1 of 221), so
        # only the executable decides.
        if grep_check_i '(<executable>[[:space:]]*(sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh|curl|wget)[[:space:]]*<|<exec[^>]*executable=["'"'"'](sh|bash|zsh|cmd|powershell|pwsh|curl|wget)["'"'"'])' "$x"; then
            record_fail "$f" "CWE-78:maven_exec_runs_shell_or_downloader"
            failed=true
        fi
        if grep_check_i 'exec-maven-plugin' "$x"; then
            record_warn "$f" "maven:exec_plugin_runs_a_program_during_the_build"
        fi
        if grep_check_i 'maven-antrun-plugin' "$x"; then
            record_warn "$f" "maven:antrun_plugin_runs_arbitrary_ant_tasks"
        fi
        # system scope points at a file on the build host rather than a
        # resolved artifact. 3 of 221, all spring-boot test fixtures.
        if grep_check_i '<scope>[[:space:]]*system[[:space:]]*<' "$x"; then
            record_warn "$f" "maven:system_scope_dependency_bypasses_resolution"
        fi
        # Deliberately no rule for -SNAPSHOT: 176 of 221 real poms use one.
        ;;
    build.xml|build-*.xml|*-build.xml)
        # 0 of 22 real build.xml for each FAIL rule below, a small corpus.
        if grep_check_i '<get[^>]+src=["'"'"']http://' "$x"; then
            record_fail "$f" "CWE-319:ant_get_over_plaintext_http"
            failed=true
        fi
        if grep_check_i '<exec[^>]*executable=["'"'"'](sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh|curl|wget)["'"'"']' "$x"; then
            record_fail "$f" "CWE-78:ant_exec_runs_shell_or_downloader"
            failed=true
        fi
        if grep_check_excl \
            '<(sshexec|scp|ftp)[^>]*[[:space:]]password=["'"'"'][^"'"'"']{4,}' \
            'password=["'"'"']\$\{' "$x"; then
            record_fail "$f" "CWE-798:ant_credential_attribute"
            failed=true
        fi
        if grep_check_i '<exec[[:space:]>]' "$x"; then
            record_warn "$f" "ant:exec_task_runs_a_program_during_the_build"
        fi
        ;;
    esac

    [[ -n "$tmp" ]] && rm -f "$tmp"
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
    # [:space:], not \s, inside the bracket. Here the slip ran the other way: the
    # class did not exclude whitespace, so `password:` followed by trailing spaces
    # counted as a value. Fixing it removed 27 false positives from 3328 real files.
    if grep_check '(password|secret|token|key|api_key)\s*:\s*[^${[:space:]][^{]' "$f"; then
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

# ── Java archives (.jar .war .ear .aar) ─────────────────────────────────────
# Before this scanner a .jar had no handler, fell through to scan_unknown and was
# recorded PASS. A jar is a ZIP of compiled code, which makes it three problems
# at once:
#
#   * It is executable code that a reviewer cannot read, so it is never silently
#     passed: a clean jar is a WARN ("vendored compiled code"), never a PASS.
#   * The container can lie. An entry named ../../etc/cron.d/x escapes the
#     extraction directory (zip-slip); a ".class" entry need not be bytecode; a
#     Windows executable can be stored as "logo.png"; a native binary can be
#     glued in front of a valid archive.
#   * gradle-wrapper.jar, committed to nearly every Gradle repository, is run by
#     ./gradlew before any code the repository declares.
#
# The archive is never extracted to disk. The helper reads entries through the
# standard library with bounded reads, so a decompression bomb costs a capped
# read and not the disk. Each limit is reported when it is reached, because an
# archive that was not fully read must not look like one that was:
#   JAR_MAX_ENTRIES (50000)         entries whose bytes are read
#   JAR_READ_BUDGET_MB (64)         bytes read across all entries
#   JAR_VIEW_MB (32)                text handed to the credential rules
#   JAR_MAX_UNCOMPRESSED_MB (1024)  declared size above which a WARN is raised
#   JAR_TIME_BUDGET_S (90)          wall-clock limit for one archive
# Entry NAMES are checked for every entry regardless: that needs only the
# central directory. Nested archives are opened two levels deep.
#
# Calibration: 365 real jars on this host (Gradle and Maven distributions,
# Kotlin, Groovy, the native-platform family) and 24 build-tool wrappers. None of
# the FAIL rules fires on any of them. What is reported: 17 jars bundle native
# libraries, 2 are Java agents, 1 nests another archive, and 1 exceeds the read
# budget (kotlin-compiler-embeddable, 150 MB uncompressed). That corpus is
# libraries from two toolchains; it says nothing about how often a hostile jar
# looks like a real one, so recall rests on fixtures. Only .jar was measured:
# .war, .ear and .aar are routed to the same scanner because they are the same
# container, and none exists on this host.
#
# Not covered, deliberately: bytecode semantics (no decompilation, so a
# Runtime.exec(userInput) in a class is not found), JSP web shells inside a .war,
# and the contents of gradle-wrapper.jar beyond its shape (the official
# checksums are not embedded, so that file always asks for a manual check).
_jar_facts() {
    python3 - "$1" "$2" <<'PYEOF' 2>/dev/null
import io, os, re, struct, sys, time, zipfile, zlib

# argv: <archive> <view file: the text of the entries, for the credential rules>
path, view_path = sys.argv[1], sys.argv[2]


def _knob(name, default):
    try:
        v = float(os.environ.get(name, ""))
        return v if v > 0 else default
    except ValueError:
        return default


MAX_ENTRIES = int(_knob("JAR_MAX_ENTRIES", 50000))  # entries whose bytes are read
BUDGET = int(_knob("JAR_READ_BUDGET_MB", 64) * 1048576)  # bytes read across all entries
MAX_UNCOMP = int(_knob("JAR_MAX_UNCOMPRESSED_MB", 1024) * 1048576)
DEADLINE = time.monotonic() + _knob("JAR_TIME_BUDGET_S", 90)
ENTRY_CAP = 4 * 1048576   # most that is read from one entry
NEST_CAP = 16 * 1048576   # largest nested archive that is opened
VIEW_CAP = int(_knob("JAR_VIEW_MB", 32) * 1048576)  # most text handed to the credential rules
MAX_DEPTH = 2             # the archive itself, and one level inside it
HEAD = 4096

facts = {}
state = {"entries": 0, "budget": BUDGET, "declared": 0, "view": 0}


def emit(tag, detail=""):
    detail = re.sub(r"[^\x20-\x7e]|\|", "?", str(detail))[:110]
    n, ex = facts.get(tag, (0, []))
    if len(ex) < 3 and detail not in ex:
        ex.append(detail)
    facts[tag] = (n + 1, ex)


NATIVE_NAME = re.compile(r"\.(so(\.\d+)*|dll|dylib|jnilib|exe|sys|ocx|node)$", re.I)
SCRIPT_NAME = re.compile(r"\.(sh|bat|cmd|ps1|vbs|hta|scr|msi)$", re.I)
ARCHIVE_NAME = re.compile(r"\.(jar|war|ear|aar|zip|tar|tgz|gz|bz2|xz|7z|rar)$", re.I)
CONTENT_NAME = re.compile(
    r"\.(class|properties|xml|json|txt|sh|bat|cmd|ps1|vbs|js|py|jsp|jspx|html?|ya?ml|conf|cfg|ini|"
    r"gradle|kts|md|toml|env|sql|groovy|java|pem|key)$|(^|/)(MANIFEST\.MF)$", re.I)
MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
         b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
# 0xCAFEBABE is deliberately absent: it is the Java class magic, and also the
# Mach-O *fat* magic. kotlinx-coroutines ships a class stored as DebugProbesKt.bin.
CLASS_MAGIC = b"\xca\xfe\xba\xbe"
READ_ERRORS = (RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError, zlib.error, OSError, ValueError)

HOSTILE = [
    ("shell_pipe", re.compile(r"(?i)\b(curl|wget)\b[^\n|]{0,160}\|\s*(sudo\s+)?(ba|z|da)?sh\b")),
    ("reverse_shell", re.compile(r"(/dev/tcp/|\bnc\s+-[a-z]*e\s|bash\s+-i\s+>&)")),
    ("encoded_powershell", re.compile(r"(?i)powershell[^\n]{0,80}\s-(e|enc|encodedcommand)[a-z]*\s+[A-Za-z0-9+/=]{20,}")),
    ("lolbin_download", re.compile(r"(?i)(certutil[^\n]{0,60}-urlcache|bitsadmin[^\n]{0,60}/transfer)")),
    ("offensive_tool_name", re.compile(r"(?i)(mimikatz|sekurlsa|meterpreter|cobalt\s?strike)")),
]


def native_kind(head):
    """ELF, thin Mach-O, or a PE whose e_lfanew really points at PE\\0\\0 (not just an MZ prefix)."""
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in MACHO:
        return "Mach-O"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        e = struct.unpack_from("<I", head, 0x3C)[0]
        if e + 4 <= len(head) and head[e:e + 4] == b"PE\x00\x00":
            return "PE"
    return ""


def texty(head):
    """True for a head that reads as text: no NUL, and almost all printable."""
    if not head or b"\x00" in head:
        return False
    return sum(1 for b in head if b >= 0x20 or b in (9, 10, 13)) / len(head) > 0.95


def class_strings(data):
    """UTF-8 constants of a class file's constant pool, or None if it does not parse."""
    try:
        if data[:4] != CLASS_MAGIC or len(data) < 10:
            return None
        count = struct.unpack_from(">H", data, 8)[0]
        i, pos, out = 1, 10, []
        while i < count:
            tag = data[pos]
            pos += 1
            if tag == 1:
                ln = struct.unpack_from(">H", data, pos)[0]
                out.append(data[pos + 2:pos + 2 + ln].decode("utf-8", "replace"))
                pos += 2 + ln
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                pos += 4
            elif tag in (5, 6):
                pos += 8
                i += 1
            elif tag in (7, 8, 16, 19, 20):
                pos += 2
            elif tag == 15:
                pos += 3
            else:
                return None
            i += 1
        return out
    except (IndexError, struct.error):
        return None


def parse_manifest(raw):
    text = raw.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n ", "", text)  # a line continues on the next one that starts with a space
    attrs = {}
    for line in text.split("\n"):
        if not line.strip():
            break  # the main section ends at the first blank line
        k, _, v = line.partition(":")
        attrs[k.strip().lower()] = v.strip()
    return attrs


view = open(view_path, "w", encoding="utf-8", errors="replace")


def to_view(label, text):
    if state["view"] >= VIEW_CAP:
        emit("incomplete", "text handed to the credential rules is capped at %d MB" % (VIEW_CAP >> 20))
        return
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text)
    view.write("== " + label + "\n" + text + "\n")
    state["view"] += len(text)


def hostile(label, text):
    for tag, rx in HOSTILE:
        if rx.search(text):
            emit("hostile_" + tag, label)


PEM_HEAD = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----")
PEM_BODY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.{0,200}[A-Za-z0-9+/]{60,}")


def private_key(label, unit):
    """A PEM header followed, within about five lines, by 60+ base64 characters.

    Judged inside ONE string, never across neighbours. A class file keeps each
    constant on its own line of the view, and a class path such as
    org/apache/sshd/common/config/keys/loader/openssh/OpenSSHKeyPairResourceParser
    is 78 characters of [A-Za-z0-9/], which the body test reads as base64: the
    header constant followed by that path failed sshd-common-2.12.1.jar.
    """
    for m in PEM_HEAD.finditer(unit):
        flat = re.sub(r"(?:\\[nrt]|[\r\n\t])+", " ", unit[m.start():m.start() + 700])
        if PEM_BODY.match(flat):
            emit("private_key", label)
            return


def name_checks(infos, label, top):
    """Everything that needs only the central directory. Unbounded by the read limits: it costs nothing."""
    names = [i.filename for i in infos]
    if top and len(set(names)) != len(names):
        emit("duplicate_names", "%d repeated" % (len(names) - len(set(names))))
    for info in infos:
        n, full = info.filename, label + info.filename
        state["declared"] += info.file_size
        parts = n.replace("\\", "/").split("/")
        if ".." in parts or n.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", n):
            emit("zip_slip", full)
        if SCRIPT_NAME.search(n):
            emit("script_entry", full)
        if info.flag_bits & 0x1 and not info.is_dir():
            emit("encrypted", full)
    return names


def walk(z, label, depth, top):
    infos = z.infolist()
    names = name_checks(infos, label, top)
    room = MAX_ENTRIES - state["entries"]
    if len(infos) > room:
        emit("incomplete", "more than %d entries, the rest were not read" % MAX_ENTRIES)
        infos = infos[:max(room, 0)]
    state["entries"] += len(infos)
    for info in infos:
        n = info.filename
        full = label + n
        if info.is_dir() or info.flag_bits & 0x1:
            continue
        if time.monotonic() > DEADLINE:
            emit("incomplete", "time budget exceeded")
            break
        # A symlink entry is a zip-slip with one more step: it is created on
        # extraction and the next entry is written through it.
        if info.create_system == 3 and (info.external_attr >> 16) & 0o170000 == 0o120000:
            try:
                with z.open(info) as fh:
                    target = fh.read(HEAD).decode("utf-8", "replace")
            except READ_ERRORS:
                target = ""
            t = target.replace("\\", "/")
            if t.startswith("/") or ".." in t.split("/") or re.match(r"^[A-Za-z]:", t):
                emit("symlink_escape", "%s -> %s" % (full, target))
            else:
                emit("symlink", full)
            continue
        wants_content = bool(CONTENT_NAME.search(n))
        try:
            with z.open(info) as fh:
                data = fh.read(min(ENTRY_CAP, max(info.file_size, HEAD)) if wants_content and state["budget"] > 0 else HEAD)
        except READ_ERRORS:
            emit("unreadable", full)
            continue
        head = data[:HEAD]
        # Entries with no recognised name (LICENSE, services files, .cert, .dat)
        # are read as text when they look like text; binary ones are not.
        if not wants_content and texty(head):
            if state["budget"] > 0:
                try:
                    with z.open(info) as fh:
                        data = fh.read(min(ENTRY_CAP, max(info.file_size, HEAD)))
                    wants_content = True
                except READ_ERRORS:
                    pass
            else:
                emit("incomplete", "read budget of %d MB exhausted" % (BUDGET >> 20))
        if wants_content:
            if state["budget"] <= 0:
                emit("incomplete", "read budget of %d MB exhausted" % (BUDGET >> 20))
                wants_content = False
            else:
                state["budget"] -= len(data)
        if wants_content and info.file_size > ENTRY_CAP:
            emit("incomplete", "an entry larger than %d MB was read only in part" % (ENTRY_CAP >> 20))
        is_class = n.endswith(".class")
        if is_class and len(head) >= 4 and head[:4] != CLASS_MAGIC:
            emit("class_not_bytecode", full)
        kind = native_kind(head)
        if NATIVE_NAME.search(n):
            if kind:
                emit("native_library", full)
        elif kind and not is_class:
            emit("hidden_native", "%s %s" % (kind, full))
        if n.upper() == "META-INF/MANIFEST.MF":
            a = parse_manifest(data)
            if depth == 1 and any(k in a for k in ("premain-class", "agent-class", "launcher-agent-class")):
                emit("agent", a.get("premain-class") or a.get("agent-class") or a.get("launcher-agent-class"))
            for tok in a.get("class-path", "").split():
                if re.match(r"^(https?|ftp)://", tok, re.I):
                    emit("classpath_remote", tok)
                elif depth == 1 and (tok.startswith(("/", "\\")) or re.match(r"^([A-Za-z]:|file:)", tok, re.I)):
                    emit("classpath_absolute", tok)
        if not is_class and (head[:4] == b"PK\x03\x04" or ARCHIVE_NAME.search(n)):
            emit("nested_archive", full)
            if depth >= MAX_DEPTH:
                emit("incomplete", "archives nested deeper than %d levels were not opened" % MAX_DEPTH)
            elif info.file_size > NEST_CAP or state["budget"] <= 0:
                emit("incomplete", "a nested archive was not opened: " + full)
            else:
                try:
                    with z.open(info) as fh:
                        raw = fh.read(NEST_CAP)
                    state["budget"] -= len(raw)
                    walk(zipfile.ZipFile(io.BytesIO(raw)), full + "!/", depth + 1, False)
                except READ_ERRORS:
                    emit("nested_unparseable", full)
            continue
        if not wants_content:
            continue
        if is_class:
            units = class_strings(data)
            if units is None:
                units = re.sub(r"[^\x20-\x7e\n]+", "\n", data.decode("latin-1")).split("\n")
        else:
            units = [data.decode("utf-8", "replace")]
        text = "\n".join(units)
        to_view(full, text)
        hostile(full, text)
        for u in units:
            private_key(full, u)
    return names


# ── Whole-file shape ────────────────────────────────────────────────────
try:
    with open(path, "rb") as fh:
        first = fh.read(4096)
except OSError:
    first = None
    emit("unreadable_file")

zf = None
if first is not None:
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, ValueError):
        if not first:
            emit("empty_file")
        elif first[:2] == b"PK":
            emit("unparseable")
        else:
            emit("not_an_archive", native_kind(first) or first[:8].hex())

if zf is not None:
    k = native_kind(first)
    if first[:2] != b"PK":
        if k:
            emit("prepended_native", k)
        elif first[:2] == b"#!":
            emit("prepended_script")
        else:
            emit("prepended_data", first[:8].hex())
    names = walk(zf, "", 1, True)
    if state["declared"] > MAX_UNCOMP:
        emit("oversize", "%d MB declared" % (state["declared"] >> 20))
    # gradle-wrapper.jar runs on ./gradlew before any code the repository
    # declares. Its shape is checkable; its contents are not (the official
    # checksums are not embedded here), so it always also asks for a manual check.
    spec = {
        "gradle-wrapper.jar": ("gradle", ("org/gradle/", "META-INF/"), "org/gradle/wrapper/GradleWrapperMain.class"),
        "maven-wrapper.jar": ("maven", ("org/apache/maven/", "META-INF/"), "org/apache/maven/wrapper/MavenWrapperMain.class"),
    }.get(os.path.basename(path).lower())
    if spec:
        kind, prefixes, must = spec
        files = [x for x in names if not x.endswith("/")]
        for x in [x for x in files if not x.startswith(prefixes)][:3]:
            emit("wrapper_unexpected", "unexpected entry " + x)
        if must not in files:
            emit("wrapper_unexpected", "missing " + must)
        if len(files) > 100:
            emit("wrapper_unexpected", "%d entries" % len(files))
        emit("wrapper", kind)
view.close()
for tag, (n, ex) in facts.items():
    print("FACT %s %d %s" % (tag, n, "; ".join(ex)))
print("FACT done")
PYEOF
}

scan_jar() {
    local f="$1"
    local failed=false view="" facts="" line tag count detail entry msg
    local -A fact_n=() fact_d=()

    if ! has_cmd python3; then
        record_warn "$f" "jar:not_inspected(install python3 so scan_jar can read the archive)"
        return 0
    fi
    view=$(mktemp "${TMPDIR:-/tmp}/aitransit_jar_XXXXXX" 2>/dev/null) || view=""
    if [[ -z "$view" ]]; then
        record_warn "$f" "jar:not_inspected(could not create a temporary file)"
        return 0
    fi
    # Removed explicitly at the single exit point below, not by a RETURN trap
    # (see scan_pdf for why).
    facts=$(_jar_facts "$f" "$view") || facts=""

    while IFS= read -r line; do
        [[ "$line" == "FACT "* ]] || continue
        line="${line#FACT }"
        tag="${line%% *}"
        line="${line#"$tag"}"; line="${line# }"
        count="${line%% *}"
        detail="${line#"$count"}"; detail="${detail# }"
        fact_n["$tag"]="$count"
        fact_d["$tag"]="$detail"
    done <<< "$facts"

    if [[ -z "${fact_n[done]+x}" ]]; then
        # The helper died before finishing. Say so: no facts is not a clean jar.
        record_warn "$f" "jar:inspection_failed(the archive could not be read; treat as not inspected)"
        rm -f "$view"
        return 0
    fi

    # FAIL: tag|message. Each has no innocent reading in a repository, and each
    # measured 0 of 365 real jars.
    local -a fail_map=(
        "zip_slip|CWE-22:jar_entry_path_traversal_zip_slip"
        "class_not_bytecode|CWE-506:jar_class_entry_is_not_bytecode"
        "hidden_native|CWE-506:jar_native_executable_hidden_under_a_non_native_name"
        "private_key|CWE-321:hardcoded_private_key"
        "classpath_remote|CWE-829:jar_manifest_class_path_names_a_remote_url"
        "prepended_native|CWE-506:jar_native_executable_prepended_to_archive"
        "not_an_archive|jar:file_is_not_an_archive_despite_its_extension"
        "symlink_escape|CWE-22:jar_symlink_entry_points_outside_the_archive"
        "wrapper_unexpected|CWE-494:wrapper_jar_has_unexpected_content"
        "hostile_shell_pipe|CWE-78:jar_embeds_download_piped_to_shell"
        "hostile_reverse_shell|CWE-78:jar_embeds_reverse_shell"
        "hostile_encoded_powershell|CWE-78:jar_embeds_encoded_powershell"
        "hostile_lolbin_download|CWE-494:jar_embeds_certutil_or_bitsadmin_download"
    )
    for entry in "${fail_map[@]}"; do
        tag="${entry%%|*}"; msg="${entry#*|}"
        if [[ -n "${fact_n[$tag]+x}" ]]; then
            record_fail "$f" "${msg}(${fact_n[$tag]}${fact_d[$tag]:+: ${fact_d[$tag]}})"
            failed=true
        fi
    done

    # WARN: ordinary in some jars (native libraries 17 of 365, agents 2 of 365),
    # or a statement that something was not looked at.
    local -a warn_map=(
        "agent|jar:java_agent_in_manifest"
        "native_library|jar:bundles_native_library"
        "script_entry|jar:bundles_script_file"
        "symlink|jar:contains_symlink_entry"
        "nested_archive|jar:contains_nested_archive"
        "nested_unparseable|jar:nested_archive_could_not_be_opened"
        "classpath_absolute|jar:manifest_class_path_is_absolute"
        "duplicate_names|jar:duplicate_entry_names_readers_may_disagree_about_which_is_used"
        "encrypted|jar:encrypted_entries_not_inspected"
        "unreadable|jar:entries_could_not_be_read"
        "incomplete|jar:inspection_incomplete"
        "oversize|jar:declared_uncompressed_size_over_limit"
        "unparseable|jar:unparseable_archive_not_inspected"
        "unreadable_file|jar:file_could_not_be_read"
        "empty_file|jar:empty_file"
        "prepended_script|jar:launch_script_prepended_to_archive"
        "prepended_data|jar:data_before_archive_start"
        "hostile_offensive_tool_name|jar:offensive_tool_name_in_content"
    )
    for entry in "${warn_map[@]}"; do
        tag="${entry%%|*}"; msg="${entry#*|}"
        if [[ -n "${fact_n[$tag]+x}" ]]; then
            record_warn "$f" "${msg}(${fact_n[$tag]}${fact_d[$tag]:+: ${fact_d[$tag]}})"
        fi
    done
    if [[ -n "${fact_n[wrapper]+x}" ]]; then
        record_warn "$f" \
            "jar:wrapper_checksum_must_be_verified(${fact_d[wrapper]} wrapper jar runs before any code the repository declares; its shape is checked but not its contents)"
    fi

    # Credentials in the text of the entries. Class files are searched through
    # their constant pools, where string constants live. Private keys are judged
    # per string inside the helper, not here: see private_key().
    if [[ -s "$view" ]]; then
        _known_cred_check "$f" "$view" && failed=true
    fi

    # Bytecode is not reviewed. A jar with nothing wrong with its structure is
    # still opaque executable code, and says so.
    if [[ "$failed" != true ]]; then
        record_warn "$f" "jar:vendored_compiled_code_not_reviewable"
    fi

    rm -f "$view"
    return 0
}

# ── Package manifests ────────────────────────────────────────────────────────
# package.json and requirements.txt used to get a single credential grep. That
# left the thing that actually matters in a manifest unexamined: code that runs
# when the dependencies are installed. npm runs preinstall, install and
# postinstall on every `npm install`, and prepare on a bare one, so a hostile
# hook fires before anything is built or reviewed.
#
# Calibration is weak and should be read that way. Of 1189 parseable
# package.json on this host, 3 carry an install hook — but the corpus is mostly
# published packages under node_modules, not application roots, so it says
# little about how often an AI-generated repository's own manifest has one. The
# FAIL rules measured 0 real hits; the only fetch-piped-to-shell file found was
# a fixture left by a research agent. The rules therefore rest on what the
# constructs mean rather than on a measured rate, and the WARN tier carries the
# ones that are ordinary in some projects (an install hook, a git dependency).
#
# JSON is parsed rather than grepped. A key can be written "post\u0069nstall",
# which npm reads as postinstall and a pattern does not.
_pkg_facts() {
    python3 - "$1" <<'PYEOF' 2>/dev/null
import json, os, re, sys

path = sys.argv[1]
base = os.path.basename(path)
try:
    with open(path, encoding="utf-8", errors="replace") as fh:
        d = json.load(fh)
except Exception:
    print("FACT unparsed")
    raise SystemExit(0)
if not isinstance(d, dict):
    print("FACT unparsed")
    raise SystemExit(0)
# Parsing succeeded. This is stated outright because a manifest with nothing to
# report prints nothing else, and empty output must not be read as a failure.
print("FACT parsed")

PIPE   = re.compile(r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b", re.I)
DECODE = re.compile(r"(base64\s+(-d|-D|--decode)|openssl\s+enc\s+-d)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b"
                    r"|/dev/tcp/|\bnc(at)?\s+-[a-z]*e\b", re.I)
FETCH  = re.compile(r"\b(curl|wget)\b", re.I)


def emit(kind):
    print("FACT " + kind)


def commands(value):
    """A script is a string, or for Composer a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


if base == "composer.json":
    LIFE = {"pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd",
            "post-autoload-dump", "post-root-package-install", "post-create-project-cmd",
            "pre-autoload-dump", "post-package-install", "post-package-update"}
    scripts = d.get("scripts") if isinstance(d.get("scripts"), dict) else {}
    for key, val in scripts.items():
        for cmd in commands(val):
            # "@php artisan x" is a script reference and "Vendor\Class::method" a
            # PHP callable; only a shell command line can fetch and execute.
            if cmd.startswith("@") or "::" in cmd:
                continue
            life = key in LIFE
            if PIPE.search(cmd):
                emit("hook_pipe" if life else "script_pipe")
            elif DECODE.search(cmd):
                emit("hook_decode" if life else "script_decode")
            elif FETCH.search(cmd):
                emit("script_fetch")
    cfg = d.get("config") if isinstance(d.get("config"), dict) else {}
    if cfg.get("secure-http") is False:
        emit("composer_insecure")
    repos = d.get("repositories")
    items = list(repos.values()) if isinstance(repos, dict) else (repos if isinstance(repos, list) else [])
    for r in items:
        if isinstance(r, dict) and isinstance(r.get("url"), str) and r["url"].startswith("http://"):
            emit("composer_insecure")
    raise SystemExit(0)

# npm
LIFE_NPM = {"preinstall", "install", "postinstall", "prepare", "prepack", "postpack",
            "prepublish", "prepublishOnly", "publish", "postpublish",
            "preuninstall", "uninstall", "postuninstall"}
INSTALL_TIME = {"preinstall", "install", "postinstall"}
scripts = d.get("scripts") if isinstance(d.get("scripts"), dict) else {}
for key, val in scripts.items():
    if not isinstance(val, str):
        continue
    life = key in LIFE_NPM
    if key in INSTALL_TIME:
        emit("install_hook")
    if PIPE.search(val):
        emit("hook_pipe" if life else "script_pipe")
    elif DECODE.search(val):
        emit("hook_decode" if life else "script_decode")
    elif FETCH.search(val):
        emit("script_fetch")

for dk in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
    deps = d.get(dk) if isinstance(d.get(dk), dict) else {}
    for spec in deps.values():
        if not isinstance(spec, str):
            continue
        if re.match(r"^(http://|git://|git\+http://)", spec):
            emit("dep_plain")
        elif (re.match(r"^(https://|git\+https://|git\+ssh://|github:|gitlab:|bitbucket:)", spec)
              or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", spec)):
            emit("dep_remote")
PYEOF
}

scan_package_json() {
    local f="$1"
    local failed=false facts="" base
    base=$(basename "$f")
    if has_cmd python3; then
        facts=$(_pkg_facts "$f" || true)
    fi

    if [[ "$facts" != *"FACT parsed"* ]]; then
        # Invalid JSON (a template with comments) or no python3: fall back to
        # patterns on the raw text, and say the inspection was weaker. 6 of 1195
        # real package.json were not valid JSON.
        #
        # Absence of facts is NOT the test. A valid manifest with nothing to
        # report prints nothing, and the first version read that as a failed
        # parse: 1172 of 1193 real files took this path.
        record_warn "$f" "pkg:not_parsed_as_json_checked_by_pattern_only"
        if grep_check_i '"((pre|post)?install|prepare|prepublish(only)?|post-install-cmd|post-update-cmd)"[[:space:]]*:[[:space:]]*"[^"]*(curl|wget)[^"]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh' "$f"; then
            facts+=$'\nFACT hook_pipe'
        fi
        # Without parsing there is no telling a dependency from a repository
        # or homepage URL — `"url": "git://github.com/x/y.git"` is in most
        # published packages and the first fallback failed 154 files on it. So
        # this can only warn.
        if grep_check_i '"[^"]+"[[:space:]]*:[[:space:]]*"(http|git)://' "$f"; then
            record_warn "$f" "pkg:plaintext_url_present_unscoped_check_dependencies_manually"
        fi
    fi

    if [[ "$base" == "composer.json" ]]; then
        if [[ "$facts" == *"FACT hook_pipe"* ]]; then
            record_fail "$f" "CWE-78:composer_hook_fetches_and_executes"; failed=true
        fi
        if [[ "$facts" == *"FACT hook_decode"* ]]; then
            record_fail "$f" "CWE-78:composer_hook_decodes_and_executes"; failed=true
        fi
        if [[ "$facts" == *"FACT composer_insecure"* ]]; then
            record_fail "$f" "CWE-319:composer_insecure_transport"; failed=true
        fi
        # Composer hooks are ordinary (@php artisan …); fetching in one is not.
        if [[ "$facts" == *"FACT script_fetch"* || "$facts" == *"FACT script_pipe"* ]]; then
            record_warn "$f" "composer:script_fetches_from_the_network"
        fi
    else
        if [[ "$facts" == *"FACT hook_pipe"* ]]; then
            record_fail "$f" "CWE-78:npm_lifecycle_hook_fetches_and_executes"; failed=true
        fi
        if [[ "$facts" == *"FACT hook_decode"* ]]; then
            record_fail "$f" "CWE-78:npm_lifecycle_hook_decodes_and_executes"; failed=true
        fi
        if [[ "$facts" == *"FACT dep_plain"* ]]; then
            record_fail "$f" "CWE-319:npm_dependency_over_plaintext"; failed=true
        fi
        # preinstall/install/postinstall run on every `npm install`. Ordinary in
        # some projects (native builds), so a WARN rather than a block.
        if [[ "$facts" == *"FACT install_hook"* ]]; then
            record_warn "$f" "npm:install_time_hook_present"
        fi
        if [[ "$facts" == *"FACT script_pipe"* ]]; then
            record_warn "$f" "npm:script_pipes_a_download_into_a_shell"
        elif [[ "$facts" == *"FACT script_fetch"* ]]; then
            record_warn "$f" "npm:script_fetches_from_the_network"
        fi
        if [[ "$facts" == *"FACT dep_remote"* ]]; then
            record_warn "$f" "npm:dependency_from_a_git_or_tarball_url_not_the_registry"
        fi
    fi

    # Credentials in the manifest itself. A dependency NAME ending in "token"
    # (csrf-token, jwt-token) sits in the same key position, so a semver range
    # as the value is excluded — "csrf-token": "^2.0.0" is not a secret.
    if grep_check_excl \
        '(password|secret|token|api_key|private_key)"?[[:space:]]*:[[:space:]]*"[^"${[:space:]]{4,}' \
        ':[[:space:]]*"[\^~><=v]*[0-9]+(\.[0-9xX*]+)*"' "$f"; then
        record_fail "$f" "CWE-798:hardcoded_credential_in_JSON"; failed=true
    fi

    $failed || record_pass "$f"
}

# ── pip requirements ─────────────────────────────────────────────────────────
# A requirements file decides where code comes from. 47 real files on this host,
# none carrying any of these, so the rules rest on what the options mean.
scan_requirements() {
    local f="$1"
    local failed=false

    # An index or a requirement over plaintext transport: whoever is on the path
    # chooses the package, and pip then runs its setup. git:// is unauthenticated.
    if grep_check_i \
        '^[[:space:]]*((--index-url|-i|--extra-index-url|--find-links|-f)[[:space:]=]+http://|(-e[[:space:]]+)?(git\+http://|git://)|http://[^[:space:]]+\.(tar\.gz|tgz|zip|whl|tar\.bz2))' \
        "$f"; then
        record_fail "$f" "CWE-319:pip_index_or_requirement_over_plaintext"; failed=true
    fi
    # user:password@host inside a URL.
    if grep_check '(https?|git\+https?|ssh)://[^/[:space:]:@]+:[^/[:space:]@]+@' "$f"; then
        record_fail "$f" "CWE-798:pip_credentials_embedded_in_url"; failed=true
    fi

    if grep_check_i '^[[:space:]]*--trusted-host' "$f"; then
        record_warn "$f" "pip:trusted_host_disables_tls_verification"
    fi
    # A second index is the dependency-confusion vector: pip takes the highest
    # version from ANY index, so a public package with the same name wins.
    if grep_check_i '^[[:space:]]*--extra-index-url' "$f"; then
        record_warn "$f" "pip:extra_index_url_enables_dependency_confusion"
    fi
    # A VCS requirement not pinned to a commit follows a moving branch.
    if grep_check_excl 'git\+(https|ssh)://' '@[0-9a-f]{7,40}([#[:space:]]|$)' "$f"; then
        record_warn "$f" "pip:vcs_requirement_not_pinned_to_a_commit"
    fi

    $failed || record_pass "$f"
}

# ── Gradle ───────────────────────────────────────────────────────────────────
# A .gradle script is not a declarative file with a few dangerous constructs in
# it: it is a program. Groovy is compiled to a Script subclass and Kotlin to a
# class, and both are evaluated in full at CONFIGURATION time — on `gradle
# tasks`, on `--dry-run`, and automatically when an IDE imports the project.
# There is no read-only mode and no declarative stage to retreat to, so a
# hostile top-level statement fires before any target is chosen. settings.gradle
# is evaluated first of all, before any project exists.
#
# Before this, *.gradle fell through to scan_unknown and was recorded PASS, and
# *.gradle.kts went to scan_kotlin, which has Kotlin SOURCE rules (Runtime.exec,
# MD5, a quoted credential) and none of the build constructs below.
#
# Rates are measured against ~6290 real build scripts, 101 gradle.properties and
# 26 gradle-wrapper.properties from gradle/gradle, spring-boot, kafka and
# elasticsearch. That corpus is cloned rather than found on this host (which has
# no .gradle file at all), so it is a measurement of what real projects write and
# not of what an AI-generated repository does.
#
# Calibration changed the design twice, and both are the CMake `URL` lesson:
#
#   `url = 'http://…'` matched 21 of 6249 and almost none were repositories —
#   licence urls, developer urls and project homepages in POM metadata. Bare
#   `http://` is 341 of 6249. So no rule keys on a URL scheme; allowInsecureProtocol
#   carries that job, because Gradle 7+ refuses an http:// repository unless it
#   is set, which makes the flag the reliable tell and the scheme noise.
#
#   `.execute()` is also a Gradle API call (ArtifactResolutionQuery.execute() was
#   2 of the 3 hits), so the process-spawn rule needs a string literal or a list
#   in front of it, as in `"curl …".execute()`.
scan_gradle() {
    local f="$1"
    local failed=false base
    base=$(basename "$f")

    case "$base" in
    gradle.properties)
        # Java .properties has no quoting, so signing.password=hunter2 has no
        # quote after the `=` and the universal credential rule cannot see it.
        # 7 of 101 real files, all `signing.password=<literal>` in Gradle's own
        # publishing documentation — true positives by form; 0 of 187 unrelated
        # .properties files on this host. A blank value, a ${…} reference and a
        # path are excluded.
        if grep_check_i '^[[:space:]]*[A-Za-z0-9_.-]*(password|passwd|secret|apikey|api[_.-]?key|auth[_.-]?token|access[_.-]?token)[[:space:]]*=[[:space:]]*[^[:space:]$/~.]' "$f"; then
            record_fail "$f" "CWE-798:gradle_credential_in_properties"
            failed=true
        fi
        # Turns off the checksum and signature verification of every resolved
        # artifact. 0 of 101.
        if grep_check_i '^[[:space:]]*(org\.gradle\.)?dependency[._-]verification[[:space:]]*=[[:space:]]*(off|lenient)' "$f"; then
            record_fail "$f" "CWE-494:gradle_dependency_verification_disabled"
            failed=true
        fi
        # A -javaagent loads arbitrary code into the build JVM before any script
        # runs. 0 of 101.
        if grep_check_i '^[[:space:]]*(org\.gradle\.jvmargs|systemProp\.)[^=]*=.*-(javaagent|agentpath|agentlib):' "$f"; then
            record_fail "$f" "CWE-829:gradle_daemon_java_agent"
            failed=true
        fi
        # Repoints TLS trust for all resolution traffic. Legitimate behind a
        # corporate proxy, so a WARN. 0 of 101.
        if grep_check_i '^[[:space:]]*systemProp\.javax\.net\.ssl\.(trustStore|trustStorePassword)[[:space:]]*=' "$f"; then
            record_warn "$f" "CWE-295:gradle_truststore_override"
        fi
        ;;

    gradle-wrapper.properties)
        # ./gradlew downloads this distribution and runs it as the build tool.
        # The `\:` is Java .properties escaping of the colon. 0 of 26.
        if grep_check_i '^[[:space:]]*distributionUrl[[:space:]]*=[[:space:]]*(http|ftp)\\?://' "$f"; then
            record_fail "$f" "CWE-494:gradle_wrapper_plaintext_distribution"
            failed=true
        fi
        if grep_check_i '^[[:space:]]*validateDistributionUrl[[:space:]]*=[[:space:]]*false' "$f"; then
            record_warn "$f" "CWE-494:gradle_wrapper_url_validation_disabled"
        fi
        # Deliberately no rule for a missing distributionSha256Sum: 20 of 26 real
        # wrapper files omit it.
        ;;

    *)
        # apply from: 'https://…' downloads a script and executes it at once.
        # One meaning, no innocent reading. Bare `apply from:` is 14 of 6249 and
        # every one is a local path. 0 of 6249.
        if grep_check_i 'apply[[:space:]]*\(?[[:space:]]*from[[:space:]]*[:=][[:space:]]*["'"'"']?(https?|ftp)://' "$f"; then
            record_fail "$f" "CWE-829:gradle_apply_from_remote_script"
            failed=true
        fi
        # Gradle 7+ refuses an http:// repository unless this is set, so the flag
        # is the reliable tell. Kotlin DSL spells it isAllowInsecureProtocol,
        # which the case-insensitive match covers. 2 of 6249, both Gradle's own
        # insecure-repository documentation snippet.
        if grep_check_i 'allowinsecureprotocol[[:space:]]*=[[:space:]]*true' "$f"; then
            record_fail "$f" "CWE-494:gradle_insecure_repository_protocol_enabled"
            failed=true
        fi
        # A process started from a literal or a list, a ProcessBuilder, or
        # Runtime.exec. The literal in front of .execute() is what separates it
        # from the Gradle API call of the same name. 2 of 6249, both genuine
        # spawns; the unanchored form would have been 2 of 3 wrong. ProcessBuilder
        # is matched without `new`, because Kotlin has no such keyword and a
        # pattern requiring it would miss every .gradle.kts script.
        if grep_check_i '(["'"'"'][^"'"'"']*["'"'"']|\])[[:space:]]*\.execute\(\)|(^|[^[:alnum:]_.])ProcessBuilder[[:space:]]*\(|Runtime\.getRuntime\(\)\.exec[[:space:]]*\(' "$f"; then
            record_fail "$f" "CWE-78:gradle_process_spawn_from_literal"
            failed=true
        fi

        # A fetch at configuration time: legitimate for a version lookup, but it
        # runs on every Gradle invocation. 5 of 6249: three are Gradle's own
        # "what not to do" snippet, two are real.
        if grep_check_i '(new[[:space:]]+URL|URL|URI)[[:space:]]*\([^)]*\)[[:space:]]*(\.toURL\(\))?[[:space:]]*\.(text|readText|getText|openStream|newInputStream)' "$f"; then
            record_warn "$f" "CWE-494:gradle_configuration_time_remote_fetch"
        fi
        # exec / commandLine / javaexec / providers.exec. The left guard keeps
        # commandLineIncludePatterns, a property that begins with commandLine,
        # from matching. 7 of 6249, all ordinary (git --version, dpkg-deb, ls).
        if grep_check_i '(^|[^[:alnum:]_.])(commandLine|javaexec|providers\.exec|exec)[[:space:]]*[({'"'"'"]' "$f"; then
            record_warn "$f" "CWE-78:gradle_build_step_runs_process"
        fi
        ;;
    esac

    $failed || record_pass "$f"
}

# ── Windows batch: .bat and .cmd ─────────────────────────────────────────────
# 116 real batch files on this host (64 distinct) were all recorded PASS: neither
# extension had a handler, so a script could download and run anything.
#
# Three properties of the language shape the scanner, and all three occur in the
# real files, so none is hypothetical:
#
#   CRLF line endings — 104 of 116. A `$` anchor or a character class that does
#   not expect the CR quietly stops matching, so the view below strips it first.
#
#   Comment lines (REM, @REM, ::) — 56 of 116. The MIT licence header in
#   virtualenv's activate.bat is made of them, and a rule keyed on the bare word
#   `copy` fails 27 of 116 files on the sentence "a copy of this software" alone.
#   A commented-out payload does not execute, so comment lines are dropped.
#
#   Caret line-continuation — 6 of 116. A trailing ^ continues the command on the
#   next line, so `certutil ^` / `-urlcache …` is one command; a line-based rule
#   would never see the two halves together. Continuations are joined first. The
#   same character, inside a word, is the oldest obfuscation there is
#   (c^e^r^t^u^t^i^l), which is its own rule.
#
# Batch is case-insensitive throughout (CERTUTIL -URLCACHE), so all matching is -i,
# and the extension is compared in lower case by classify_file.
#
# CALIBRATION IS WEAKER THAN IT LOOKS. The corpus is npm and corepack shims,
# virtualenv activate.bat, Sphinx make.bat and Go and Maven wrappers: it carries no
# Windows-native automation at all. "0 of 116" therefore shows the rules do not
# misfire on benign scripts; it says almost nothing about recall, which is covered
# by fixtures only. Where a construct is ordinary in real Windows administration
# (certutil -decode of a certificate, `net user /add` in provisioning, a
# scheduled task, `powershell` inside `for /f` to read the date) it is a WARN, and
# only a composition with no innocent reading is a FAIL.
#
# Not handled: batch can assemble a command from variable substrings at run time
# (%a:~0,1%%b:~3,1%…), which no pattern can follow. Two or more substring
# extractions on one line are reported as a WARN instead. `.btm` (Take Command)
# and the 4DOS family are not routed.
_bat_view() {
    local f="$1" out="$2"
    tr -d '\r' < "$f" \
        | sed -e '/^[[:space:]]*@\{0,1\}rem\([[:space:]]\|$\)/Id' -e '/^[[:space:]]*@\{0,1\}::/d' \
        | sed -e ':a' -e '/\^$/N' -e 's/\^\n[[:space:]]*//' -e 'ta' > "$out"
}

scan_bat() {
    local f="$1"
    local failed=false v="$f" tmp=""

    tmp=$(mktemp "${TMPDIR:-/tmp}/aitransit_bat_XXXXXX" 2>/dev/null) || tmp=""
    if [[ -n "$tmp" ]]; then
        # If the view cannot be built the raw file is scanned instead: more noise,
        # never less coverage.
        if _bat_view "$f" "$tmp" 2>/dev/null; then v="$tmp"; fi
    fi

    local FETCH='(curl|wget|bitsadmin(\.exe)?[^|&]*[-/](transfer|addfile)|certutil(\.exe)?[^|&]*[-/](urlcache|verifyctl)|powershell.*(downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient|[[:space:]](iwr|irm)[[:space:]]))'

    # CWE-78 — a native downloader. certutil -urlcache and bitsadmin /transfer are
    # the classic living-off-the-land fetches; neither has a use in a build script.
    if grep_check_i '(certutil(\.exe)?[^|&]*[-/](urlcache|verifyctl)|bitsadmin(\.exe)?[^|&]*[-/](transfer|addfile))' "$v"; then
        record_fail "$f" "CWE-78:bat_download_cradle_certutil_or_bitsadmin"
        failed=true
    fi
    # CWE-78 — a PowerShell download cradle launched from batch.
    if grep_check_i 'powershell(\.exe)?.*(downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient|[[:space:]](iwr|irm)[[:space:]])' "$v"; then
        record_fail "$f" "CWE-78:bat_powershell_download_cradle"
        failed=true
    fi
    # CWE-78 — a base64 command line. -EncodedCommand has legal abbreviations down
    # to -e; 24+ base64 characters after it separates it from `-ExecutionPolicy`.
    if grep_check_i 'powershell(\.exe)?.*[-/]e[a-z]*[[:space:]]+["'"'"']?[A-Za-z0-9+/]{24,}' "$v"; then
        record_fail "$f" "CWE-78:bat_powershell_encoded_command"
        failed=true
    fi
    # CWE-78 — certutil -decode into something executable. Decoding a certificate
    # is ordinary, so it is the output type that decides.
    if grep_check_i 'certutil(\.exe)?[^|&]*[-/]decode[^|&]*\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|msi|scr|hta)' "$v"; then
        record_fail "$f" "CWE-78:bat_certutil_decodes_to_an_executable"
        failed=true
    fi
    # CWE-78 — fetch, then run, on one line. `call :label` is a subroutine call
    # and appears in 21 of 116 real files, so a call must name something that is
    # not a label.
    if grep_check_i '(curl|wget|bitsadmin|certutil|powershell).*(https?|ftp)://.*(&&|&|\|)[[:space:]]*(start[[:space:]]|call[[:space:]]+[^:[:space:]]|cmd|wscript|cscript|mshta|"?%[A-Za-z_]+%)' "$v"; then
        record_fail "$f" "CWE-78:bat_download_then_execute"
        failed=true
    fi
    # CWE-78 — obfuscation: carets inside a word. A caret as a
    # line continuation or as a redirection escape (2^>nul) is ordinary and is
    # not matched; three letters separated by two carets is not.
    if grep_check_i '[a-z]\^[a-z]\^[a-z]' "$v"; then
        record_fail "$f" "CWE-78:bat_caret_obfuscated_command_name"
        failed=true
    fi

    # CWE-798 — a literal credential. The name must be one of these words, so a
    # variable that merely contains TOKEN is not read as a secret; the value must
    # not start with % or !, so `set "GIT_TOKEN=%GITHUB_TOKEN%"` — a reference,
    # the correct form — is not either; and `set /p` is a prompt, not a literal.
    if grep_check_i 'set[[:space:]]+(/a[[:space:]]+)?"?[A-Za-z_]*(passwd|password|secret|api_?key|auth_?token|access_?token|credential)[A-Za-z_]*=[^%!"[:space:]][^"[:space:]]{3,}' "$v"; then
        record_fail "$f" "CWE-798:bat_hardcoded_credential"
        failed=true
    fi

    # CWE-912 — persistence: a Run / RunOnce / Winlogon / IFEO key, or a file
    # dropped into the Startup folder.
    if grep_check_i 'reg(\.exe)?[[:space:]]+add[^|&]*(currentversion[\\]+run(once)?|winlogon|image file execution options)' "$v"; then
        record_fail "$f" "CWE-912:bat_persistence_run_key"
        failed=true
    fi
    if grep_check_i '(copy|xcopy|move|echo|type)[^|&]*start menu[\\]+programs[\\]+startup' "$v"; then
        record_fail "$f" "CWE-912:bat_persistence_startup_folder"
        failed=true
    fi

    # CWE-693 — turning off the defences: UAC, Defender, the firewall.
    if grep_check_i 'reg(\.exe)?[[:space:]]+add[^|&]*(enablelua|consentpromptbehavioradmin|disableantispyware|disablerealtimemonitoring|disableantivirus)' "$v" \
       || grep_check_i '(add|set)-mppreference.*(exclusionpath|exclusionextension|disablerealtimemonitoring)' "$v" \
       || grep_check_i 'netsh[^|&]*advfirewall[^|&]*state[[:space:]]+off' "$v" \
       || grep_check_i 'sc(\.exe)?[[:space:]]+(stop|config)[[:space:]]+(windefend|mpssvc)' "$v"; then
        record_fail "$f" "CWE-693:bat_security_control_disabled"
        failed=true
    fi

    # Destructive: a delete aimed at a drive root or the profile itself, or a
    # format. The target must be EXACTLY the root, so `del /q /s %BUILDDIR%\*`
    # (Sphinx's clean) and `rd /s /q build` — both in the real corpus — are not
    # matched. A bare `\bdel\b|\brd\b` is 13 of 116.
    if grep_check_i '(^|[^[:alnum:]_])(del|erase|rd|rmdir)[[:space:]]+(/[a-z][[:space:]]*)*"?(%systemdrive%|%homedrive%|%userprofile%|%appdata%|[a-z]:)([\\](\*(\.\*)?)?)?"?[[:space:]]*$' "$v" \
       || grep_check_i '(^|[^[:alnum:]_])format(\.com)?[[:space:]]+[a-z]:' "$v"; then
        record_fail "$f" "bat:destructive_delete_of_a_drive_root_or_profile"
        failed=true
    fi

    # CWE-494 — certificate checking switched off for a download.
    if grep_check_i '(curl|wget).*([[:space:]]--insecure|[[:space:]]-k([[:space:]]|$)|--no-check-certificate)|servercertificatevalidationcallback' "$v"; then
        record_fail "$f" "CWE-494:bat_download_without_certificate_verification"
        failed=true
    fi

    # CWE-250 — a new member of the local Administrators group.
    if grep_check_i 'net[[:space:]]+localgroup[^|&]*(administrators|administrateurs)[^|&]*/add' "$v"; then
        record_fail "$f" "CWE-250:bat_local_admin_account_added"
        failed=true
    fi

    # ── Ordinary in real Windows administration: reported, not blocked ───
    if grep_check_i 'net[[:space:]]+user[^|&]*/add' "$v"; then
        record_warn "$f" "bat:creates_a_local_account"
    fi
    if grep_check_i 'certutil(\.exe)?[^|&]*[-/]decode' "$v"; then
        record_warn "$f" "bat:certutil_decodes_a_file"
    fi
    if grep_check_i 'schtasks(\.exe)?[[:space:]]+/create' "$v"; then
        record_warn "$f" "bat:creates_a_scheduled_task"
    fi
    # `for /f … in ('curl …')` reads a download into a variable. Not an execution
    # on its own, and `for /f` with `powershell` inside is the usual way to get a
    # timestamp, so only a fetcher counts.
    if grep_check_i "for[[:space:]]+/f[^(]*\\([[:space:]]*'[^']*(curl|wget|certutil[^']*urlcache|bitsadmin)" "$v"; then
        record_warn "$f" "bat:command_output_comes_from_a_download"
    fi
    if grep_check_i "$FETCH" "$v" && grep_check_i '(^|[&|(][[:space:]]*)(start|msiexec)[[:space:]]|call[[:space:]]+[^:[:space:]]' "$v"; then
        record_warn "$f" "bat:downloads_then_runs_a_program"
    fi
    if grep_check_i '(curl|wget|bitsadmin|certutil|powershell).*http://' "$v"; then
        record_warn "$f" "bat:plaintext_http_download_no_transport_integrity"
    fi
    if grep_check_i 'powershell.*[-/]e[a-z]*[[:space:]]+(bypass|unrestricted)' "$v"; then
        record_warn "$f" "bat:powershell_execution_policy_bypass"
    fi
    if grep_check_i 'powershell.*[-/]w(indowstyle)?[[:space:]]+h(idden)?([[:space:]]|$)' "$v"; then
        record_warn "$f" "bat:powershell_hidden_window"
    fi
    if grep_check_i '(^|[^[:alnum:]_])(mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?[[:space:]]' "$v"; then
        record_warn "$f" "bat:script_host_or_proxy_execution"
    fi
    if grep_check_i 'wmic.*process.*call.*create' "$v"; then
        record_warn "$f" "bat:wmic_process_create"
    fi
    if grep_check_i '(start|call|cmd[[:space:]]*/c|xcopy|copy)[[:space:]]+[^[:space:]]*\\\\[A-Za-z0-9._-]+\\' "$v"; then
        record_warn "$f" "bat:runs_or_copies_from_a_remote_unc_path"
    fi
    # Substring extractions ADJACENT to each other build a word one character at a
    # time, which is how a command name is assembled so that no pattern can see
    # it: %a:~2,1%%a:~3,1%%a:~4,1%. The first version fired on any two on a line,
    # and Maven's own mvn.cmd has two apart — `if "_%EXEC_DIR:~-1%"=="_\" set
    # "EXEC_DIR=%EXEC_DIR:~0,-1%"` — the standard trailing-backslash trim.
    if grep_check_i '%[a-z0-9_]+:~[-0-9]+(,[-0-9]+)?%%[a-z0-9_]+:~[-0-9]+(,[-0-9]+)?%' "$v"; then
        record_warn "$f" "bat:command_assembled_from_variable_substrings"
    fi

    [[ -n "$tmp" ]] && rm -f "$tmp"
    $failed || record_pass "$f"
}

# ── setup.py and conanfile.py ────────────────────────────────────────────────
# setup.py runs on a source `pip install`, and a Conan recipe runs on `conan
# install` / `conan create`: both are install-time code, so everything in them
# fires before the package is imported by anything. That gives them a risk model
# of their own, and the generic Python rules fit it badly. os.system and
# subprocess are ordinary build tools here; what is not ordinary is fetching and
# then executing.
#
# The generic rules failed 4 of 36 real setup.py files on this host, and 3 of
# the 4 were idioms rather than attacks: `exec(fp.read(), version)` — loading a
# LOCAL version file into a namespace, in two files — and a literal
# `os.system('pip install .')`, which the "command injection" rule flagged even
# though a literal command cannot be injected into.
#
# This REPLACES scan_python for these two filenames, and that is a trade-off, not
# a free win: bandit and the generic eval/exec/os.system FAILs no longer run on
# them. The attacks those rules would have caught here are covered by the
# explicit rules below (decode-and-execute, execute-a-network-response, pipe to a
# shell, reverse shell, persistence). All install-time FAIL rules measured 0 of
# 36 real setup.py.
scan_setup_py() {
    local f="$1"
    local failed=false

    # CWE-78 — a download piped into a shell.
    if grep_check '(curl|wget)[^"'"'"']*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh' "$f"; then
        record_fail "$f" "CWE-78:setup_py_fetches_and_executes"
        failed=true
    fi
    # CWE-95 — exec/eval applied to something fetched, on one line.
    if grep_check '(exec|eval)[[:space:]]*\([^)]*(urlopen|urlretrieve|requests\.(get|post)|urllib|https?://)' "$f"; then
        record_fail "$f" "CWE-95:setup_py_executes_a_network_response"
        failed=true
    fi
    # CWE-95 — a decoded blob that is then executed. The two usually sit on
    # different lines (payload = b64decode(...) ; exec(payload)), so this is a
    # whole-file test: decoding AND executing in one setup script has no
    # ordinary reading.
    if grep_check '(exec|eval)[[:space:]]*\([[:space:]]*(base64\.[a-z0-9_]*decode|codecs\.decode|zlib\.decompress|bytes\.fromhex|binascii\.[a-z]*)' "$f" \
       || { grep_check '(b64decode|a85decode|b32decode|bytes\.fromhex|zlib\.decompress|binascii\.unhexlify)' "$f" \
            && grep_check '(^|[^[:alnum:]_.])(exec|eval)[[:space:]]*\(' "$f"; }; then
        record_fail "$f" "CWE-95:setup_py_decodes_and_executes"
        failed=true
    fi
    # CWE-78 — a socket handed to a shell, or a pty.
    if grep_check '(pty\.spawn|/dev/tcp/|nc[[:space:]]+-[a-z]*e[[:space:]])' "$f" \
       || { grep_check 'socket\.socket[[:space:]]*\(' "$f" \
            && grep_check '(/bin/(ba)?sh|cmd\.exe|dup2[[:space:]]*\()' "$f"; }; then
        record_fail "$f" "CWE-78:setup_py_reverse_shell"
        failed=true
    fi
    # CWE-912 — an installer that writes into somewhere that runs later.
    if grep_check '(authorized_keys|crontab|/etc/cron\.|\.ssh/id_|/etc/systemd/system)' "$f"; then
        record_fail "$f" "CWE-912:setup_py_persistence"
        failed=true
    fi

    # ── Reported, not blocked ────────────────────────────────────────────
    # Overriding install/develop/egg_info means the package runs its own code
    # during installation. 0 of 36 real files (build_ext / build_py are common
    # and are not reported).
    if grep_check 'cmdclass[[:space:]]*=[^#]*['"'"'"](install|develop|egg_info)['"'"'"]' "$f"; then
        record_warn "$f" "setup:overrides_install_command_runs_package_code_at_install_time"
    fi
    if grep_check '(urlretrieve|urlopen|requests\.(get|post)|[^[:alnum:]_](wget|curl)[[:space:]])' "$f"; then
        record_warn "$f" "setup:downloads_something_at_install_time"
    fi
    if grep_check '(os\.system|subprocess\.(call|run|check_call|check_output|Popen))' "$f"; then
        record_warn "$f" "setup:runs_a_program_at_install_time"
    fi

    $failed || record_pass "$f"
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
        '#!'*pwsh*|'#!'*powershell*)
                      scan_powershell "$f"; return ;;
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
# One rule set, `_ps_rules`, shared by every PowerShell file type:
#
#   text         .ps1 script · .psm1 module · .psd1 manifest · .pssc session
#                configuration · .psrc role capability · and an extensionless file
#                whose first line is a pwsh / powershell shebang
#   XML-based    .ps1xml type and format data · .psc1 console file · .cdxml CIM
#                cmdlet definition — XML that carries script blocks, so they get
#                the same rules plus the external-entity check
#
# The legacy Monad extensions (.msh, .msh1, .msh2, .mshxml …) are not routed:
# PowerShell has not associated them since 1.0 shipped. None of .psm1, .psd1,
# .ps1xml, .psc1, .pssc, .psrc or .cdxml exists on the reference host, so those
# routes are tested from fixtures and reasoned from the format, not calibrated.
#
# The previous scanner had three rules and was wrong in both directions. On the 69
# real .ps1 files on this host (32 distinct) it FAILed 8, and every one was a
# false positive: npm.ps1 and npx.ps1 ship with every Node install and call
# Invoke-Expression on a command they assemble; pnpm's completion script does the
# same; and Playwright's five browser installers download an MSI over https and
# run msiexec on it. Meanwhile `iex $c`, `IEX (iwr …)` and `powershell -enc …` all
# PASSED, because the rules were case-sensitive and `iex` was only matched before
# a parenthesis.
#
# The shape that came out of that corpus: a construct that is ordinary on its own
# (Invoke-Expression, Start-Process, a download) is a WARN, and it becomes a FAIL
# only in a composition that has no innocent reading — fetch-then-execute, decode-
# then-execute, an AMSI bypass. Several of those are whole-file tests, because the
# two halves sit on different lines and PowerShell happily spreads a pipeline
# across them.
#
# Not handled: comments. A payload inside a # or <# #> comment is still matched,
# which errs towards reporting; stripping them would need a PowerShell lexer to
# avoid mistaking a # inside a string for a comment.
PS_FAILED=false

_ps_rules() {
    local f="$1"

    # Primitives. PowerShell is case-insensitive throughout — IEX, iex and
    # Invoke-Expression are one command — so every match below is -i.
    #
    # `iex` is matched before a space, a parenthesis or end of line, because the
    # common forms are `iex $c`, `… | iex` and `iex (iwr …)`; the first scanner
    # only matched `iex(`. The backtick variants are the obfuscated spellings
    # i`ex, ie`x and i`e`x, which PowerShell reads as plain iex.
    local IEXA='(invoke-expression|(^|[^[:alnum:]_.$-])(iex|i`e`?x|ie`x)([[:space:]]|\(|$))'
    local FETCH='(downloadstring|downloaddata|downloadfile|net\.webclient|invoke-webrequest|invoke-restmethod|start-bitstransfer|(^|[^[:alnum:]_.$-])(iwr|irm)([[:space:]]|\())'
    local RUN='(start-process|invoke-item|msiexec|regsvr32|rundll32|(^|[;|{[:space:]])&[[:space:]]*["'"'"'$(])'

    # CWE-78 — fetch, then execute. Whole-file, because `irm $u |` and `iex` can
    # be on different lines. This is also the canonical installer one-liner
    # (`irm https://… | iex`), which is exactly why it is a FAIL here: it runs
    # whatever the server sends with no integrity check. A shell pipe inside a
    # pwsh script is the same thing. 0 of 32 distinct real scripts.
    if { grep_check_i "$IEXA" "$f" && grep_check_i "$FETCH" "$f"; } \
       || grep_check_i '(curl|wget)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh([[:space:]]|$)' "$f"; then
        record_fail "$f" "CWE-78:PowerShell_download_and_execute"
        PS_FAILED=true
    fi

    # CWE-78 — a base64 command line. -EncodedCommand has legal abbreviations
    # down to -e, and -enc is the form attackers actually write. 30+ base64
    # characters after it separates it from `-ExecutionPolicy Bypass`.
    if grep_check_i '-encodedcommand' "$f" \
       || grep_check_i '(powershell|pwsh)(\.exe)?[^|;]*[[:space:]]-e[a-z]*[[:space:]]+["'"'"']?[A-Za-z0-9+/]{30,}' "$f"; then
        record_fail "$f" "CWE-78:PowerShell_EncodedCommand_obfuscation"
        PS_FAILED=true
    fi

    # CWE-95 — decode a blob, then run it. Decoding alone is ordinary (a
    # certificate, a file), so this needs an execution primitive in the same file.
    if grep_check_i 'frombase64string' "$f" \
       && { grep_check_i "$IEXA" "$f" \
            || grep_check_i '(scriptblock\]::create|assembly\]::load|virtualalloc|createthread)' "$f"; }; then
        record_fail "$f" "CWE-95:PowerShell_decodes_and_executes"
        PS_FAILED=true
    fi

    # CWE-95 — a backtick inside the command name. No innocent reading.
    if grep_check_i '(^|[^[:alnum:]_.$-])(i`e`?x|ie`x)([[:space:]]|\(|$)' "$f"; then
        record_fail "$f" "CWE-95:PowerShell_obfuscated_Invoke_Expression"
        PS_FAILED=true
    fi

    # CWE-693 — defeating the Antimalware Scan Interface, or Defender itself.
    if grep_check_i '(amsiinitfailed|amsiutils|amsiscanbuffer|amsicontext)' "$f"; then
        record_fail "$f" "CWE-693:PowerShell_AMSI_bypass"
        PS_FAILED=true
    fi
    if grep_check_i 'set-mppreference[^|;]*-disable(realtimemonitoring|ioavprotection|behaviormonitoring|scriptscanning|intrusionpreventionsystem|blockatfirstseen)[[:space:]:=]*(\$true|1|true)' "$f"; then
        record_fail "$f" "CWE-693:PowerShell_disables_Defender"
        PS_FAILED=true
    fi

    # CWE-912 — persistence: a Run key, a WMI event subscription, or a file in
    # the Startup folder.
    if grep_check_i '(new-itemproperty|set-itemproperty|reg(\.exe)?[[:space:]]+add)[^|;]*currentversion[\\]+run' "$f" \
       || grep_check_i '(__eventfilter|commandlineeventconsumer|activescripteventconsumer)' "$f" \
       || grep_check_i '(copy-item|move-item|set-content|out-file|add-content|new-item)[^|;]*[\\]start menu[\\]programs[\\]startup' "$f"; then
        record_fail "$f" "CWE-912:PowerShell_persistence"
        PS_FAILED=true
    fi

    # CWE-78 — a socket whose stream is fed to a command interpreter. A TcpClient
    # on its own is a port check and is not reported.
    if { grep_check_i 'tcpclient' "$f" && grep_check_i 'getstream' "$f" \
         && { grep_check_i "$IEXA" "$f" || grep_check_i '(cmd\.exe|powershell)' "$f"; }; } \
       || grep_check_i '(nc(\.exe)?[[:space:]]+-[a-z]*e[[:space:]]|/dev/tcp/)' "$f"; then
        record_fail "$f" "CWE-78:PowerShell_reverse_shell"
        PS_FAILED=true
    fi

    # CWE-94 — allocate executable memory and start a thread in it.
    if grep_check_i 'virtualalloc' "$f" \
       && grep_check_i '(createthread|createremotethread|writeprocessmemory|marshal\]::copy)' "$f"; then
        record_fail "$f" "CWE-94:PowerShell_in_memory_shellcode_loader"
        PS_FAILED=true
    fi

    # CWE-506 — offensive tooling by name.
    if grep_check_i '(invoke-mimikatz|invoke-shellcode|invoke-reflectivepeinjection|invoke-dllinjection|invoke-tokenmanipulation|invoke-kerberoast|invoke-powerdump|get-gpppassword|invoke-ninjacopy|sekurlsa::)' "$f"; then
        record_fail "$f" "CWE-506:PowerShell_known_offensive_tool"
        PS_FAILED=true
    fi

    # CWE-798 — a literal credential. Case-insensitive now ($Password is $password
    # to PowerShell); the variable name must be exactly one of these, so that
    # `$tokenEndpoint = 'https://…'` is not read as a token.
    if grep_check_i '\$(password|passwd|secret|apikey|api_key|token|accesstoken|clientsecret|client_secret|authtoken)[[:space:]]*=[[:space:]]*["'"'"'][^"'"'"'$]{4,}["'"'"']' "$f" \
       || grep_check_i 'convertto-securestring[[:space:]]+["'"'"'][^"'"'"'$]{4,}["'"'"'][^|;]*-asplaintext' "$f"; then
        record_fail "$f" "CWE-798:hardcoded_credential"
        PS_FAILED=true
    fi

    # CWE-319 — a download over plaintext http://. If something is then run the
    # contents were chosen by whoever is on the path, so it blocks; alone, it warns.
    if grep_check_i '(downloadfile|downloadstring|downloaddata|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer)[^;|]*["'"'"']http://' "$f"; then
        if grep_check_i "$RUN" "$f" || grep_check_i "$IEXA" "$f"; then
            record_fail "$f" "CWE-319:PowerShell_plaintext_download_then_run"
            PS_FAILED=true
        else
            record_warn "$f" "powershell:plaintext_http_download"
        fi
    fi

    # ── Ordinary on their own: reported, not blocked ─────────────────────
    # Invoke-Expression appeared in 3 distinct real scripts (npm, npx, pnpm's
    # completion) and was benign every time; PSScriptAnalyzer ranks it a warning.
    # The message keeps the old rule's token so the original test still matches.
    if grep_check_i "$IEXA" "$f"; then
        record_warn "$f" "CWE-78:PowerShell_command_execution_Invoke_Expression"
    fi
    # Start-Process: 5 real hits, all Playwright's `Start-Process msiexec.exe`.
    if grep_check_i '(start-process|cmd(\.exe)?[[:space:]]+/c)' "$f"; then
        record_warn "$f" "CWE-78:PowerShell_command_execution_Start_Process"
    fi
    # Fetch and run in one script without an iex: the installer idiom. 5 real
    # hits, all Playwright, all https.
    if grep_check_i "$FETCH" "$f" && grep_check_i "$RUN" "$f"; then
        record_warn "$f" "powershell:downloads_then_runs_a_program"
    fi
    if grep_check_i '(set-executionpolicy|-executionpolicy|[[:space:]]-ep)[[:space:]]+(bypass|unrestricted)' "$f"; then
        record_warn "$f" "powershell:execution_policy_bypass"
    fi
    if grep_check_i '(-windowstyle|[[:space:]]-w)[[:space:]]+h(idden)?([[:space:]]|$)' "$f"; then
        record_warn "$f" "powershell:hidden_window"
    fi
    if grep_check_i 'add-mppreference[^|;]*-exclusion' "$f"; then
        record_warn "$f" "powershell:adds_a_Defender_exclusion"
    fi
    if grep_check_i '(schtasks(\.exe)?[[:space:]]+/create|register-scheduledtask|new-scheduledtask)' "$f"; then
        record_warn "$f" "powershell:creates_a_scheduled_task"
    fi
    if grep_check_i '(servercertificatevalidationcallback[^;]*(\$true|\{[[:space:]]*\$true)|-skipcertificatecheck|trustallcertspolicy)' "$f"; then
        record_warn "$f" "CWE-295:powershell_certificate_validation_disabled"
    fi
    if grep_check_i '(net(\.exe)?[[:space:]]+(user|localgroup)[^|;]*/add|new-localuser|add-localgroupmember)' "$f"; then
        record_warn "$f" "powershell:creates_or_elevates_a_local_account"
    fi
    # `& ('ie' + 'x')`, `& ("{0}{1}" -f 'ie','x')`: a command name assembled from
    # pieces so no pattern can see it.
    if grep_check_i '&[[:space:]]*\([[:space:]]*["'"'"'][^"'"'"')]{1,12}["'"'"'][[:space:]]*(\+|-f)' "$f"; then
        record_warn "$f" "powershell:command_name_built_from_strings"
    fi
    # Data files (.psd1 .pssc .psrc). Ordinary in a module author's hands, but
    # these run code at import or define what a remote session may do.
    if grep_check_i 'scriptstoprocess[[:space:]]*=[[:space:]]*@?\(?[[:space:]]*["'"'"']' "$f"; then
        record_warn "$f" "powershell:manifest_runs_scripts_at_import"
    fi
    if grep_check_i 'visible(cmdlets|functions|externalcommands|providers|aliases)[[:space:]]*=[[:space:]]*@?\(?[[:space:]]*["'"'"']\*' "$f"; then
        record_warn "$f" "powershell:role_capability_exposes_everything"
    fi
}

scan_powershell() {
    local f="$1"
    PS_FAILED=false
    _ps_rules "$f"
    $PS_FAILED || record_pass "$f"
}

# .ps1xml, .psc1, .cdxml: XML first, PowerShell second. The script blocks inside
# get the PowerShell rules; the document gets the external-entity check that
# scan_xml applies, matched with newlines folded for the same reason.
scan_powershell_xml() {
    local f="$1"
    PS_FAILED=false
    _ps_rules "$f"
    if grep_flat '<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+["'"'"'](file:|expect:|php:|gopher:|jar:|netdoc:|ftp:|https?:|/|\\\\)' "$f"; then
        record_fail "$f" "CWE-611:xxe_external_entity_references_a_resource"
        PS_FAILED=true
    fi
    $PS_FAILED || record_pass "$f"
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
    # Matched in lower case. The dispatch was case-sensitive, so UPPER.PS1 and
    # UPPER.PY fell through to scan_unknown and PASSED while lower.ps1 and
    # lower.py FAILed: renaming a file bypassed its scanner. Windows users write
    # .PS1 and .BAT as a matter of course.
    ext="${ext,,}"

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
        # Manifests are routed by basename. package.json and composer.json end in
        # .json and were only credential-checked; requirements*.txt ended in .txt
        # and went to the documentation scanner.
        package.json|composer.json)           scan_package_json "$f"; return ;;
        requirements*.txt|constraints*.txt)   scan_requirements "$f"; return ;;
        # Gradle build scripts are programs. *.gradle.kts must be matched here,
        # by name, because its extension is .kts and the extension branch would
        # send it to scan_kotlin, which knows Kotlin source and not Gradle.
        gradle.properties|gradle-wrapper.properties|*.gradle|*.gradle.kts)
                                              scan_gradle   "$f"; return ;;
        # install-time Python: setup.py on `pip install`, a Conan recipe on
        # `conan install`. Matched by name because the extension is just .py and
        # would route to scan_python, whose rules fit these files badly.
        setup.py|conanfile.py)                scan_setup_py "$f"; return ;;
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
        # Text: script, module, manifest, session configuration, role capability.
        .ps1|.psm1|.psd1|.pssc|.psrc)    scan_powershell      "$f" ;;
        # XML-based: type/format data, console file, CIM cmdlet definition.
        .ps1xml|.psc1|.cdxml)            scan_powershell_xml  "$f" ;;
        # Windows batch. The extension is already lower-cased, so .BAT and .CMD match.
        .bat|.cmd)                       scan_bat             "$f" ;;
        .rs)                              scan_rust        "$f" ;;
        .kt|.kts)                         scan_kotlin      "$f" ;;
        .cs)                              scan_csharp      "$f" ;;
        .xml|.pom)                        scan_xml         "$f" ;;
        .yml|.yaml)                       scan_yaml        "$f" ;;
        .tf|.tfvars|.hcl)               scan_terraform   "$f" ;;
        .so|.dll|.dylib|.exe|.elf|.bin)  scan_binary     "$f" ;;
        .zip|.tar|.gz|.tgz|.bz2|.xz)    scan_archive    "$f" ;;
        # A jar is a ZIP of compiled code. The extension is already lower-cased.
        .jar|.war|.ear|.aar)             scan_jar         "$f" ;;
        .pdf)                             scan_pdf         "$f" ;;
        .mk|.mak|.make)                 scan_makefile    "$f" ;;
        .html|.htm|.xhtml)              scan_html        "$f" ;;
        .cmake)                           scan_cmake       "$f" ;;
        .sql)                             scan_sql         "$f" ;;
        .json)
            if grep_check \
                '(password|secret|token|api_key|private_key)\s*"?\s*:\s*"[^"${[:space:]]{4,}' "$f"; then
                record_fail "$f" "CWE-798:hardcoded_credential_in_JSON"
            else
                record_pass "$f"
            fi
            ;;
        .md|.txt|.rst)
            if grep_check \
                '(password|secret|api_key)\s*[:=]\s*[^${[:space:]][^[:space:]]{4,}' "$f"; then
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
                     "HTML-Active-Content", "XML-Build-Hardening", "Package-Manifest-Integrity", "Gradle-Build-Hardening", "Install-Time-Python", "Known-Credential-Formats", "PowerShell-Hardening", "Windows-Batch-Hardening", "Java-Archive-Hardening"],
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

# HTML-escape $1 into ESC (a variable, not command substitution: this runs once
# per file, and a subshell per file adds up on a large repository).
#
# Everything the report prints about a file comes from the repository being
# scanned. A file can be NAMED <img src=x onerror=…>, and a finding message can
# carry text from inside a file or an archive entry; written as markup, either
# runs in the browser of whoever opens the report to review the scan. patsub_
# replacement is switched off because bash 5.2 otherwise reads an & in the
# replacement as "the matched text", which would make &amp; expand to itself.
_html_esc() {
    shopt -u patsub_replacement 2>/dev/null || true
    ESC="$1"
    ESC="${ESC//&/&amp;}"
    ESC="${ESC//</&lt;}"
    ESC="${ESC//>/&gt;}"
    ESC="${ESC//\"/&quot;}"
    ESC="${ESC//\'/&#39;}"
}

generate_report_html() {
    local color ESC
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
        _html_esc "$SCAN_DIR"
        echo "<p>Directory: <code>${ESC}</code> | Date: ${TIMESTAMP}</p>"
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
            _html_esc "$path"; local path_html="$ESC"
            _html_esc "$msg";  local msg_html="$ESC"
            echo "<tr><td><code>${path_html}</code></td><td class='${cls}'>${status}</td><td>${msg_html}</td></tr>"
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
