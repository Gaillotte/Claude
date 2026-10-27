#!/usr/bin/env bash
# AI Transit Pipeline — verify the installation works with no network
#
# Run this as the LAST step of an offline-capable install, ideally with the
# network physically disconnected. It checks each tool individually rather than
# only running the pipeline, because the pipeline degrades silently: a tool that
# cannot work offline produces an empty result, and an empty result looks
# exactly like a clean one.
#
#   ./verify_offline_install.sh                 # verify
#   ./verify_offline_install.sh --simulate      # also block network, to prove
#                                               # nothing silently reaches out
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-/opt/ai-transit}"
OFFLINE_CACHE="${OFFLINE_CACHE:-${WORK_DIR}/offline-cache}"
SEMGREP_RULES_DIR="${SEMGREP_RULES_DIR:-${OFFLINE_CACHE}/semgrep-rules}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-${OFFLINE_CACHE}/trivy-db}"
CLAMAV_DB_DIR="${CLAMAV_DB_DIR:-${OFFLINE_CACHE}/clamav}"

SIMULATE=false
[[ "${1:-}" == "--simulate" ]] && SIMULATE=true

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
BLUE='\033[34m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

PASS_N=0; FAIL_N=0; SKIP_N=0
declare -a FAILED=()

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

pass() { (( PASS_N++ )); echo -e "  ${GREEN}✔${RESET} $1"; }
fail() { (( FAIL_N++ )); FAILED+=("$1"); echo -e "  ${RED}✘${RESET} $1"; [[ $# -gt 1 ]] && echo -e "    ${DIM}$2${RESET}"; }
skip() { (( SKIP_N++ )); echo -e "  ${YELLOW}—${RESET} $1 ${DIM}(${2:-skipped})${RESET}"; }
hdr()  { echo; echo -e "${BOLD}${BLUE}── $1${RESET}"; }

has_cmd() { command -v "$1" &>/dev/null; }

# Run a command with a hard timeout. Offline, a tool that tries to reach the
# network usually hangs rather than failing, so a timeout is itself a result.
run_t() { timeout "${1}s" bash -c "$2" >/dev/null 2>&1; }

echo
echo -e "${BOLD}═══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Offline installation verification${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════${RESET}"
echo -e "  cache : ${OFFLINE_CACHE}"

# ── Network reachability ──────────────────────────────────────────────────────
hdr "Network state"
if run_t 5 "curl -sS --max-time 4 https://pypi.org >/dev/null"; then
    NET_UP=true
    echo -e "  ${YELLOW}!${RESET} Network is REACHABLE."
    echo -e "    ${DIM}Tools may silently succeed by fetching what they need, so a pass here${RESET}"
    echo -e "    ${DIM}does not prove offline readiness. Re-run disconnected, or use --simulate.${RESET}"
else
    NET_UP=false
    echo -e "  ${GREEN}✔${RESET} Network is unreachable — this is a genuine offline test."
fi

if $SIMULATE && $NET_UP; then
    # Point every tool at a black hole. This is not a substitute for a real
    # disconnection (it does not stop a tool using a cached DNS answer or a unix
    # socket), but it catches the common case of an outbound HTTP call.
    export http_proxy="http://127.0.0.1:9" https_proxy="http://127.0.0.1:9"
    export HTTP_PROXY="$http_proxy" HTTPS_PROXY="$https_proxy"
    export no_proxy="" NO_PROXY=""
    echo -e "  ${BLUE}i${RESET} --simulate: outbound HTTP forced to a dead port."
fi

# ── Group A: tools that need nothing staged ───────────────────────────────────
hdr "Group A — no staged data required"

check_simple() {   # name, command that must succeed offline
    local name="$1" cmd="$2"
    if ! has_cmd "$name"; then skip "$name" "not installed"; return; fi
    if run_t 60 "$cmd"; then pass "$name works offline"
    else fail "$name works offline" "command failed or timed out: $cmd"; fi
}

echo 'password = "hunter2supersecret123"' > "${SCRATCH}/probe.py"
echo 'x = 1' > "${SCRATCH}/clean.py"
printf '#!/bin/sh\necho "$1"\n' > "${SCRATCH}/probe.sh"
printf 'int main(){return 0;}\n' > "${SCRATCH}/probe.c"
printf 'FROM ubuntu:22.04\nUSER root\n' > "${SCRATCH}/Dockerfile"

check_simple betterleaks    "betterleaks dir '${SCRATCH}' -v; true"
check_simple detect-secrets "detect-secrets scan '${SCRATCH}'"
check_simple bandit         "bandit -q '${SCRATCH}/clean.py'; true"
check_simple shellcheck     "shellcheck '${SCRATCH}/probe.sh'; true"
check_simple cppcheck       "cppcheck '${SCRATCH}/probe.c'"
check_simple hadolint       "hadolint '${SCRATCH}/Dockerfile'; true"

if has_cmd yara; then
    if compgen -G "${WORK_DIR}/yara-rules/*.yar" >/dev/null 2>&1; then
        check_simple yara "yara ${WORK_DIR}/yara-rules/*.yar '${SCRATCH}'; true"
    else
        skip "yara" "no .yar rules in ${WORK_DIR}/yara-rules (rules are yours to supply)"
    fi
else
    skip "yara" "not installed"
fi

# ── Group B: tools that need staged data ──────────────────────────────────────
hdr "Group B — requires staged data"

# Semgrep: must resolve a LOCAL ruleset file, never a registry identifier.
if has_cmd semgrep; then
    if compgen -G "${SEMGREP_RULES_DIR}/*.yaml" >/dev/null 2>&1; then
        rules=$(ls -1 "${SEMGREP_RULES_DIR}"/*.yaml | head -1)
        if run_t 180 "semgrep --config '${rules}' --metrics=off --quiet --json '${SCRATCH}'"; then
            pass "semgrep runs from staged rules ($(ls -1 "${SEMGREP_RULES_DIR}"/*.yaml | wc -l) ruleset file(s))"
        else
            fail "semgrep runs from staged rules" "check ${rules}"
        fi
        # A registry identifier must NOT resolve offline; if it does, the host
        # still has network and this whole run proves nothing.
        if $NET_UP; then
            skip "semgrep cannot reach its registry" "network is up"
        elif run_t 30 "semgrep --config p/owasp-top-ten --metrics=off --quiet --json '${SCRATCH}'"; then
            fail "semgrep cannot reach its registry" \
                 "a p/ identifier resolved — something has network access"
        else
            pass "semgrep cannot reach its registry (expected offline)"
        fi
    else
        fail "semgrep runs from staged rules" \
             "no .yaml in ${SEMGREP_RULES_DIR} — Layer 2 will not run; see INSTALL.md §10.4"
    fi
else
    skip "semgrep" "not installed"
fi

# trivy: must scan using the staged DB with every update path disabled.
if has_cmd trivy; then
    if [[ -d "$TRIVY_CACHE_DIR" ]] && compgen -G "${TRIVY_CACHE_DIR}/db/*" >/dev/null 2>&1; then
        if run_t 240 "trivy fs --quiet --exit-code 0 --format json \
                       --skip-db-update --skip-java-db-update --offline-scan \
                       --cache-dir '${TRIVY_CACHE_DIR}' '${SCRATCH}'"; then
            pass "trivy scans from the staged database"
        else
            fail "trivy scans from the staged database" \
                 "check ${TRIVY_CACHE_DIR}"
        fi
    else
        fail "trivy scans from the staged database" \
             "no database in ${TRIVY_CACHE_DIR} — this is the ONLY offline CVE coverage; see INSTALL.md §10.4"
    fi
else
    skip "trivy" "not installed"
fi

# ClamAV: an empty database still exits 0, so check signatures exist first.
if has_cmd clamscan; then
    db=""
    compgen -G "${CLAMAV_DB_DIR}/*.c[vl]d"  >/dev/null 2>&1 && db="$CLAMAV_DB_DIR"
    [[ -z "$db" ]] && compgen -G "/var/lib/clamav/*.c[vl]d" >/dev/null 2>&1 && db="/var/lib/clamav"
    if [[ -n "$db" ]]; then
        if run_t 240 "clamscan -r --quiet --database='${db}' '${SCRATCH}'; true"; then
            pass "clamscan runs against signatures in ${db}"
        else
            fail "clamscan runs against signatures" "database at ${db} may be corrupt"
        fi
    else
        fail "clamscan has signatures" \
             "no *.cvd/*.cld found — a scan would report clean because it has no signatures"
    fi
else
    skip "clamscan" "not installed"
fi

check_simple checkov "checkov -f '${SCRATCH}/Dockerfile' --quiet --skip-download; true"

if has_cmd scancode; then
    if run_t 300 "scancode --license --copyright --json-pp '${SCRATCH}/sc.json' --quiet --timeout 60 '${SCRATCH}'"; then
        pass "scancode detects licences offline (CVE lookup correctly omitted)"
    else
        fail "scancode detects licences offline"
    fi
else
    skip "scancode" "not installed"
fi

# ── Group C: no offline mode exists ───────────────────────────────────────────
hdr "Group C — no offline mode (expected to be unavailable)"
for t in pip-audit safety npm; do
    if has_cmd "$t"; then
        echo -e "  ${BLUE}i${RESET} ${t} is installed but is never invoked under --offline"
    else
        echo -e "  ${BLUE}i${RESET} ${t} not installed — no impact offline"
    fi
done
echo -e "    ${DIM}Python and JavaScript dependency CVEs are covered by the staged trivy database.${RESET}"

# ── End-to-end pipeline run ───────────────────────────────────────────────────
hdr "End-to-end — pipeline scan with coverage check"

FIXTURE="${SCRIPT_DIR}/tests/fixtures/clean"
if [[ ! -d "$FIXTURE" ]]; then
    FIXTURE="${SCRATCH}/repo"; mkdir -p "${FIXTURE}/src"
    cp "${SCRATCH}/clean.py" "${FIXTURE}/src/app.py"
fi

VW="${SCRATCH}/work"; mkdir -p "$VW"
if WORK_DIR="$VW" OUTPUT_DIR="${VW}/out" OFFLINE_CACHE="$OFFLINE_CACHE" \
   timeout 900 "${SCRIPT_DIR}/ai_transit.sh" --offline --quiet "$FIXTURE" >/dev/null 2>&1; then
    pass "offline pipeline run completed"
else
    # A FAIL verdict is a legitimate outcome; only a crash is a problem here.
    [[ -n "$(ls -t "${VW}"/reports/report_*.json 2>/dev/null)" ]] \
        && pass "offline pipeline run completed (non-zero verdict)" \
        || fail "offline pipeline run completed" "no report was produced"
fi

REPORT=$(ls -t "${VW}"/reports/report_*.json 2>/dev/null | head -1 || true)
if [[ -n "$REPORT" ]]; then
    echo
    python3 - "$REPORT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"    verdict           : {d['verdict']}")
print(f"    coverage_complete : {d['coverage_complete']}")
print()
for layer, state in sorted(d.get("coverage", {}).items()):
    mark = "OK " if state.startswith("ran") else "GAP"
    print(f"      [{mark}] {layer:26} {state}")
PY
    echo
    # The five layers a verdict actually rests on.
    GAPS=$(python3 - "$REPORT" <<'PY'
import json, sys
REQUIRED = ["L1_secrets_betterleaks","L1_malware","L2_owasp_cwe",
            "L3_dependency_cve","L5_per_language_sast"]
cov = json.load(open(sys.argv[1])).get("coverage", {})
print(" ".join(l for l in REQUIRED if not cov.get(l,"missing").startswith("ran")))
PY
)
    if [[ -z "$GAPS" ]]; then
        pass "all required layers ran offline"
    else
        fail "all required layers ran offline" "not run: ${GAPS}"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}───────────────────────────────────────────────${RESET}"
TOTAL=$(( PASS_N + FAIL_N ))
if (( FAIL_N == 0 )); then
    echo -e "${GREEN}${BOLD}  ✔  ${PASS_N}/${TOTAL} checks passed${RESET}  (${SKIP_N} skipped)"
    $NET_UP && echo -e "${YELLOW}     Network was reachable — re-run disconnected to confirm.${RESET}"
    echo
    exit 0
else
    echo -e "${RED}${BOLD}  ✘  ${FAIL_N} of ${TOTAL} checks failed${RESET}  (${SKIP_N} skipped)"
    echo
    for f in "${FAILED[@]}"; do echo -e "    ${RED}•${RESET} $f"; done
    echo
    echo -e "  ${DIM}Staging instructions: INSTALL.md §10.4${RESET}"
    exit 1
fi
