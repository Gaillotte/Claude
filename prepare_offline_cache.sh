#!/usr/bin/env bash
# AI Transit Pipeline — build the offline asset cache
#
# Run this on a CONNECTED host. It downloads everything the scanners need at
# scan time, into a single directory you then copy to the air-gapped host.
#
#   ./prepare_offline_cache.sh [output_dir]      # default: ./offline-cache
#
# On the air-gapped host:
#   export OFFLINE_CACHE=/opt/ai-transit/offline-cache
#   ./ai_transit.sh --offline /path/to/repo
set -euo pipefail

CACHE="${1:-$(pwd)/offline-cache}"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
BLUE='\033[34m'; BOLD='\033[1m'; RESET='\033[0m'
info() { echo -e "${BLUE}[INFO]${RESET}  $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()  { echo -e "${RED}${BOLD}[ERROR]${RESET} $*" >&2; exit 1; }

has_cmd() { command -v "$1" &>/dev/null; }

STAGED=0
SKIPPED=0

mkdir -p "${CACHE}/semgrep-rules" "${CACHE}/trivy-db" "${CACHE}/clamav" "${CACHE}/yara-rules"

echo
echo -e "${BOLD}Building offline cache in: ${CACHE}${RESET}"
echo

# ── 1. Semgrep rulesets ───────────────────────────────────────────────────────
# The pipeline requests these by registry name ("p/owasp-top-ten"), which needs
# the network. --dump-config resolves a ruleset into a single self-contained
# YAML file that --config can read from disk instead.
info "[1/4] Semgrep rulesets"
if has_cmd semgrep; then
    for rs in owasp-top-ten cwe-top-25 security-audit secrets javascript; do
        if semgrep --config "p/${rs}" --dump-config \
                > "${CACHE}/semgrep-rules/${rs}.yaml" 2>/dev/null \
           && [[ -s "${CACHE}/semgrep-rules/${rs}.yaml" ]]; then
            ok "  ${rs}.yaml  ($(wc -l < "${CACHE}/semgrep-rules/${rs}.yaml") lines)"
            (( STAGED++ )) || true
        else
            rm -f "${CACHE}/semgrep-rules/${rs}.yaml"
            warn "  ${rs}: could not be exported"
            (( SKIPPED++ )) || true
        fi
    done
else
    warn "  semgrep not installed — Layer 2 will not run offline"
    (( SKIPPED++ )) || true
fi

# ── 2. Trivy vulnerability database ───────────────────────────────────────────
info "[2/4] Trivy vulnerability database"
if has_cmd trivy; then
    if trivy fs --download-db-only --cache-dir "${CACHE}/trivy-db" 2>/dev/null; then
        ok "  database downloaded ($(du -sh "${CACHE}/trivy-db" | cut -f1))"
        (( STAGED++ )) || true
    else
        warn "  trivy database download failed"
        (( SKIPPED++ )) || true
    fi
else
    warn "  trivy not installed — Layer 3 dependency CVEs will not run offline"
    (( SKIPPED++ )) || true
fi

# ── 3. ClamAV signatures ──────────────────────────────────────────────────────
# An empty ClamAV database still exits 0, which reads as "clean". Staging real
# signatures is what makes the malware layer meaningful offline.
info "[3/4] ClamAV signature database"
if has_cmd freshclam; then
    freshclam --quiet 2>/dev/null || warn "  freshclam reported an error (continuing)"
fi
if compgen -G "/var/lib/clamav/*.c[vl]d" >/dev/null 2>&1; then
    cp /var/lib/clamav/*.c[vl]d "${CACHE}/clamav/" 2>/dev/null || true
    ok "  $(ls -1 "${CACHE}/clamav" | wc -l) signature file(s) copied"
    (( STAGED++ )) || true
else
    warn "  no signature files found in /var/lib/clamav — malware scan will detect nothing offline"
    (( SKIPPED++ )) || true
fi

# ── 4. YARA rules ─────────────────────────────────────────────────────────────
# These are your own rules; there is nothing to download. Copy whatever the
# connected host uses so the air-gapped host has the same coverage.
info "[4/4] YARA rules"
if compgen -G "/opt/ai-transit/yara-rules/*.yar" >/dev/null 2>&1; then
    cp /opt/ai-transit/yara-rules/*.yar "${CACHE}/yara-rules/" 2>/dev/null || true
    ok "  $(ls -1 "${CACHE}/yara-rules" | wc -l) rule file(s) copied"
    (( STAGED++ )) || true
else
    warn "  no .yar files in /opt/ai-transit/yara-rules (custom IOC rules are optional)"
fi

# ── Manifest, so the air-gapped host can verify the transfer ──────────────────
( cd "$CACHE" && find . -type f ! -name '.cache_manifest.sha256' -print0 \
    | sort -z | xargs -0 sha256sum > .cache_manifest.sha256 ) 2>/dev/null || true

echo
echo -e "${BOLD}────────────────────────────────────────${RESET}"
echo "  Staged : ${STAGED} asset group(s)"
echo "  Skipped: ${SKIPPED}"
echo "  Size   : $(du -sh "$CACHE" | cut -f1)"
echo
echo "Copy this directory to the air-gapped host, then:"
echo "    export OFFLINE_CACHE=/opt/ai-transit/offline-cache"
echo "    ./ai_transit.sh --offline /path/to/repo"
echo
echo "Verify the transfer on arrival:"
echo "    cd \$OFFLINE_CACHE && sha256sum --check .cache_manifest.sha256"
echo

# These three have no offline mode at all; say so plainly rather than letting
# the air-gapped operator discover it from a silently empty report.
echo -e "${YELLOW}Not available offline under any configuration:${RESET}"
echo "  pip-audit   — queries a remote advisory service"
echo "  safety      — queries a remote advisory service"
echo "  npm audit   — queries the npm registry"
echo "  ScanCode --vulnerability — queries VulnerableCode"
echo
echo "Python and JavaScript dependency CVEs are covered by the staged trivy"
echo "database instead. ScanCode licence and copyright detection is unaffected."
echo
