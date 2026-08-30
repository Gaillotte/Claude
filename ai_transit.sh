#!/usr/bin/env bash
# AI Transit Pipeline — main entry point
# Usage: ./ai_transit.sh [--quiet|--verbose] <git_url_or_local_path> [branch]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-/opt/ai-transit}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/Good}"
VERBOSITY="normal"   # quiet | normal | verbose

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
BLUE='\033[34m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { [[ "$VERBOSITY" != "quiet" ]] && echo -e "${BLUE}[INFO]${RESET}  $*" || true; }
ok()    { [[ "$VERBOSITY" != "quiet" ]] && echo -e "${GREEN}[OK]${RESET}    $*" || true; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}${BOLD}[ERROR]${RESET} $*" >&2; }
die()   { error "$*"; exit 1; }

# ── Flag parsing ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 && "$1" == --* ]]; do
    case "$1" in
        --quiet)   VERBOSITY="quiet";   shift ;;
        --verbose) VERBOSITY="verbose"; shift ;;
        *) break ;;
    esac
done

# ── Usage ─────────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo -e "${BOLD}Usage:${RESET} $0 [--quiet|--verbose] <git_url_or_local_path> [branch]"
    echo
    echo "  Examples:"
    echo "    $0 https://github.com/org/repo"
    echo "    $0 https://github.com/org/repo main"
    echo "    $0 /local/path/to/repo"
    echo "    $0 --quiet https://github.com/org/repo   # verdict only (CI mode)"
    echo
    echo "  Environment variables:"
    echo "    WORK_DIR    (default: /opt/ai-transit)   working directory"
    echo "    OUTPUT_DIR  (default: <script_dir>/Good) approved ZIP destination"
    echo "    GITHUB_TOKEN                             for private GitHub repos"
    echo
    echo "  Result:"
    echo "    PASS → ZIP archive in ./Good/"
    echo "    FAIL → quarantine + JSON/HTML reports in \${WORK_DIR}/reports/"
    exit 1
fi

REPO_INPUT="$1"
BRANCH="${2:-}"

# ── Dependency check ──────────────────────────────────────────────────────────
[[ -f "${SCRIPT_DIR}/fetch_repo.sh" ]]    || die "fetch_repo.sh not found in $SCRIPT_DIR"
[[ -f "${SCRIPT_DIR}/scan_pipeline.sh" ]] || die "scan_pipeline.sh not found in $SCRIPT_DIR"

# ── Output directory ──────────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"

if [[ "$VERBOSITY" != "quiet" ]]; then
    echo
    echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}        AI Transit Pipeline — Starting        ${RESET}"
    echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
    echo
    info "Source   : $REPO_INPUT"
    [[ -n "$BRANCH" ]] && info "Branch   : $BRANCH"
    info "Work dir : $WORK_DIR"
    info "Output   : $OUTPUT_DIR"
    echo
fi

# ── Phase 1 : Fetch ───────────────────────────────────────────────────────────
echo -e "${BOLD}── Phase 1 : Récupération ─────────────────────${RESET}"
FETCH_ARGS=("$REPO_INPUT")
[[ -n "$BRANCH" ]] && FETCH_ARGS+=("$BRANCH")

rm -f "${WORK_DIR}/.fetch_result"
FETCH_OUTPUT=$(WORK_DIR="$WORK_DIR" bash "${SCRIPT_DIR}/fetch_repo.sh" "${FETCH_ARGS[@]}" 2>&1) || {
    error "Repository fetch failed."
    echo "$FETCH_OUTPUT" >&2
    die "Pipeline aborted at phase 1."
}

# Read the repo path from the dedicated result file written by fetch_repo.sh.
# This avoids grepping stdout, which is fragile when log lines contain absolute paths.
FETCH_DIR=$(cat "${WORK_DIR}/.fetch_result" 2>/dev/null || true)
[[ "$VERBOSITY" != "quiet" ]] && echo "$FETCH_OUTPUT" | grep -v '^/' || true

[[ -d "$FETCH_DIR" ]] || die "Fetched directory not found: $FETCH_DIR"
ok "Repository available: $FETCH_DIR"
[[ "$VERBOSITY" != "quiet" ]] && echo || true

# ── Phase 2: Security scan ────────────────────────────────────────────────────
[[ "$VERBOSITY" != "quiet" ]] && echo -e "${BOLD}── Phase 2: Security scan ──────────────────────${RESET}" || true
SCAN_OUTPUT=$(REPO_INPUT="$REPO_INPUT" WORK_DIR="$WORK_DIR" VERBOSITY="$VERBOSITY" \
    bash "${SCRIPT_DIR}/scan_pipeline.sh" "$FETCH_DIR" 2>&1) || true

VERDICT=$(echo "$SCAN_OUTPUT" | grep -E '^(PASS|FAIL)$' | tail -1 || echo "FAIL")
REPORT_JSON=$(echo "$SCAN_OUTPUT" | grep -E '^/.+\.json$' | tail -1 || true)
REPORT_HTML="${REPORT_JSON%.json}.html"
# Display logs (strip metadata lines)
[[ "$VERBOSITY" != "quiet" ]] && \
    echo "$SCAN_OUTPUT" | grep -vE '^(PASS|FAIL|/.+\.(json|html))$' || true

[[ "$VERBOSITY" != "quiet" ]] && echo || true
[[ "$VERBOSITY" != "quiet" ]] && echo -e "${BOLD}── Verdict ─────────────────────────────────────${RESET}" || true

# ── Décision finale ───────────────────────────────────────────────────────────
if [[ "$VERDICT" == "PASS" ]]; then
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    REPO_NAME=$(basename "$FETCH_DIR")
    ARCHIVE="${OUTPUT_DIR}/${REPO_NAME}_${TIMESTAMP}.zip"

    # Génération du rapport Excel (inclus dans le ZIP)
    EXCEL_PATH="${FETCH_DIR}/scan_report_${TIMESTAMP}.xlsx"
    if [[ -n "$REPORT_JSON" && -f "$REPORT_JSON" ]]; then
        info "Generating Excel report…"
        if python3 "${SCRIPT_DIR}/generate_excel_report.py" \
                "$REPORT_JSON" "$EXCEL_PATH" 2>/dev/null; then
            ok "Excel report  : $EXCEL_PATH"
        else
            warn "Excel report not generated (is openpyxl installed? pip install openpyxl)"
        fi
    fi

    info "Creating archive…"
    if ! zip -r "$ARCHIVE" "$FETCH_DIR" -x "*.manifest_sha256.txt"; then
        die "ZIP archive creation failed (disk full? insufficient permissions?)"
    fi
    [[ -f "$ARCHIVE" ]] || die "Archive not found after zip: $ARCHIVE"

    echo
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}║              ✔  SCAN PASSED (PASS)          ║${RESET}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
    ok "Archive         : $ARCHIVE"
    [[ -f "$EXCEL_PATH" ]] && ok "Excel report    : scan_report_${TIMESTAMP}.xlsx (included in ZIP)"
    [[ -f "$REPORT_JSON" ]]  && ok "JSON report     : $REPORT_JSON"
    [[ -f "$REPORT_HTML" ]]  && ok "HTML report     : file://${REPORT_HTML}"
    echo
else
    # Move to quarantine (cp -a + rm as cross-filesystem fallback)
    QUARANTINE="${WORK_DIR}/quarantine"
    mkdir -p "$QUARANTINE"
    chmod 700 "$QUARANTINE"
    if ! mv "$FETCH_DIR" "$QUARANTINE/" 2>/dev/null; then
        if cp -a "$FETCH_DIR" "$QUARANTINE/" 2>/dev/null; then
            rm -rf "$FETCH_DIR"
        else
            warn "Quarantine: could not move $FETCH_DIR to $QUARANTINE — check permissions and disk space"
        fi
    fi

    LATEST_REPORT=$(ls -t "${WORK_DIR}/reports/report_"*.json 2>/dev/null | head -1 || true)
    LATEST_HTML="${LATEST_REPORT%.json}.html"

    echo
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}${BOLD}║           ✘  SCAN FAILED (FAIL)             ║${RESET}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
    echo
    error "Repository did not pass the security scan."
    error "Files quarantined at: $QUARANTINE"

    if [[ -f "$LATEST_REPORT" ]]; then
        error "JSON report : $LATEST_REPORT"
        [[ -f "$LATEST_HTML" ]] && error "HTML report : file://${LATEST_HTML}"
        echo
        warn "Findings summary:"
        if command -v jq &>/dev/null; then
            jq -r '
              "  Verdict : " + .verdict,
              "  Pass    : " + (.summary.pass | tostring),
              "  Warn    : " + (.summary.warn | tostring),
              "  Fail    : " + (.summary.fail | tostring),
              "",
              "  Findings:",
              (.findings | to_entries[] | "    - " + .key + " → " + .value)
            ' "$LATEST_REPORT" >&2
        else
            cat "$LATEST_REPORT" >&2
        fi
    fi

    echo
    exit 1
fi
