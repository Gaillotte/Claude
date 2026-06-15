#!/usr/bin/env bash
# Point d'entrée principal du pipeline AI Transit
# Usage : ./ai_transit.sh <chemin_ou_url_git> [branche]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-/opt/ai-transit}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/Good}"

# ── Couleurs ─────────────────────────────────────────────────────────────────
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
BLUE='\033[34m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${BLUE}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}${BOLD}[ERREUR]${RESET} $*" >&2; }
die()   { error "$*"; exit 1; }

# ── Usage ─────────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo -e "${BOLD}Usage :${RESET} $0 <chemin_ou_url_git> [branche]"
    echo
    echo "  Exemples :"
    echo "    $0 https://github.com/org/repo"
    echo "    $0 https://github.com/org/repo main"
    echo "    $0 /chemin/local/vers/repo"
    echo
    echo "  Résultat :"
    echo "    PASS → archive ZIP dans ./Good/"
    echo "    FAIL → message d'erreur + rapport dans \${WORK_DIR}/reports/"
    exit 1
fi

REPO_INPUT="$1"
BRANCH="${2:-}"

# ── Vérification des scripts dépendants ──────────────────────────────────────
[[ -f "${SCRIPT_DIR}/fetch_repo.sh" ]]   || die "fetch_repo.sh introuvable dans $SCRIPT_DIR"
[[ -f "${SCRIPT_DIR}/scan_pipeline.sh" ]] || die "scan_pipeline.sh introuvable dans $SCRIPT_DIR"

# ── Création du répertoire de sortie ─────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"

echo
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}       AI Transit Pipeline — Démarrage        ${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo
info "Source   : $REPO_INPUT"
[[ -n "$BRANCH" ]] && info "Branche  : $BRANCH"
info "Work dir : $WORK_DIR"
info "Sortie   : $OUTPUT_DIR"
echo

# ── Phase 1 : Fetch ───────────────────────────────────────────────────────────
echo -e "${BOLD}── Phase 1 : Récupération ─────────────────────${RESET}"
FETCH_ARGS=("$REPO_INPUT")
[[ -n "$BRANCH" ]] && FETCH_ARGS+=("$BRANCH")

FETCH_OUTPUT=$(WORK_DIR="$WORK_DIR" bash "${SCRIPT_DIR}/fetch_repo.sh" "${FETCH_ARGS[@]}" 2>&1) || {
    error "Échec de la récupération du dépôt."
    echo "$FETCH_OUTPUT" >&2
    die "Pipeline interrompu à la phase 1."
}

# Récupère le dernier chemin absolu retourné par fetch_repo.sh
FETCH_DIR=$(echo "$FETCH_OUTPUT" | grep -E '^/' | tail -1)
echo "$FETCH_OUTPUT" | grep -v '^/'   # affiche les logs (sans la ligne de chemin)

[[ -d "$FETCH_DIR" ]] || die "Répertoire fetchté introuvable : $FETCH_DIR"
ok "Dépôt disponible : $FETCH_DIR"
echo

# ── Phase 2 : Scan ───────────────────────────────────────────────────────────
echo -e "${BOLD}── Phase 2 : Scan de sécurité ─────────────────${RESET}"
SCAN_OUTPUT=$(WORK_DIR="$WORK_DIR" bash "${SCRIPT_DIR}/scan_pipeline.sh" "$FETCH_DIR" 2>&1) || true

VERDICT=$(echo "$SCAN_OUTPUT" | grep -E '^(PASS|FAIL)$' | tail -1 || echo "FAIL")
echo "$SCAN_OUTPUT" | grep -v -E '^(PASS|FAIL)$'   # logs sans la ligne verdict

echo
echo -e "${BOLD}── Verdict ────────────────────────────────────${RESET}"

# ── Décision finale ───────────────────────────────────────────────────────────
if [[ "$VERDICT" == "PASS" ]]; then
    # Création de l'archive ZIP dans Good/
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    REPO_NAME=$(basename "$FETCH_DIR")
    ARCHIVE="${OUTPUT_DIR}/${REPO_NAME}_${TIMESTAMP}.zip"

    info "Archivage en cours…"
    zip -r "$ARCHIVE" "$FETCH_DIR" -x "*.manifest_sha256.txt" > /dev/null

    echo
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}║              ✔  SCAN RÉUSSI (PASS)          ║${RESET}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
    ok "Archive créée : $ARCHIVE"
    echo
else
    # Déplacement en quarantaine
    QUARANTINE="${WORK_DIR}/quarantine"
    mkdir -p "$QUARANTINE"
    chmod 700 "$QUARANTINE"
    mv "$FETCH_DIR" "$QUARANTINE/" 2>/dev/null || true

    # Recherche du rapport le plus récent
    LATEST_REPORT=$(ls -t "${WORK_DIR}/reports/report_"*.json 2>/dev/null | head -1 || true)

    echo
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}${BOLD}║           ✘  SCAN ÉCHOUÉ (FAIL)             ║${RESET}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
    echo
    error "Le dépôt n'a pas passé le scan de sécurité."
    error "Les fichiers ont été déplacés en quarantaine : $QUARANTINE"

    if [[ -f "$LATEST_REPORT" ]]; then
        error "Rapport détaillé : $LATEST_REPORT"
        echo
        warn "Résumé des findings :"
        # Affiche les findings si jq disponible
        if command -v jq &>/dev/null; then
            jq -r '
              "  Verdict   : " + .verdict,
              "  Pass      : " + (.summary.pass | tostring),
              "  Warn      : " + (.summary.warn | tostring),
              "  Fail      : " + (.summary.fail | tostring),
              "",
              "  Findings :",
              (.findings | to_entries[] | "    - " + .key + " → " + .value)
            ' "$LATEST_REPORT" >&2
        else
            cat "$LATEST_REPORT" >&2
        fi
    fi

    echo
    exit 1
fi
