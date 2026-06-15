#!/usr/bin/env bash
# Récupération sécurisée d'un dépôt Git public (GitHub uniquement)
set -euo pipefail

WORK_DIR="${WORK_DIR:-/opt/ai-transit}"
MAX_SIZE_MB=500

# ── Fonctions de log ────────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
info() { echo -e "\033[34m[INFO]\033[0m  $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m  $*"; }
ok()   { echo -e "\033[32m[OK]\033[0m    $*"; }
fail() { echo -e "\033[31m[FAIL]\033[0m  $*" >&2; exit 1; }

has_cmd() { command -v "$1" &>/dev/null; }

# ── Vérification des arguments ───────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    fail "Usage : $0 <url_ou_chemin_git> [branche]"
fi

REPO_INPUT="$1"
BRANCH="${2:-}"

# ── Whitelist hôte : GitHub uniquement ──────────────────────────────────────
if [[ "$REPO_INPUT" =~ ^https?:// ]]; then
    HOST=$(echo "$REPO_INPUT" | awk -F/ '{print $3}')
    if [[ "$HOST" != "github.com" ]]; then
        fail "Hôte refusé : '$HOST'. Seul github.com est autorisé."
    fi
    IS_REMOTE=true
else
    # Chemin local
    if [[ ! -d "$REPO_INPUT" ]]; then
        fail "Chemin local introuvable : $REPO_INPUT"
    fi
    IS_REMOTE=false
fi

# ── Vérification taille (API GitHub) ────────────────────────────────────────
if [[ "$IS_REMOTE" == true ]] && has_cmd jq && has_cmd curl; then
    REPO_PATH=$(echo "$REPO_INPUT" | sed 's|https://github.com/||;s|\.git$||')
    SIZE_KB=$(curl -sf "https://api.github.com/repos/${REPO_PATH}" \
        -H "Accept: application/vnd.github+json" 2>/dev/null \
        | jq -r '.size // 0') || SIZE_KB=0
    SIZE_MB=$(( SIZE_KB / 1024 ))
    if (( SIZE_MB > MAX_SIZE_MB )); then
        fail "Repo trop volumineux : ${SIZE_MB} MB > limite ${MAX_SIZE_MB} MB"
    fi
    info "Taille repo : ${SIZE_MB} MB (limite ${MAX_SIZE_MB} MB)"
fi

# ── Préparation répertoires ──────────────────────────────────────────────────
mkdir -p "${WORK_DIR}/fetch" "${WORK_DIR}/quarantine" \
         "${WORK_DIR}/approved" "${WORK_DIR}/reports" \
         "${WORK_DIR}/logs" "${WORK_DIR}/yara-rules"
chmod 700 "${WORK_DIR}/quarantine"

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
DEST="${WORK_DIR}/fetch/repo_${TIMESTAMP}"

# ── Clone / copie ────────────────────────────────────────────────────────────
if [[ "$IS_REMOTE" == true ]]; then
    info "Clonage : $REPO_INPUT → $DEST"
    CLONE_ARGS=(--depth 1 --no-tags --single-branch)
    [[ -n "$BRANCH" ]] && CLONE_ARGS+=(--branch "$BRANCH")
    git clone "${CLONE_ARGS[@]}" "$REPO_INPUT" "$DEST"
else
    info "Copie locale : $REPO_INPUT → $DEST"
    cp -r "$REPO_INPUT" "$DEST"
fi

# ── Suppression métadonnées git ──────────────────────────────────────────────
rm -rf "${DEST}/.git"
ok "Métadonnées .git supprimées"

# ── Manifest SHA-256 ────────────────────────────────────────────────────────
MANIFEST="${DEST}/.manifest_sha256.txt"
info "Calcul du manifest SHA-256…"
find "$DEST" -type f | sort | while read -r f; do
    sha256sum "$f"
done > "$MANIFEST"
ok "Manifest écrit : $MANIFEST"

# ── Triage rapide patterns bruts ────────────────────────────────────────────
TRIAGE_HITS=0
TRIAGE_PATTERNS=('eval\s*\(' 'exec\s*\(' 'base64_decode' 'system\s*\(' \
                 'curl\s*\|' 'wget\s*\|' 'chmod\s*\+x' 'rm\s*-rf\s*/')

for pattern in "${TRIAGE_PATTERNS[@]}"; do
    if grep -rqE "$pattern" "$DEST" 2>/dev/null; then
        warn "Pattern suspect détecté : $pattern"
        (( TRIAGE_HITS++ )) || true
    fi
done

if (( TRIAGE_HITS > 0 )); then
    warn "Triage rapide : ${TRIAGE_HITS} pattern(s) suspect(s) — scan approfondi requis"
else
    ok "Triage rapide : aucun pattern suspect"
fi

ok "Fetch terminé → $DEST"
echo "$DEST"
