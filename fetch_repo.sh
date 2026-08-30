#!/usr/bin/env bash
# AI Transit Pipeline — secure repository fetch (GitHub only)
set -euo pipefail

WORK_DIR="${WORK_DIR:-/opt/ai-transit}"
MAX_SIZE_MB="${MAX_SIZE_MB:-500}"

# ── Log functions ─────────────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
info() { echo -e "\033[34m[INFO]\033[0m  $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m  $*"; }
ok()   { echo -e "\033[32m[OK]\033[0m    $*"; }
fail() { echo -e "\033[31m[FAIL]\033[0m  $*" >&2; exit 1; }

has_cmd() { command -v "$1" &>/dev/null; }

# ── Arguments ─────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    fail "Usage: $0 <git_url_or_local_path> [branch]"
fi

REPO_INPUT="$1"
BRANCH="${2:-}"

# ── Host whitelist: github.com only ──────────────────────────────────────────
if [[ "$REPO_INPUT" =~ ^https?:// ]]; then
    HOST=$(echo "$REPO_INPUT" | awk -F/ '{print $3}')
    if [[ "$HOST" != "github.com" ]]; then
        fail "Host rejected: '$HOST'. Only github.com is allowed."
    fi
    IS_REMOTE=true
else
    # Local path
    if [[ ! -d "$REPO_INPUT" ]]; then
        fail "Local path not found: $REPO_INPUT"
    fi
    IS_REMOTE=false
fi

# ── Size check via GitHub API ─────────────────────────────────────────────────
if [[ "$IS_REMOTE" == true ]] && has_cmd jq && has_cmd curl; then
    REPO_PATH=$(echo "$REPO_INPUT" | sed 's|https://github.com/||;s|\.git$||')
    # Capture body and HTTP status code on separate lines
    API_RESPONSE=$(curl -sf \
        -H "Accept: application/vnd.github+json" \
        ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
        -w "\n%{http_code}" \
        "https://api.github.com/repos/${REPO_PATH}" 2>/dev/null || true)
    HTTP_CODE=$(echo "$API_RESPONSE" | tail -1)
    API_BODY=$(echo "$API_RESPONSE" | head -n -1)

    if [[ "$HTTP_CODE" == "404" ]]; then
        fail "Repository not found or private: ${REPO_INPUT} (HTTP 404). For private repos, set GITHUB_TOKEN."
    elif [[ "$HTTP_CODE" != "200" ]]; then
        warn "GitHub API unavailable (HTTP ${HTTP_CODE:-timeout}) — size check skipped"
    else
        SIZE_KB=$(echo "$API_BODY" | jq -r '.size // 0' 2>/dev/null || echo "0")
        SIZE_MB=$(( SIZE_KB / 1024 ))
        if (( SIZE_MB > MAX_SIZE_MB )); then
            fail "Repository too large: ${SIZE_MB} MB exceeds limit of ${MAX_SIZE_MB} MB"
        fi
        info "Repository size: ${SIZE_MB} MB (limit: ${MAX_SIZE_MB} MB)"
    fi
fi

# ── Directory setup ───────────────────────────────────────────────────────────
mkdir -p "${WORK_DIR}/fetch" "${WORK_DIR}/quarantine" \
         "${WORK_DIR}/approved" "${WORK_DIR}/reports" \
         "${WORK_DIR}/logs" "${WORK_DIR}/yara-rules"
chmod 700 "${WORK_DIR}/quarantine"

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
DEST="${WORK_DIR}/fetch/repo_${TIMESTAMP}"

# ── Clone / copy ──────────────────────────────────────────────────────────────
if [[ "$IS_REMOTE" == true ]]; then
    info "Cloning: $REPO_INPUT → $DEST"
    CLONE_ARGS=(--depth 1 --no-tags --single-branch)
    [[ -n "$BRANCH" ]] && CLONE_ARGS+=(--branch "$BRANCH")

    # Authenticate private repos via GIT_ASKPASS. The token is passed to the
    # helper through the environment (readable only by this user via /proc),
    # never in the clone URL (git config / reflog) nor in argv (world-readable
    # through `ps`). The helper script itself contains no secret.
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        info "GITHUB_TOKEN detected — using authenticated clone via GIT_ASKPASS"
        ASKPASS_SCRIPT=$(mktemp)
        chmod 700 "$ASKPASS_SCRIPT"
        printf '#!/bin/sh\nprintf %%s "$GIT_TOKEN_VALUE"\n' > "$ASKPASS_SCRIPT"
        # Guarantee removal even if the clone fails under `set -e`.
        trap 'rm -f "$ASKPASS_SCRIPT"' EXIT
        GIT_TOKEN_VALUE="$GITHUB_TOKEN" \
        GIT_ASKPASS="$ASKPASS_SCRIPT" \
        GIT_TERMINAL_PROMPT=0 \
            git clone "${CLONE_ARGS[@]}" "$REPO_INPUT" "$DEST"
        rm -f "$ASKPASS_SCRIPT"
        trap - EXIT
    else
        git clone "${CLONE_ARGS[@]}" "$REPO_INPUT" "$DEST"
    fi
else
    info "Copying local path: $REPO_INPUT → $DEST"
    cp -r "$REPO_INPUT" "$DEST"
fi

# ── Diff mode: list files changed since SINCE_COMMIT ─────────────────────────
DIFF_FILES_LIST=""
if [[ -n "${SINCE_COMMIT:-}" ]]; then
    info "Diff mode: computing changed files since ${SINCE_COMMIT}"
    # Temporarily keep .git for the diff, then remove it
    if [[ "$IS_REMOTE" == true ]]; then
        # For remote clone we used --depth 1; need to fetch the reference commit too
        git -C "$DEST" fetch --depth=2 origin "${SINCE_COMMIT}" 2>/dev/null || true
    fi
    DIFF_FILES_LIST=$(git -C "$DEST" diff --name-only "${SINCE_COMMIT}" HEAD 2>/dev/null \
        | sed "s|^|${DEST}/|" | tr '\n' ':' || true)
    if [[ -n "$DIFF_FILES_LIST" ]]; then
        # Count non-empty entries: the list has a trailing ':' delimiter, so a
        # plain `tr | wc -l` would report one extra.
        info "Diff mode: $(echo "$DIFF_FILES_LIST" | tr ':' '\n' | grep -c .) changed file(s)"
        echo "$DIFF_FILES_LIST" > "${WORK_DIR}/.diff_files"
    else
        warn "Diff mode: commit ${SINCE_COMMIT} not reachable or no files changed — falling back to full scan"
    fi
fi

# ── Remove git metadata ───────────────────────────────────────────────────────
rm -rf "${DEST}/.git"
ok ".git metadata removed"

# ── SHA-256 manifest ──────────────────────────────────────────────────────────
MANIFEST="${DEST}/.manifest_sha256.txt"
info "Computing SHA-256 manifest…"
find "$DEST" -type f | sort | while read -r f; do
    sha256sum "$f"
done > "$MANIFEST"
ok "Manifest written: $MANIFEST"

# ── Quick pattern triage ──────────────────────────────────────────────────────
TRIAGE_HITS=0
# Patterns use ERE. Pipe character must be escaped as \| is ERE alternation,
# so we match a literal pipe with [|].
TRIAGE_PATTERNS=('eval\s*\(' 'exec\s*\(' 'base64_decode' 'system\s*\(' \
                 'curl\s+[^;]*[|]' 'wget\s+[^;]*[|]' 'chmod\s*\+x' 'rm\s+-rf\s*/')

for pattern in "${TRIAGE_PATTERNS[@]}"; do
    if grep -rqE "$pattern" "$DEST" 2>/dev/null; then
        warn "Suspicious pattern found: $pattern"
        (( TRIAGE_HITS++ )) || true
    fi
done

if (( TRIAGE_HITS > 0 )); then
    warn "Quick triage: ${TRIAGE_HITS} suspicious pattern(s) — deep scan required"
else
    ok "Quick triage: no suspicious patterns"
fi

ok "Fetch complete → $DEST"
# Write path to a dedicated result file so the caller can read it reliably
# without grepping stdout (which may contain other absolute paths in log lines).
echo "$DEST" > "${WORK_DIR}/.fetch_result"
echo "$DEST"
