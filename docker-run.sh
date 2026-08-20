#!/usr/bin/env bash
# AI Transit Pipeline — Docker wrapper
# Usage: ./docker-run.sh <repo_url_or_local_path> [branch]
#
# Requirements: Docker (https://docs.docker.com/get-docker/)
# Build once:  ./docker-run.sh --build
set -euo pipefail

IMAGE="ai-transit:latest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/Good"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
BLUE='\033[34m'; BOLD='\033[1m'; RESET='\033[0m'
info()  { echo -e "${BLUE}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()   { echo -e "${RED}${BOLD}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Check Docker ──────────────────────────────────────────────────────────────
command -v docker &>/dev/null || die "Docker not found. Install it from https://docs.docker.com/get-docker/"

# ── Build mode ────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--build" ]]; then
    info "Building Docker image '${IMAGE}' …"
    docker build -t "$IMAGE" "$SCRIPT_DIR"
    ok "Image built: ${IMAGE}"
    echo
    echo -e "${BOLD}Usage:${RESET} $0 <repo_url_or_local_path> [branch]"
    exit 0
fi

# ── Ensure image exists ───────────────────────────────────────────────────────
if ! docker image inspect "$IMAGE" &>/dev/null; then
    info "Image '${IMAGE}' not found — building now …"
    docker build -t "$IMAGE" "$SCRIPT_DIR"
    ok "Image built."
fi

# ── Arguments ─────────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && {
    echo -e "${BOLD}Usage:${RESET} $0 <repo_url_or_local_path> [branch]"
    echo
    echo "  Examples:"
    echo "    $0 https://github.com/org/repo"
    echo "    $0 https://github.com/org/repo main"
    echo "    $0 /path/to/local/repo"
    echo
    echo "  Options:"
    echo "    --build   Rebuild the Docker image"
    exit 1
}

REPO_INPUT="$1"
BRANCH="${2:-}"
mkdir -p "$OUTPUT_DIR"

# ── Decide: remote URL or local path ─────────────────────────────────────────
DOCKER_ARGS=()

if [[ "$REPO_INPUT" =~ ^https?:// ]]; then
    # Remote URL — pass as-is to the container
    DOCKER_ARGS+=("$REPO_INPUT")
    [[ -n "$BRANCH" ]] && DOCKER_ARGS+=("$BRANCH")

    info "Scanning remote repo : $REPO_INPUT"
    docker run --rm \
        -v "${OUTPUT_DIR}:/output" \
        -e OUTPUT_DIR=/output \
        "$IMAGE" "${DOCKER_ARGS[@]}"
else
    # Local path — mount it into the container as read-only
    LOCAL_PATH="$(realpath "$REPO_INPUT")"
    [[ -d "$LOCAL_PATH" ]] || die "Local path not found: $LOCAL_PATH"
    CONTAINER_PATH="/mnt/localrepo"
    DOCKER_ARGS+=("$CONTAINER_PATH")
    [[ -n "$BRANCH" ]] && DOCKER_ARGS+=("$BRANCH")

    info "Scanning local path  : $LOCAL_PATH"
    docker run --rm \
        -v "${OUTPUT_DIR}:/output" \
        -v "${LOCAL_PATH}:${CONTAINER_PATH}:ro" \
        -e OUTPUT_DIR=/output \
        "$IMAGE" "${DOCKER_ARGS[@]}"
fi

EXIT_CODE=$?

echo
if [[ $EXIT_CODE -eq 0 ]]; then
    ok "Approved archive available in: ${OUTPUT_DIR}/"
else
    warn "Scan failed — check output above for details."
fi
exit $EXIT_CODE
