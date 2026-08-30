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

# ── Arguments ─────────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && {
    echo -e "${BOLD}Usage:${RESET} $0 <repo_url_or_local_path> [branch]"
    echo
    echo "  Examples:"
    echo "    $0 https://github.com/org/repo"
    echo "    $0 https://github.com/org/repo main"
    echo "    $0 /path/to/local/repo"
    echo
    echo "    $0 --quiet --min-severity critical https://github.com/org/repo"
    echo
    echo "  Options:"
    echo "    --build                Rebuild the Docker image"
    echo
    echo "  Forwarded to the pipeline inside the container:"
    echo "    --quiet | --verbose    Log verbosity"
    echo "    --report-only          Never block; generate reports and exit 0"
    echo "    --min-severity LEVEL   low | medium | high | critical"
    echo "    --since COMMIT         Diff mode: scan only files changed since COMMIT"
    exit 1
}

# ── Collect pipeline flags to forward into the container ─────────────────────
# Without this the Docker interface is asymmetric with the native one: env
# vars reach the pipeline but --quiet / --report-only / --min-severity /
# --since do not, so those flags can only be used outside Docker.
PIPELINE_FLAGS=()
while [[ $# -gt 0 && "$1" == --* ]]; do
    case "$1" in
        --quiet|--verbose|--report-only)
            PIPELINE_FLAGS+=("$1"); shift ;;
        --min-severity|--since)
            [[ $# -ge 2 ]] || die "$1 requires an argument"
            PIPELINE_FLAGS+=("$1" "$2"); shift 2 ;;
        *)
            die "Unknown option: $1" ;;
    esac
done

[[ $# -lt 1 ]] && die "Missing <repo_url_or_local_path>. Run with no arguments for usage."

REPO_INPUT="$1"
BRANCH="${2:-}"
mkdir -p "$OUTPUT_DIR"

# ── Ensure image exists ───────────────────────────────────────────────────────
if ! docker image inspect "$IMAGE" &>/dev/null; then
    info "Image '${IMAGE}' not found — building now …"
    docker build -t "$IMAGE" "$SCRIPT_DIR"
    ok "Image built."
fi


# ── Forward environment variables to the container ───────────────────────────
# Variables from the host shell are automatically propagated when set.
DOCKER_ENV_ARGS=(-e OUTPUT_DIR=/output)
for _var in WORK_DIR MAX_SIZE_MB MIN_SEVERITY VERBOSITY GITHUB_TOKEN SINCE_COMMIT; do
    [[ -n "${!_var:-}" ]] && DOCKER_ENV_ARGS+=(-e "${_var}=${!_var}")
done

# ── Decide: remote URL or local path ─────────────────────────────────────────
DOCKER_ARGS=()
EXIT_CODE=0   # initialise before the if/else so set -e cannot swallow it

if [[ "$REPO_INPUT" =~ ^https?:// ]]; then
    # Remote URL — pass as-is to the container
    DOCKER_ARGS+=(${PIPELINE_FLAGS[@]+"${PIPELINE_FLAGS[@]}"} "$REPO_INPUT")
    [[ -n "$BRANCH" ]] && DOCKER_ARGS+=("$BRANCH")

    info "Scanning remote repo : $REPO_INPUT"
    docker run --rm \
        -v "${OUTPUT_DIR}:/output" \
        "${DOCKER_ENV_ARGS[@]}" \
        "$IMAGE" "${DOCKER_ARGS[@]}" || EXIT_CODE=$?
else
    # Local path — mount it into the container as read-only
    LOCAL_PATH="$(realpath "$REPO_INPUT")"
    [[ -d "$LOCAL_PATH" ]] || die "Local path not found: $LOCAL_PATH"
    CONTAINER_PATH="/mnt/localrepo"
    DOCKER_ARGS+=(${PIPELINE_FLAGS[@]+"${PIPELINE_FLAGS[@]}"} "$CONTAINER_PATH")
    # A branch is meaningless for a local path -- the tree is already checked out.
    if [[ -n "$BRANCH" ]]; then
        warn "Ignoring branch '$BRANCH': not applicable to a local path."
    fi

    info "Scanning local path  : $LOCAL_PATH"
    docker run --rm \
        -v "${OUTPUT_DIR}:/output" \
        -v "${LOCAL_PATH}:${CONTAINER_PATH}:ro" \
        "${DOCKER_ENV_ARGS[@]}" \
        "$IMAGE" "${DOCKER_ARGS[@]}" || EXIT_CODE=$?
fi

echo
if [[ $EXIT_CODE -eq 0 ]]; then
    ok "Approved archive available in: ${OUTPUT_DIR}/"
else
    warn "Scan failed — check output above for details."
fi
exit $EXIT_CODE
