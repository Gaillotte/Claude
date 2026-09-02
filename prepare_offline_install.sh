#!/usr/bin/env bash
# AI Transit Pipeline — build the offline INSTALL bundle
#
# Distinct from prepare_offline_cache.sh:
#
#   this script  → the software itself (tools + pipeline). Static; rebuild only
#                  when a tool version changes.
#   cache script → the data the scanners read (rules, CVE DB, signatures).
#                  Perishable; rebuild weekly.
#
# Run on a CONNECTED host running the SAME OS and architecture as the target.
# Packages are not portable across distributions or architectures.
#
#   ./prepare_offline_install.sh [output_dir]     # default: ./offline-install
set -euo pipefail

BUNDLE="${1:-$(pwd)/offline-install}"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
BLUE='\033[34m'; BOLD='\033[1m'; RESET='\033[0m'
info() { echo -e "${BLUE}[INFO]${RESET}  $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()  { echo -e "${RED}${BOLD}[ERROR]${RESET} $*" >&2; exit 1; }
has_cmd() { command -v "$1" &>/dev/null; }

STAGED=0; SKIPPED=0

mkdir -p "${BUNDLE}"/{deb,wheels,bin,pipeline,docker}

echo
echo -e "${BOLD}Building offline install bundle in: ${BUNDLE}${RESET}"
echo -e "Host: $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}") · $(uname -m)"
echo

# Record what this bundle was built on. Installing an amd64 Ubuntu 22.04 bundle
# onto arm64 or Debian 12 fails in confusing ways; the target should be able to
# check before it starts.
{
    . /etc/os-release 2>/dev/null || true
    echo "os_id=${ID:-unknown}"
    echo "os_version=${VERSION_ID:-unknown}"
    echo "arch=$(dpkg --print-architecture 2>/dev/null || uname -m)"
    echo "built_on=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "${BUNDLE}/.bundle_platform"

# ── 1. System packages (.deb) ─────────────────────────────────────────────────
info "[1/5] System packages"
APT_PKGS=(bash git curl ca-certificates jq zip unzip file coreutils
          python3 python3-pip python3-venv rsync
          shellcheck cppcheck clamav clamav-daemon clamav-freshclam yara
          nodejs npm)
if has_cmd apt-get; then
    # --download-only fetches the packages AND their dependencies into the apt
    # cache; copy them out rather than relying on the cache surviving.
    if sudo apt-get install --download-only --reinstall -y "${APT_PKGS[@]}" >/dev/null 2>&1; then
        cp /var/cache/apt/archives/*.deb "${BUNDLE}/deb/" 2>/dev/null || true
        n=$(ls -1 "${BUNDLE}/deb"/*.deb 2>/dev/null | wc -l)
        if (( n > 0 )); then
            ok "  ${n} .deb file(s) staged ($(du -sh "${BUNDLE}/deb" | cut -f1))"
            (( STAGED++ )) || true
        else
            warn "  no .deb files were copied — the apt cache may be cleaned automatically"
            (( SKIPPED++ )) || true
        fi
    else
        warn "  apt-get download failed (needs sudo, and a working apt source list)"
        (( SKIPPED++ )) || true
    fi
else
    warn "  apt-get not available — this bundle targets Debian/Ubuntu only"
    (( SKIPPED++ )) || true
fi

# ── 2. Python wheels ──────────────────────────────────────────────────────────
info "[2/5] Python packages"
PIP_PKGS=(openpyxl reportlab python-docx detect-secrets bandit
          pip-audit safety semgrep checkov scancode-toolkit)
if has_cmd pip3; then
    if pip3 download --dest "${BUNDLE}/wheels" "${PIP_PKGS[@]}" >/dev/null 2>&1; then
        n=$(ls -1 "${BUNDLE}/wheels" 2>/dev/null | wc -l)
        ok "  ${n} wheel/sdist file(s) staged ($(du -sh "${BUNDLE}/wheels" | cut -f1))"
        (( STAGED++ )) || true
    else
        warn "  pip download failed — some packages may have no wheel for this platform"
        (( SKIPPED++ )) || true
    fi
else
    warn "  pip3 not available"
    (( SKIPPED++ )) || true
fi

# ── 3. Standalone binaries ────────────────────────────────────────────────────
info "[3/5] Standalone binaries"
for tool in betterleaks trivy hadolint; do
    if has_cmd "$tool"; then
        cp "$(command -v "$tool")" "${BUNDLE}/bin/" 2>/dev/null \
            && ok "  ${tool} copied from $(command -v "$tool")" \
            || warn "  ${tool}: copy failed"
    else
        warn "  ${tool} not installed on this host — install it first, then re-run"
        (( SKIPPED++ )) || true
    fi
done
[[ -n "$(ls -A "${BUNDLE}/bin" 2>/dev/null)" ]] && (( STAGED++ )) || true

# ── 4. The pipeline itself ────────────────────────────────────────────────────
info "[4/5] Pipeline scripts"
for f in ai_transit.sh fetch_repo.sh scan_pipeline.sh docker-run.sh \
         prepare_offline_cache.sh prepare_offline_install.sh \
         generate_excel_report.py selfcheck.py \
         Dockerfile INSTALL.md OFFLINE_RUNBOOK.md CLAUDE.md; do
    [[ -f "$f" ]] && cp "$f" "${BUNDLE}/pipeline/" 2>/dev/null || true
done
[[ -d tests ]] && cp -r tests "${BUNDLE}/pipeline/" 2>/dev/null || true
ok "  $(find "${BUNDLE}/pipeline" -type f | wc -l) file(s) staged"
(( STAGED++ )) || true

# ── 5. Docker image (optional, and by far the simplest path) ──────────────────
info "[5/5] Docker image"
if has_cmd docker && docker image inspect ai-transit:latest >/dev/null 2>&1; then
    info "  exporting ai-transit:latest (this takes a while)…"
    if docker save ai-transit:latest | gzip > "${BUNDLE}/docker/ai-transit.tar.gz"; then
        ok "  image exported ($(du -sh "${BUNDLE}/docker/ai-transit.tar.gz" | cut -f1))"
        (( STAGED++ )) || true
    else
        warn "  docker save failed"
        (( SKIPPED++ )) || true
    fi
else
    warn "  ai-transit:latest not built here — skipping the Docker path"
    warn "  (build it first with ./docker-run.sh --build to include it)"
    (( SKIPPED++ )) || true
fi

# ── Manifest ──────────────────────────────────────────────────────────────────
( cd "$BUNDLE" && find . -type f ! -name '.install_manifest.sha256' -print0 \
    | sort -z | xargs -0 sha256sum > .install_manifest.sha256 ) 2>/dev/null || true

echo
echo -e "${BOLD}────────────────────────────────────────${RESET}"
echo "  Staged : ${STAGED} group(s)"
echo "  Skipped: ${SKIPPED}"
echo "  Size   : $(du -sh "$BUNDLE" | cut -f1)"
echo
echo "Transfer this directory to the air-gapped host, then follow INSTALL.md §11."
echo "Remember the scan-data cache is a SEPARATE, perishable bundle:"
echo "    ./prepare_offline_cache.sh"
echo
