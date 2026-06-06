#!/usr/bin/env bash
# Build SoftHSM2 from source and install it locally inside the project.
#
# Usage:
#   ./scripts/build_softhsm2.sh [--with-coverage] [--clean]
#
# Output:
#   softhsm2_build/          — build artefacts (out-of-tree)
#   softhsm2_install/        — local install prefix
#     bin/softhsm2-util
#     lib/softhsm/libsofthsm2.so
#     etc/softhsm/softhsm2.conf
#
# Environment variables honoured:
#   BUILD_JOBS   — parallel jobs (default: nproc)
#   CRYPTO_BACKEND — openssl (default) | botan
#
# After a successful build the script prints the environment variables
# needed to run the tests against the locally built library.

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/softhsm2_src"
BUILD_DIR="$PROJECT_ROOT/softhsm2_build"
INSTALL_DIR="$PROJECT_ROOT/softhsm2_install"

# ── Defaults ──────────────────────────────────────────────────────────────────
WITH_COVERAGE=0
CLEAN=0
BUILD_JOBS="${BUILD_JOBS:-$(nproc)}"
CRYPTO_BACKEND="${CRYPTO_BACKEND:-openssl}"

# ── Parse args ────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --with-coverage) WITH_COVERAGE=1 ;;
    --clean)         CLEAN=1 ;;
    --help|-h)
      sed -n '2,20p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

# ── Sanity checks ─────────────────────────────────────────────────────────────
if [[ ! -d "$SRC_DIR" ]]; then
  echo "ERROR: Source directory not found: $SRC_DIR"
  echo "Run:  git clone --depth=1 --branch 2.6.1 https://github.com/opendnssec/SoftHSMv2.git softhsm2_src"
  exit 1
fi

for tool in autoconf automake libtoolize pkg-config; do
  if ! command -v "$tool" &>/dev/null; then
    echo "ERROR: $tool is required. Install with: sudo apt-get install libtool autoconf automake pkg-config"
    exit 1
  fi
done

# ── Clean if requested ────────────────────────────────────────────────────────
if [[ "$CLEAN" -eq 1 ]]; then
  echo "==> Cleaning build and install directories..."
  rm -rf "$BUILD_DIR" "$INSTALL_DIR"
fi

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

# ── autogen (only when configure script is missing) ───────────────────────────
if [[ ! -f "$SRC_DIR/configure" ]]; then
  echo "==> Running autogen.sh..."
  (cd "$SRC_DIR" && ./autogen.sh)
fi

# ── Configure ─────────────────────────────────────────────────────────────────
EXTRA_CFLAGS=""
EXTRA_CXXFLAGS=""

if [[ "$WITH_COVERAGE" -eq 1 ]]; then
  echo "==> Coverage build enabled (gcov)"
  EXTRA_CFLAGS="--coverage -O0 -g"
  EXTRA_CXXFLAGS="--coverage -O0 -g"
fi

echo "==> Configuring (crypto=$CRYPTO_BACKEND, coverage=$WITH_COVERAGE)..."
(
  cd "$BUILD_DIR"
  "$SRC_DIR/configure" \
    --prefix="$INSTALL_DIR" \
    --with-crypto-backend="$CRYPTO_BACKEND" \
    --disable-non-paged-memory \
    --disable-p11-kit \
    CFLAGS="-O2 -g $EXTRA_CFLAGS" \
    CXXFLAGS="-O2 -g $EXTRA_CXXFLAGS"
)

# ── Build ─────────────────────────────────────────────────────────────────────
echo "==> Building with $BUILD_JOBS jobs..."
make -C "$BUILD_DIR" -j"$BUILD_JOBS"

# ── Install ───────────────────────────────────────────────────────────────────
echo "==> Installing to $INSTALL_DIR..."
make -C "$BUILD_DIR" install

# ── Verify ────────────────────────────────────────────────────────────────────
LIB_PATH="$INSTALL_DIR/lib/softhsm/libsofthsm2.so"
UTIL_PATH="$INSTALL_DIR/bin/softhsm2-util"

if [[ ! -f "$LIB_PATH" ]]; then
  echo "ERROR: Library not found after install: $LIB_PATH"
  exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  SoftHSM2 built and installed successfully                      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Library : $LIB_PATH"
echo "  Utility : $UTIL_PATH"
echo "  Version : $("$UTIL_PATH" --version 2>/dev/null || echo 'unknown')"
echo ""
echo "  To use this build for tests, run:"
echo ""
echo "    source scripts/env_local_softhsm2.sh"
echo "  or export manually:"
echo "    export PKCS11_MODULE_PATH=\"$LIB_PATH\""
echo ""

if [[ "$WITH_COVERAGE" -eq 1 ]]; then
  echo "  Coverage instrumentation is active."
  echo "  After running tests, generate a report with:"
  echo "    scripts/softhsm2_coverage_report.sh"
  echo ""
fi
