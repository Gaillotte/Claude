#!/usr/bin/env bash
# Generate an HTML + lcov coverage report for the locally built SoftHSM2 (C++).
#
# Prerequisites:
#   - SoftHSM2 must have been built with --with-coverage
#   - lcov and genhtml must be installed (sudo apt-get install lcov)
#   - Tests must have been run at least once against the local library
#
# Usage:
#   ./scripts/softhsm2_coverage_report.sh [--output-dir DIR]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/softhsm2_build"
OUTPUT_DIR="$PROJECT_ROOT/softhsm2_coverage_html"

for arg in "$@"; do
  case "$arg" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --output-dir=*) OUTPUT_DIR="${arg#*=}" ;;
  esac
done

# ── Checks ────────────────────────────────────────────────────────────────────
for tool in lcov genhtml; do
  if ! command -v "$tool" &>/dev/null; then
    echo "ERROR: $tool not found. Install: sudo apt-get install lcov"
    exit 1
  fi
done

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "ERROR: Build directory not found: $BUILD_DIR"
  echo "Run:  ./scripts/build_softhsm2.sh --with-coverage"
  exit 1
fi

# ── Capture coverage data ─────────────────────────────────────────────────────
INFO_FILE="$PROJECT_ROOT/softhsm2_coverage.info"

echo "==> Capturing coverage data from $BUILD_DIR..."
lcov \
  --capture \
  --directory "$BUILD_DIR" \
  --output-file "$INFO_FILE" \
  --quiet

# Remove system headers and test infrastructure from the report
echo "==> Filtering system headers..."
lcov \
  --remove "$INFO_FILE" \
  '/usr/*' \
  '*/testing/*' \
  --output-file "$INFO_FILE" \
  --quiet

# ── Generate HTML report ──────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
echo "==> Generating HTML report → $OUTPUT_DIR..."
genhtml \
  "$INFO_FILE" \
  --output-directory "$OUTPUT_DIR" \
  --title "SoftHSM2 C++ Coverage" \
  --legend \
  --show-details \
  --quiet

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  SoftHSM2 C++ coverage report generated                        ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
lcov --summary "$INFO_FILE" 2>&1 | grep -E "lines|functions|branches"
echo ""
echo "  HTML report: $OUTPUT_DIR/index.html"
