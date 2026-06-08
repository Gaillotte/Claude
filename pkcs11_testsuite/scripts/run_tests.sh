#!/usr/bin/env bash
# Build and run the full PKCS#11 test suite against SoftHSM2
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
BUILD="$ROOT/build"

SOFTHSM2_CONF="${SOFTHSM2_CONF:-$HOME/.softhsm2/softhsm2.conf}"
LIB="${PKCS11_LIB:-/usr/lib/softhsm/libsofthsm2.so}"
USER_PIN="${USER_PIN:-1234}"
SO_PIN="${SO_PIN:-1234}"

export SOFTHSM2_CONF

echo "==================================================="
echo "  PKCS#11 Test Suite — SoftHSM2"
echo "==================================================="
echo "  Library : $LIB"
echo "  Config  : $SOFTHSM2_CONF"
echo ""

# Check library exists
if [ ! -f "$LIB" ]; then
    echo "ERROR: Library not found: $LIB"
    echo "       Try: apt install softhsm2"
    exit 1
fi

# Setup token if not already done
if [ ! -f "$SOFTHSM2_CONF" ]; then
    echo "[*] Running first-time SoftHSM2 setup..."
    bash "$SCRIPT_DIR/setup_softhsm.sh"
fi

# Build
echo "[*] Building..."
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -Wno-dev > /dev/null
cmake --build "$BUILD" --parallel $(nproc)
echo "[+] Build complete."

# Run
echo "[*] Running tests..."
"$BUILD/pkcs11_test" -l "$LIB" -p "$USER_PIN" -P "$SO_PIN" "$@"
