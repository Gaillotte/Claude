#!/usr/bin/env bash
# Initialize a SoftHSM2 token for testing

set -euo pipefail

SLOT_LABEL="${PKCS11_TOKEN_LABEL:-TestToken}"
SO_PIN="${PKCS11_SO_PIN:-12345678}"
USER_PIN="${PKCS11_USER_PIN:-1234}"
SOFTHSM2_CONF="${SOFTHSM2_CONF:-/etc/softhsm/softhsm2.conf}"

# Allow per-user config override
if [ -f "${HOME}/.config/softhsm2/softhsm2.conf" ]; then
    export SOFTHSM2_CONF="${HOME}/.config/softhsm2/softhsm2.conf"
fi

echo "=== SoftHSM2 configuration: $SOFTHSM2_CONF ==="

# Create token directory if needed
TOKEN_DIR=$(grep "^directories.tokendir" "$SOFTHSM2_CONF" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "/var/lib/softhsm/tokens")
mkdir -p "$TOKEN_DIR"

# Delete existing token with same label (idempotent)
if softhsm2-util --show-slots 2>/dev/null | grep -q "Label.*$SLOT_LABEL"; then
    echo "Deleting existing token '$SLOT_LABEL'..."
    softhsm2-util --delete-token --token "$SLOT_LABEL" || true
fi

echo "=== Initializing token '$SLOT_LABEL' ==="
softhsm2-util --init-token --free \
    --label "$SLOT_LABEL" \
    --so-pin "$SO_PIN" \
    --pin "$USER_PIN"

echo "=== Available slots ==="
softhsm2-util --show-slots

# Detect PKCS11 library path
find_pkcs11_lib() {
    for path in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /opt/homebrew/lib/softhsm/libsofthsm2.so; do
        if [ -f "$path" ]; then
            echo "$path"
            return
        fi
    done
    # Fallback: let ldconfig find it
    ldconfig -p 2>/dev/null | grep libsofthsm2 | awk '{print $NF}' | head -1
}

LIB=$(find_pkcs11_lib)
if [ -z "$LIB" ]; then
    echo "WARNING: Could not locate libsofthsm2.so automatically."
    echo "Set PKCS11_MODULE_PATH manually."
else
    echo "=== PKCS11 library: $LIB ==="
    echo "Export the following for tests:"
    echo "  export PKCS11_MODULE_PATH=\"$LIB\""
    echo "  export PKCS11_TOKEN_LABEL=\"$SLOT_LABEL\""
    echo "  export PKCS11_USER_PIN=\"$USER_PIN\""
    echo "  export PKCS11_SO_PIN=\"$SO_PIN\""
fi

echo "=== Initialization complete ==="
