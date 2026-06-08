#!/usr/bin/env bash
# Initialize a SoftHSM2 token for the test suite
set -euo pipefail

SOFTHSM2_CONF="${SOFTHSM2_CONF:-$HOME/.softhsm2/softhsm2.conf}"
TOKEN_DIR="${SOFTHSM2_TOKEN_DIR:-$HOME/.softhsm2/tokens}"
SO_PIN="${SO_PIN:-1234}"
USER_PIN="${USER_PIN:-1234}"
LABEL="${LABEL:-TestToken}"

echo "[*] Setting up SoftHSM2..."
mkdir -p "$TOKEN_DIR"
mkdir -p "$(dirname "$SOFTHSM2_CONF")"

cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF

export SOFTHSM2_CONF

echo "[*] Deleting existing test tokens..."
softhsm2-util --delete-token --token "$LABEL" 2>/dev/null || true

echo "[*] Initializing token '$LABEL'..."
softhsm2-util --init-token --free \
    --label "$LABEL" \
    --so-pin "$SO_PIN" \
    --pin "$USER_PIN"

echo "[*] Token list:"
softhsm2-util --show-slots

echo ""
echo "[+] Setup complete."
echo "    SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo "    SO_PIN=$SO_PIN"
echo "    USER_PIN=$USER_PIN"
