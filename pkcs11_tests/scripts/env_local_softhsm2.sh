#!/usr/bin/env bash
# Source this file to point tests at the locally built SoftHSM2.
#
#   source scripts/env_local_softhsm2.sh
#
# It also initialises the token if it does not yet exist.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_DIR="$PROJECT_ROOT/softhsm2_install"
TOKEN_DIR="$PROJECT_ROOT/softhsm2_tokens"

export PKCS11_MODULE_PATH="$INSTALL_DIR/lib/softhsm/libsofthsm2.so"
export PKCS11_TOKEN_LABEL="TestToken"
export PKCS11_USER_PIN="1234"
export PKCS11_SO_PIN="12345678"
export SOFTHSM2_CONF="$PROJECT_ROOT/softhsm2_local.conf"

# Write a local softhsm2.conf pointing at our token directory
mkdir -p "$TOKEN_DIR"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF

# Initialise token only if not yet done
UTIL="$INSTALL_DIR/bin/softhsm2-util"
if ! SOFTHSM2_CONF="$SOFTHSM2_CONF" "$UTIL" --show-slots 2>/dev/null | grep -q "$PKCS11_TOKEN_LABEL"; then
  echo "==> Initialising token '$PKCS11_TOKEN_LABEL'..."
  SOFTHSM2_CONF="$SOFTHSM2_CONF" "$UTIL" \
    --init-token --free \
    --label  "$PKCS11_TOKEN_LABEL" \
    --pin    "$PKCS11_USER_PIN" \
    --so-pin "$PKCS11_SO_PIN"
fi

echo "==> Local SoftHSM2 environment active"
echo "    PKCS11_MODULE_PATH=$PKCS11_MODULE_PATH"
echo "    SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo "    Token: $PKCS11_TOKEN_LABEL"
