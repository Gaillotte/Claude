#!/usr/bin/env bash
# Install SoftHSM2 and required PKCS11 Python dependencies

set -euo pipefail

echo "=== Installing SoftHSM2 ==="

if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y softhsm2 opensc libengine-pkcs11-openssl
elif command -v yum &>/dev/null; then
    yum install -y softhsm opensc
elif command -v brew &>/dev/null; then
    brew install softhsm opensc
else
    echo "ERROR: Unsupported package manager. Install softhsm2 manually." >&2
    exit 1
fi

echo "=== SoftHSM2 version ==="
softhsm2-util --version

echo "=== Installing Python dependencies ==="
pip install -r "$(dirname "$0")/../requirements.txt"

echo "=== Install complete ==="
