#!/usr/bin/env bash
# Reset / reinitialize the SoftHSM2 token (useful between test runs)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$SCRIPT_DIR/init_softhsm.sh"
