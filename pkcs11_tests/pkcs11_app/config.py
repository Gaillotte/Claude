"""PKCS11 configuration, resolved from environment variables with sane defaults."""

import os
from dataclasses import dataclass, field
from pathlib import Path


def _find_softhsm_lib() -> str:
    """Auto-detect libsofthsm2.so on common Linux/macOS paths."""
    candidates = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so",
    ]
    for path in candidates:
        if Path(path).exists():
            return path
    return ""


@dataclass
class PKCS11Config:
    module_path: str = field(
        default_factory=lambda: os.environ.get("PKCS11_MODULE_PATH", _find_softhsm_lib())
    )
    token_label: str = field(
        default_factory=lambda: os.environ.get("PKCS11_TOKEN_LABEL", "TestToken")
    )
    user_pin: str = field(
        default_factory=lambda: os.environ.get("PKCS11_USER_PIN", "1234")
    )
    so_pin: str = field(
        default_factory=lambda: os.environ.get("PKCS11_SO_PIN", "12345678")
    )

    def validate(self) -> None:
        if not self.module_path:
            raise RuntimeError(
                "PKCS11 module not found. Set PKCS11_MODULE_PATH or install softhsm2."
            )
        if not Path(self.module_path).exists():
            raise RuntimeError(f"PKCS11 module not found at: {self.module_path}")
