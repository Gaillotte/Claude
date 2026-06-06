"""Tests for PKCS11Config — unit tests (no HSM needed)."""

import os
import pytest
from unittest.mock import patch
from pathlib import Path

from pkcs11_app.config import PKCS11Config, _find_softhsm_lib


class TestPKCS11Config:
    def test_defaults_from_env(self, monkeypatch):
        monkeypatch.setenv("PKCS11_TOKEN_LABEL", "MyToken")
        monkeypatch.setenv("PKCS11_USER_PIN", "9999")
        monkeypatch.setenv("PKCS11_SO_PIN", "87654321")
        monkeypatch.setenv("PKCS11_MODULE_PATH", "/fake/lib.so")
        cfg = PKCS11Config()
        assert cfg.token_label == "MyToken"
        assert cfg.user_pin == "9999"
        assert cfg.so_pin == "87654321"
        assert cfg.module_path == "/fake/lib.so"

    def test_hardcoded_override(self):
        cfg = PKCS11Config(token_label="Custom", user_pin="0000", so_pin="11111111", module_path="/x")
        assert cfg.token_label == "Custom"
        assert cfg.user_pin == "0000"

    def test_validate_missing_module(self):
        cfg = PKCS11Config(module_path="")
        with pytest.raises(RuntimeError, match="PKCS11 module not found"):
            cfg.validate()

    def test_validate_nonexistent_path(self):
        cfg = PKCS11Config(module_path="/nonexistent/libpkcs11.so")
        with pytest.raises(RuntimeError, match="not found at"):
            cfg.validate()

    def test_validate_existing_path(self, tmp_path):
        lib = tmp_path / "libfake.so"
        lib.write_bytes(b"")
        cfg = PKCS11Config(module_path=str(lib))
        cfg.validate()  # should not raise

    def test_find_softhsm_lib_returns_string(self):
        result = _find_softhsm_lib()
        assert isinstance(result, str)

    def test_find_softhsm_lib_real_or_empty(self):
        result = _find_softhsm_lib()
        if result:
            assert Path(result).exists()
