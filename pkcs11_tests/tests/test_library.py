"""Tests for PKCS11Library — token/slot discovery."""

import pytest
import pkcs11

from pkcs11_app.library import PKCS11Library
from pkcs11_app.config import PKCS11Config


class TestPKCS11Library:
    def test_lib_loads(self, pkcs11_library: PKCS11Library):
        assert pkcs11_library.lib is not None

    def test_lib_singleton(self, pkcs11_library: PKCS11Library):
        lib1 = pkcs11_library.lib
        lib2 = pkcs11_library.lib
        assert lib1 is lib2

    def test_reinitialize_clears_cached_lib(self, pkcs11_library: PKCS11Library):
        _ = pkcs11_library.lib
        assert pkcs11_library._lib is not None
        pkcs11_library.reinitialize()
        assert pkcs11_library._lib is None
        # Trigger reload so other tests still work
        _ = pkcs11_library.lib

    def test_list_tokens(self, pkcs11_library: PKCS11Library):
        tokens = pkcs11_library.list_tokens()
        assert isinstance(tokens, list)
        assert len(tokens) >= 1

    def test_list_slots(self, pkcs11_library: PKCS11Library):
        slots = pkcs11_library.list_slots()
        assert isinstance(slots, list)

    def test_get_token_found(self, pkcs11_library: PKCS11Library):
        token = pkcs11_library.get_token()
        assert token is not None
        assert pkcs11_library.config.token_label in token.label

    def test_get_token_not_found(self, pkcs11_library: PKCS11Library):
        lib = PKCS11Library(
            PKCS11Config(
                module_path=pkcs11_library.config.module_path,
                token_label="__NonExistentToken__",
                user_pin="1234",
                so_pin="12345678",
            )
        )
        with pytest.raises(RuntimeError, match="not found"):
            lib.get_token()

    def test_get_info(self, pkcs11_library: PKCS11Library):
        info = pkcs11_library.get_info()
        assert info is not None

    def test_invalid_module_path_raises(self):
        cfg = PKCS11Config(module_path="/nonexistent/libpkcs11.so")
        with pytest.raises(RuntimeError):
            cfg.validate()
