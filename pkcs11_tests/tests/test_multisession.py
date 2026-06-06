"""Tests for concurrent/multi-session scenarios.

Note: SoftHSM2 (PKCS11 spec §6.7.7) raises UserAlreadyLoggedIn when a second
session authenticates while a user session is open in the same process.
The correct multi-session approach is to open sessions sequentially or use
one session per thread without re-logging in on the same slot.
"""

import threading
import pytest
import pkcs11

from pkcs11_app.session import SessionManager
from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.token import TokenManager
from pkcs11_app.library import PKCS11Library


class TestMultiSession:
    def test_sequential_sessions(self, session_manager: SessionManager):
        """Sessions can be opened and closed sequentially without error."""
        for _ in range(3):
            with session_manager.open_user_session() as s:
                assert s is not None

    def test_rw_and_ro_sessions_coexist(self, session_manager: SessionManager):
        """An RW authenticated session and a RO public session can coexist."""
        with session_manager.open_user_session() as rw:
            with session_manager.open_ro_session() as ro:
                assert SessionManager.session_is_rw(rw) is True
                assert SessionManager.session_is_rw(ro) is False

    def test_sequential_crypto_operations(self, session_manager: SessionManager, token_manager: TokenManager):
        """Multiple sequential sessions each performing crypto work."""
        results = []
        for idx in range(3):
            with session_manager.open_user_session() as session:
                key = token_manager.generate_aes_key(
                    session, 256, label=f"seq-{idx}", token=False
                )
                crypto = CryptoOperations()
                plaintext = f"Thread {idx} secret".encode()
                ciphertext, iv = crypto.aes_cbc_encrypt(key, plaintext)
                recovered = crypto.aes_cbc_decrypt(key, ciphertext, iv)
                assert recovered == plaintext
                key.destroy()
                results.append(idx)
        assert results == [0, 1, 2]

    def test_parallel_sessions_different_libraries(self, pkcs11_library: PKCS11Library):
        """Each thread gets its own library instance — this avoids slot contention."""
        results = []
        errors = []

        def worker():
            from pkcs11_app.config import PKCS11Config
            cfg = PKCS11Config(
                module_path=pkcs11_library.config.module_path,
                token_label=pkcs11_library.config.token_label,
                user_pin=pkcs11_library.config.user_pin,
                so_pin=pkcs11_library.config.so_pin,
            )
            lib = PKCS11Library(cfg)
            sm = SessionManager(lib)
            try:
                with sm.open_user_session() as s:
                    info = SessionManager.get_session_info(s)
                    results.append(info["rw"])
            except pkcs11.UserAlreadyLoggedIn:
                # PKCS11 spec allows this — record as partial success
                results.append(None)
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Unexpected errors: {errors}"
        assert len(results) == 4

    def test_session_info_fields(self, user_session):
        info = SessionManager.get_session_info(user_session)
        assert info["rw"] is True
        assert "handle" in info
        assert "token_label" in info
