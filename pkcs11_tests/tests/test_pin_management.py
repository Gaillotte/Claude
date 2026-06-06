"""Tests for PIN management: change_pin, seed_random."""

import os
import pytest
import pkcs11

from pkcs11_app.session import SessionManager
from pkcs11_app.library import PKCS11Library
from pkcs11_app.config import PKCS11Config

TEMP_PIN = "temppkcs1"


class TestPINManagement:
    def test_change_pin_and_back(self, session_manager: SessionManager):
        """Change PIN, verify new PIN works, restore original PIN."""
        original_pin = session_manager.library.config.user_pin
        with session_manager.open_user_session() as session:
            SessionManager.change_pin(session, original_pin, TEMP_PIN)
        try:
            lib2 = PKCS11Library(PKCS11Config(
                module_path=session_manager.library.config.module_path,
                token_label=session_manager.library.config.token_label,
                user_pin=TEMP_PIN,
                so_pin=session_manager.library.config.so_pin,
            ))
            sm2 = SessionManager(lib2)
            with sm2.open_user_session() as session2:
                assert session2.rw is True
                # Restore original PIN from within the new session
                SessionManager.change_pin(session2, TEMP_PIN, original_pin)
        except Exception:
            # If anything goes wrong, restore via a fresh session with the temp PIN
            try:
                lib3 = PKCS11Library(PKCS11Config(
                    module_path=session_manager.library.config.module_path,
                    token_label=session_manager.library.config.token_label,
                    user_pin=TEMP_PIN,
                    so_pin=session_manager.library.config.so_pin,
                ))
                with SessionManager(lib3).open_user_session() as s:
                    s.set_pin(TEMP_PIN, original_pin)
            except Exception:
                pass
            raise

    def test_change_pin_wrong_old_pin_raises(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            with pytest.raises(pkcs11.PKCS11Error):
                SessionManager.change_pin(session, "wrong_pin_!", "newpin")

    def test_seed_random(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            SessionManager.seed_random(session, os.urandom(32))

    def test_seed_random_various_lengths(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            for length in (8, 16, 32, 64, 128):
                SessionManager.seed_random(session, os.urandom(length))

    def test_login_user_on_already_authenticated(self, session_manager: SessionManager):
        """reaffirm_credentials raises OperationNotInitialized on SoftHSM (expected)."""
        with session_manager.open_user_session() as session:
            try:
                SessionManager.login_user(session, session_manager.library.config.user_pin)
            except pkcs11.OperationNotInitialized:
                pass  # expected on non-protected-auth tokens

    def test_logout_noop(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            SessionManager.logout(session)
            info = SessionManager.get_session_info(session)
            assert info["rw"] is True
