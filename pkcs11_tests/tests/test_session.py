"""Tests for PKCS11 session lifecycle and authentication."""

import pytest
import pkcs11

from pkcs11_app.session import SessionManager
from pkcs11_app.library import PKCS11Library
from pkcs11_app.config import PKCS11Config


class TestSessionLifecycle:
    def test_open_user_session(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            assert session is not None

    def test_open_ro_session(self, session_manager: SessionManager):
        with session_manager.open_ro_session() as session:
            assert session is not None

    def test_user_session_is_rw(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            assert SessionManager.session_is_rw(session) is True

    def test_ro_session_is_not_rw(self, session_manager: SessionManager):
        with session_manager.open_ro_session() as session:
            assert SessionManager.session_is_rw(session) is False

    def test_get_session_info(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            info = SessionManager.get_session_info(session)
            assert "rw" in info
            assert "user_type" in info
            assert "handle" in info
            assert "token_label" in info

    def test_session_context_manager_closes(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            pass  # should not raise on exit

    def test_rw_plus_ro_concurrent(self, session_manager: SessionManager):
        """An authenticated RW session and a public RO session can coexist."""
        with session_manager.open_user_session() as s1:
            with session_manager.open_ro_session() as s2:
                assert s1 is not s2
                assert s1.rw is True
                assert s2.rw is False

    def test_wrong_user_pin_raises(self, pkcs11_library: PKCS11Library):
        bad_lib = PKCS11Library(
            PKCS11Config(
                module_path=pkcs11_library.config.module_path,
                token_label=pkcs11_library.config.token_label,
                user_pin="wrong",
                so_pin=pkcs11_library.config.so_pin,
            )
        )
        sm = SessionManager(bad_lib)
        with pytest.raises(pkcs11.PKCS11Error):
            with sm.open_user_session():
                pass

    def test_so_session_opens(self, session_manager: SessionManager):
        with session_manager.open_so_session() as session:
            assert session is not None
            assert SessionManager.session_is_rw(session) is True

    def test_wrong_so_pin_raises(self, pkcs11_library: PKCS11Library):
        bad_lib = PKCS11Library(
            PKCS11Config(
                module_path=pkcs11_library.config.module_path,
                token_label=pkcs11_library.config.token_label,
                user_pin=pkcs11_library.config.user_pin,
                so_pin="wrongso",
            )
        )
        sm = SessionManager(bad_lib)
        with pytest.raises(pkcs11.PKCS11Error):
            with sm.open_so_session():
                pass

    def test_session_token_label(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            assert session_manager.library.config.token_label in session.token.label

    def test_logout_noop(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            SessionManager.logout(session)  # should not raise

    def test_user_type_authenticated(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            assert session.user_type == pkcs11.UserType.USER

    def test_ro_session_user_type(self, session_manager: SessionManager):
        with session_manager.open_ro_session() as session:
            assert session.user_type == pkcs11.UserType.NOBODY
