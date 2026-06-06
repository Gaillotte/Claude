"""PKCS11 session lifecycle management."""

from __future__ import annotations

import pkcs11
from pkcs11 import Session
from pkcs11_app.library import PKCS11Library
from pkcs11_app.config import PKCS11Config


class SessionManager:
    """Open / close PKCS11 sessions with optional authentication."""

    def __init__(self, library: PKCS11Library | None = None) -> None:
        self.library = library or PKCS11Library()

    # ------------------------------------------------------------------ #
    # Context-manager helpers
    # ------------------------------------------------------------------ #

    def open_user_session(self) -> Session:
        """Open an R/W session authenticated with the User PIN."""
        token = self.library.get_token()
        return token.open(
            rw=True,
            user_pin=self.library.config.user_pin,
        )

    def open_ro_session(self) -> Session:
        """Open a read-only session (no authentication)."""
        token = self.library.get_token()
        return token.open(rw=False)

    def open_so_session(self) -> Session:
        """Open an R/W session authenticated with the SO PIN."""
        token = self.library.get_token()
        return token.open(
            rw=True,
            so_pin=self.library.config.so_pin,
        )

    # ------------------------------------------------------------------ #
    # Session information helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def get_session_info(session: Session) -> dict:
        """Return basic session metadata using python-pkcs11 attributes."""
        return {
            "rw": session.rw,
            "user_type": session.user_type,
            "handle": session.handle,
            "token_label": session.token.label,
        }

    @staticmethod
    def session_is_rw(session: Session) -> bool:
        return session.rw

    @staticmethod
    def login_user(session: Session, pin: str) -> None:
        session.reaffirm_credentials(pin=pin)

    @staticmethod
    def logout(session: Session) -> None:
        # python-pkcs11 does not expose an explicit logout;
        # closing and reopening achieves the same security boundary.
        pass

    @staticmethod
    def change_pin(session: Session, old_pin: str, new_pin: str) -> None:
        session.set_pin(old_pin, new_pin)
