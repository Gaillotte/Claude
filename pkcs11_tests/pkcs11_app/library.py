"""PKCS11 library loader — wraps python-pkcs11 lib object."""

import pkcs11
from pkcs11_app.config import PKCS11Config


class PKCS11Library:
    """Manages the loaded PKCS11 library and token lookup."""

    def __init__(self, config: PKCS11Config | None = None) -> None:
        self.config = config or PKCS11Config()
        self.config.validate()
        self._lib: pkcs11.lib | None = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    @property
    def lib(self) -> pkcs11.lib:
        if self._lib is None:
            self._lib = pkcs11.lib(self.config.module_path)
        return self._lib

    def get_token(self) -> pkcs11.Token:
        """Return the token matching config.token_label."""
        tokens = list(self.lib.get_tokens(token_label=self.config.token_label))
        if not tokens:
            raise RuntimeError(
                f"Token '{self.config.token_label}' not found. "
                "Run scripts/init_softhsm.sh first."
            )
        return tokens[0]

    def list_tokens(self) -> list[pkcs11.Token]:
        return list(self.lib.get_tokens())

    def list_slots(self) -> list[pkcs11.Slot]:
        return list(self.lib.get_slots())

    def get_info(self) -> pkcs11.lib:
        return self.lib

    def reinitialize(self) -> None:
        """Force reload of the library (e.g. after token re-init)."""
        self._lib = None
