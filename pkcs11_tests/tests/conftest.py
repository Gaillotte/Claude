"""Shared pytest fixtures for PKCS11 / SoftHSM2 tests."""

import pytest
import pkcs11

from pkcs11_app.config import PKCS11Config
from pkcs11_app.library import PKCS11Library
from pkcs11_app.session import SessionManager
from pkcs11_app.token import TokenManager
from pkcs11_app.crypto import CryptoOperations


# ------------------------------------------------------------------ #
# Session-scoped singletons
# ------------------------------------------------------------------ #

@pytest.fixture(scope="session")
def pkcs11_config() -> PKCS11Config:
    cfg = PKCS11Config()
    try:
        cfg.validate()
    except RuntimeError as exc:
        pytest.skip(f"PKCS11 module unavailable: {exc}")
    return cfg


@pytest.fixture(scope="session")
def pkcs11_library(pkcs11_config: PKCS11Config) -> PKCS11Library:
    return PKCS11Library(pkcs11_config)


@pytest.fixture(scope="session")
def session_manager(pkcs11_library: PKCS11Library) -> SessionManager:
    return SessionManager(pkcs11_library)


@pytest.fixture(scope="session")
def token_manager(pkcs11_library: PKCS11Library) -> TokenManager:
    return TokenManager(pkcs11_library)


@pytest.fixture(scope="session")
def crypto() -> CryptoOperations:
    return CryptoOperations()


# ------------------------------------------------------------------ #
# Function-scoped sessions
# ------------------------------------------------------------------ #

@pytest.fixture
def user_session(session_manager: SessionManager):
    with session_manager.open_user_session() as session:
        yield session


@pytest.fixture
def ro_session(session_manager: SessionManager):
    with session_manager.open_ro_session() as session:
        yield session


# ------------------------------------------------------------------ #
# Key fixtures (function-scoped — destroyed after each test)
# ------------------------------------------------------------------ #

@pytest.fixture
def aes_key(user_session, token_manager: TokenManager):
    key = token_manager.generate_aes_key(user_session, key_length=256, label="test-aes", token=False)
    yield key
    try:
        key.destroy()
    except Exception:
        pass


@pytest.fixture
def aes_key_128(user_session, token_manager: TokenManager):
    key = token_manager.generate_aes_key(user_session, key_length=128, label="test-aes-128", token=False)
    yield key
    try:
        key.destroy()
    except Exception:
        pass


@pytest.fixture
def des3_key(user_session, token_manager: TokenManager):
    key = token_manager.generate_des3_key(user_session, label="test-des3", token=False)
    yield key
    try:
        key.destroy()
    except Exception:
        pass


@pytest.fixture
def rsa_keypair(user_session, token_manager: TokenManager):
    pub, priv = token_manager.generate_rsa_keypair(
        user_session, key_length=2048, label="test-rsa", token=False
    )
    yield pub, priv
    for obj in (pub, priv):
        try:
            obj.destroy()
        except Exception:
            pass


@pytest.fixture
def ec_keypair(user_session, token_manager: TokenManager):
    pub, priv = token_manager.generate_ec_keypair(user_session, label="test-ec", token=False)
    yield pub, priv
    for obj in (pub, priv):
        try:
            obj.destroy()
        except Exception:
            pass
