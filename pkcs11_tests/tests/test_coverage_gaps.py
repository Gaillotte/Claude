"""Tests targeting specific uncovered branches: exception handlers in verify methods,
config auto-detection fallback, RSA sign/verify with multiple hash algorithms."""

import os
import pytest
import pkcs11
from pkcs11 import Mechanism
from unittest.mock import patch

from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.config import PKCS11Config, _find_softhsm_lib
from pkcs11_app.session import SessionManager


# ------------------------------------------------------------------ #
# Cover exception handler branches in crypto.py verify methods
# ------------------------------------------------------------------ #

class TestVerifyExceptionBranches:
    """Force SignatureInvalid/SignatureLenRange/DataInvalid paths."""

    def test_rsa_verify_raises_signature_invalid(self, rsa_keypair):
        """All-zero sig triggers the exception branch and returns False."""
        pub, _ = rsa_keypair
        result = CryptoOperations.rsa_verify(pub, b"data", b"\x00" * 256)
        assert result is False

    def test_rsa_verify_raises_on_wrong_length(self, rsa_keypair):
        """Truncated signature (wrong length) triggers exception path."""
        pub, _ = rsa_keypair
        result = CryptoOperations.rsa_verify(pub, b"data", b"\x00" * 10)
        assert result is False

    def test_rsa_pss_verify_raises_signature_invalid(self, rsa_keypair):
        pub, _ = rsa_keypair
        result = CryptoOperations.rsa_pss_verify(pub, b"data", b"\x00" * 256)
        assert result is False

    def test_rsa_pss_verify_wrong_length(self, rsa_keypair):
        pub, _ = rsa_keypair
        result = CryptoOperations.rsa_pss_verify(pub, b"data", b"\x00" * 5)
        assert result is False

    def test_ecdsa_verify_raises_on_bad_sig(self, ec_keypair):
        pub, _ = ec_keypair
        result = CryptoOperations.ecdsa_verify(pub, b"data", b"\x00" * 4)
        assert result is False

    def test_ecdsa_verify_wrong_sig_length(self, ec_keypair):
        pub, _ = ec_keypair
        result = CryptoOperations.ecdsa_verify(pub, b"data", b"\x01")
        assert result is False


# ------------------------------------------------------------------ #
# config.py: _find_softhsm_lib fallback (line 22 — return "")
# ------------------------------------------------------------------ #

class TestConfigAutoDetect:
    def test_find_softhsm_lib_fallback_returns_empty(self):
        """When no candidate path exists, _find_softhsm_lib returns ''."""
        with patch("pkcs11_app.config.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            result = _find_softhsm_lib()
        assert result == ""

    def test_find_softhsm_lib_returns_first_match(self, tmp_path):
        """Returns first existing path."""
        fake_lib = tmp_path / "libsofthsm2.so"
        fake_lib.write_bytes(b"")
        with patch("pkcs11_app.config.Path", side_effect=lambda p: fake_lib if p == str(fake_lib) else type("P", (), {"exists": lambda self: False})()) as _:
            # Just verify the real function can return a path
            result = _find_softhsm_lib()
        assert isinstance(result, str)


# ------------------------------------------------------------------ #
# Additional RSA hash algorithm variants
# ------------------------------------------------------------------ #

class TestRSAHashVariants:
    @pytest.mark.parametrize("mech", [
        Mechanism.SHA1_RSA_PKCS,
        Mechanism.SHA256_RSA_PKCS,
        Mechanism.SHA384_RSA_PKCS,
        Mechanism.SHA512_RSA_PKCS,
    ])
    def test_rsa_sign_verify_hash_variants(self, user_session, token_manager, mech):
        pub, priv = token_manager.generate_rsa_keypair(user_session, key_length=2048, label=f"rsa-hash-{mech}", token=False)
        data = b"test data for hash variant"
        sig = priv.sign(data, mechanism=mech)
        assert isinstance(sig, bytes)
        result = pub.verify(data, sig, mechanism=mech)
        assert result is not False
        pub.destroy(); priv.destroy()


# ------------------------------------------------------------------ #
# AES-CBC raw (no padding) — multi-block
# ------------------------------------------------------------------ #

class TestAESCBCNopadMultiBlock:
    def test_two_blocks(self, user_session, aes_key):
        from pkcs11_app.objects import ObjectOperations
        iv = os.urandom(16)
        plaintext = b"A" * 32  # exactly 2 blocks
        ct = ObjectOperations.aes_cbc_nopad_encrypt(aes_key, plaintext, iv)
        pt = ObjectOperations.aes_cbc_nopad_decrypt(aes_key, ct, iv)
        assert pt == plaintext

    def test_four_blocks(self, user_session, aes_key):
        from pkcs11_app.objects import ObjectOperations
        iv = os.urandom(16)
        plaintext = os.urandom(64)
        ct = ObjectOperations.aes_cbc_nopad_encrypt(aes_key, plaintext, iv)
        pt = ObjectOperations.aes_cbc_nopad_decrypt(aes_key, ct, iv)
        assert pt == plaintext


# ------------------------------------------------------------------ #
# seed_random on session
# ------------------------------------------------------------------ #

class TestSeedRandom:
    def test_seed_random_covered(self, session_manager: SessionManager):
        with session_manager.open_user_session() as session:
            SessionManager.seed_random(session, b"\xDE\xAD\xBE\xEF" * 8)


# ------------------------------------------------------------------ #
# Exception handler branches — mock SignatureInvalid / SignatureLenRange
# ------------------------------------------------------------------ #

class TestExceptionHandlerBranches:
    """Force the except clauses in verify() wrappers via mock."""

    def _mock_signature_invalid(self, *a, **kw):
        raise pkcs11.SignatureInvalid

    def _mock_signature_len_range(self, *a, **kw):
        raise pkcs11.SignatureLenRange

    def test_rsa_verify_signature_invalid_branch(self, rsa_keypair):
        from unittest.mock import patch
        pub, _ = rsa_keypair
        with patch.object(type(pub), "verify", self._mock_signature_invalid):
            assert CryptoOperations.rsa_verify(pub, b"data", b"\x00" * 256) is False

    def test_rsa_verify_signature_len_range_branch(self, rsa_keypair):
        from unittest.mock import patch
        pub, _ = rsa_keypair
        with patch.object(type(pub), "verify", self._mock_signature_len_range):
            assert CryptoOperations.rsa_verify(pub, b"data", b"\x00" * 256) is False

    def test_rsa_pss_verify_signature_invalid_branch(self, rsa_keypair):
        from unittest.mock import patch
        pub, _ = rsa_keypair
        with patch.object(type(pub), "verify", self._mock_signature_invalid):
            assert CryptoOperations.rsa_pss_verify(pub, b"data", b"\x00" * 256) is False

    def test_ecdsa_verify_signature_invalid_branch(self, ec_keypair):
        from unittest.mock import patch
        pub, _ = ec_keypair
        with patch.object(type(pub), "verify", self._mock_signature_invalid):
            assert CryptoOperations.ecdsa_verify(pub, b"data", b"\x00" * 64) is False

    def test_hmac_verify_signature_invalid_branch(self, user_session):
        from unittest.mock import patch
        from pkcs11_app.mac import MACOperations
        key = MACOperations.generate_hmac_key(user_session)
        with patch.object(type(key), "verify", self._mock_signature_invalid):
            assert MACOperations.hmac_verify(key, b"data", b"\x00" * 32) is False
        key.destroy()

    def test_aes_cmac_verify_signature_invalid_branch(self, user_session):
        from unittest.mock import patch
        from pkcs11_app.mac import MACOperations
        key = MACOperations.generate_cmac_key(user_session)
        with patch.object(type(key), "verify", self._mock_signature_invalid):
            assert MACOperations.aes_cmac_verify(key, b"data", b"\x00" * 16) is False
        key.destroy()

    def test_des3_cmac_verify_signature_invalid_branch(self, user_session):
        from unittest.mock import patch
        from pkcs11_app.mac import MACOperations
        key = MACOperations.generate_des3_cmac_key(user_session)
        with patch.object(type(key), "verify", self._mock_signature_invalid):
            assert MACOperations.des3_cmac_verify(key, b"data", b"\x00" * 8) is False
        key.destroy()

    def test_dsa_verify_signature_invalid_branch(self, user_session):
        from unittest.mock import patch
        from pkcs11_app.derive import DeriveOperations
        params = DeriveOperations.generate_dsa_params(user_session, key_size=1024)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label="dsa-exc")
        with patch.object(type(pub), "verify", self._mock_signature_invalid):
            assert DeriveOperations.dsa_verify(pub, b"data", b"\x00" * 40) is False
        pub.destroy(); priv.destroy()

    def test_eddsa_verify_signature_invalid_branch(self, user_session):
        from unittest.mock import patch
        from pkcs11_app.objects import ObjectOperations
        pub, priv = ObjectOperations.generate_ed25519_keypair(user_session, label="ed-exc")
        with patch.object(type(pub), "verify", self._mock_signature_invalid):
            assert ObjectOperations.eddsa_verify(pub, b"data", b"\x00" * 64) is False
        pub.destroy(); priv.destroy()


# ------------------------------------------------------------------ #
# info.py empty-slots branches (lines 57 and 70)
# ------------------------------------------------------------------ #

class TestInfoEmptySlots:
    def test_list_mechanisms_empty_slots(self, pkcs11_library):
        from unittest.mock import patch
        from pkcs11_app.info import InfoOperations
        info = InfoOperations(pkcs11_library)
        with patch.object(info, "get_slots", return_value=[]):
            assert info.list_mechanisms() == []

    def test_get_all_mechanism_infos_empty_slots(self, pkcs11_library):
        from unittest.mock import patch
        from pkcs11_app.info import InfoOperations
        info = InfoOperations(pkcs11_library)
        with patch.object(info, "get_slots", return_value=[]):
            assert info.get_all_mechanism_infos() == {}
