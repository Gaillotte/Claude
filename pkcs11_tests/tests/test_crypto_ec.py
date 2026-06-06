"""Tests for ECDSA sign/verify operations."""

import os
import pytest

from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.token import TokenManager


class TestECDSA:
    def test_sign_verify_roundtrip(self, ec_keypair, crypto: CryptoOperations):
        pub, priv = ec_keypair
        data = b"EC signed data"
        signature = crypto.ecdsa_sign(priv, data)
        assert crypto.ecdsa_verify(pub, data, signature) is True

    def test_verify_bad_signature(self, ec_keypair, crypto: CryptoOperations):
        """All-zero (wrong-length) digest causes rejection at the PKCS11 layer."""
        import hashlib
        pub, priv = ec_keypair
        data = b"some data"
        signature = crypto.ecdsa_sign(priv, data)
        # Truncated signature is clearly invalid
        assert crypto.ecdsa_verify(pub, data, b"\x00" * 4) is False

    def test_sign_large_data(self, ec_keypair, crypto: CryptoOperations):
        pub, priv = ec_keypair
        data = os.urandom(10_000)
        signature = crypto.ecdsa_sign(priv, data)
        assert crypto.ecdsa_verify(pub, data, signature) is True

    def test_different_curves(self, user_session, token_manager: TokenManager, crypto: CryptoOperations):
        from pkcs11.util.ec import encode_named_curve_parameters
        for curve_name in ("secp256r1", "secp384r1", "secp521r1"):
            curve = encode_named_curve_parameters(curve_name)
            pub, priv = token_manager.generate_ec_keypair(
                user_session, curve=curve, label=f"ec-{curve_name}", token=False
            )
            data = f"Test with {curve_name}".encode()
            sig = crypto.ecdsa_sign(priv, data)
            assert crypto.ecdsa_verify(pub, data, sig) is True
            pub.destroy()
            priv.destroy()
