"""Tests for RSA cryptographic operations: encrypt/decrypt, sign/verify, PSS."""

import os
import pytest
import pkcs11

from pkcs11_app.crypto import CryptoOperations


class TestRSAPKCS1:
    def test_encrypt_decrypt_roundtrip(self, rsa_keypair, crypto: CryptoOperations):
        pub, priv = rsa_keypair
        plaintext = b"RSA secret message"
        ciphertext = crypto.rsa_encrypt(pub, plaintext)
        recovered = crypto.rsa_decrypt(priv, ciphertext)
        assert recovered == plaintext

    def test_ciphertext_differs_from_plaintext(self, rsa_keypair, crypto: CryptoOperations):
        pub, _ = rsa_keypair
        plaintext = b"Test RSA plaintext"
        ciphertext = crypto.rsa_encrypt(pub, plaintext)
        assert ciphertext != plaintext

    def test_ciphertext_length(self, rsa_keypair, crypto: CryptoOperations):
        pub, _ = rsa_keypair
        ciphertext = crypto.rsa_encrypt(pub, b"short")
        assert len(ciphertext) == 256  # 2048-bit RSA = 256 bytes

    def test_sign_verify_roundtrip(self, rsa_keypair, crypto: CryptoOperations):
        pub, priv = rsa_keypair
        data = b"Document to sign"
        signature = crypto.rsa_sign(priv, data)
        assert crypto.rsa_verify(pub, data, signature) is True

    def test_verify_wrong_signature_fails(self, rsa_keypair, crypto: CryptoOperations):
        """All-zero signature must be rejected."""
        pub, _ = rsa_keypair
        assert crypto.rsa_verify(pub, b"some data", b"\x00" * 256) is False

    def test_sign_large_data(self, rsa_keypair, crypto: CryptoOperations):
        pub, priv = rsa_keypair
        data = os.urandom(10_000)
        signature = crypto.rsa_sign(priv, data)
        assert crypto.rsa_verify(pub, data, signature) is True


class TestRSAOAEP:
    def test_oaep_encrypt_decrypt(self, rsa_keypair, crypto: CryptoOperations):
        pub, priv = rsa_keypair
        plaintext = b"OAEP padded message"
        ciphertext = crypto.rsa_oaep_encrypt(pub, plaintext)
        recovered = crypto.rsa_oaep_decrypt(priv, ciphertext)
        assert recovered == plaintext

    def test_oaep_ciphertext_length(self, rsa_keypair, crypto: CryptoOperations):
        pub, _ = rsa_keypair
        ciphertext = crypto.rsa_oaep_encrypt(pub, b"data")
        assert len(ciphertext) == 256


class TestRSAPSS:
    def test_pss_sign_verify(self, rsa_keypair, crypto: CryptoOperations):
        pub, priv = rsa_keypair
        data = b"PSS signed document"
        signature = crypto.rsa_pss_sign(priv, data)
        assert crypto.rsa_pss_verify(pub, data, signature) is True

    def test_pss_verify_bad_signature(self, rsa_keypair, crypto: CryptoOperations):
        """All-zero signature must be rejected by PSS verify."""
        pub, _ = rsa_keypair
        assert crypto.rsa_pss_verify(pub, b"some data", b"\x00" * 256) is False

    def test_pss_sign_large_data(self, rsa_keypair, crypto: CryptoOperations):
        pub, priv = rsa_keypair
        data = os.urandom(50_000)
        signature = crypto.rsa_pss_sign(priv, data)
        assert crypto.rsa_pss_verify(pub, data, signature) is True
