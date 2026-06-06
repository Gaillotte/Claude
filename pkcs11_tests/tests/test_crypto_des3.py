"""Tests for Triple-DES (3DES) cryptographic operations."""

import os
import pytest

from pkcs11_app.crypto import CryptoOperations


class TestDES3CBC:
    def test_encrypt_decrypt_roundtrip(self, des3_key, crypto: CryptoOperations):
        plaintext = b"DES3 secret data"
        ciphertext, iv = crypto.des3_cbc_encrypt(des3_key, plaintext)
        recovered = crypto.des3_cbc_decrypt(des3_key, ciphertext, iv)
        assert recovered == plaintext

    def test_explicit_iv(self, des3_key, crypto: CryptoOperations):
        iv = os.urandom(8)
        plaintext = b"Explicit IV test"
        ciphertext, returned_iv = crypto.des3_cbc_encrypt(des3_key, plaintext, iv=iv)
        assert returned_iv == iv
        recovered = crypto.des3_cbc_decrypt(des3_key, ciphertext, iv)
        assert recovered == plaintext

    def test_ciphertext_differs_from_plaintext(self, des3_key, crypto: CryptoOperations):
        plaintext = b"NotEncrypted!123"
        ciphertext, _ = crypto.des3_cbc_encrypt(des3_key, plaintext)
        assert ciphertext != plaintext

    def test_large_data(self, des3_key, crypto: CryptoOperations):
        plaintext = os.urandom(4096)
        ciphertext, iv = crypto.des3_cbc_encrypt(des3_key, plaintext)
        recovered = crypto.des3_cbc_decrypt(des3_key, ciphertext, iv)
        assert recovered == plaintext
