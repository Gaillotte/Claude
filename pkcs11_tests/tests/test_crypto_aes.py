"""Tests for AES symmetric cryptography operations."""

import os
import pytest

from pkcs11_app.crypto import CryptoOperations


class TestAESCBC:
    def test_encrypt_decrypt_roundtrip(self, aes_key, crypto: CryptoOperations):
        plaintext = b"Hello, PKCS11 World!"
        ciphertext, iv = crypto.aes_cbc_encrypt(aes_key, plaintext)
        recovered = crypto.aes_cbc_decrypt(aes_key, ciphertext, iv)
        assert recovered == plaintext

    def test_encrypt_with_explicit_iv(self, aes_key, crypto: CryptoOperations):
        iv = os.urandom(16)
        plaintext = b"Test with explicit IV"
        ciphertext, returned_iv = crypto.aes_cbc_encrypt(aes_key, plaintext, iv=iv)
        assert returned_iv == iv
        recovered = crypto.aes_cbc_decrypt(aes_key, ciphertext, iv)
        assert recovered == plaintext

    def test_ciphertext_differs_from_plaintext(self, aes_key, crypto: CryptoOperations):
        plaintext = b"SensitiveData1234"
        ciphertext, _ = crypto.aes_cbc_encrypt(aes_key, plaintext)
        assert ciphertext != plaintext

    def test_different_ivs_produce_different_ciphertexts(self, aes_key, crypto: CryptoOperations):
        plaintext = b"Same plaintext"
        ct1, _ = crypto.aes_cbc_encrypt(aes_key, plaintext, iv=os.urandom(16))
        ct2, _ = crypto.aes_cbc_encrypt(aes_key, plaintext, iv=os.urandom(16))
        assert ct1 != ct2

    def test_empty_plaintext(self, aes_key, crypto: CryptoOperations):
        plaintext = b""
        ciphertext, iv = crypto.aes_cbc_encrypt(aes_key, plaintext)
        recovered = crypto.aes_cbc_decrypt(aes_key, ciphertext, iv)
        assert recovered == plaintext

    def test_large_plaintext(self, aes_key, crypto: CryptoOperations):
        plaintext = os.urandom(1024 * 64)
        ciphertext, iv = crypto.aes_cbc_encrypt(aes_key, plaintext)
        recovered = crypto.aes_cbc_decrypt(aes_key, ciphertext, iv)
        assert recovered == plaintext

    def test_aes_128_encrypt_decrypt(self, aes_key_128, crypto: CryptoOperations):
        plaintext = b"AES-128 test data"
        ciphertext, iv = crypto.aes_cbc_encrypt(aes_key_128, plaintext)
        recovered = crypto.aes_cbc_decrypt(aes_key_128, ciphertext, iv)
        assert recovered == plaintext


class TestAESECB:
    def test_ecb_encrypt_decrypt(self, aes_key, crypto: CryptoOperations):
        plaintext = b"0123456789abcdef"  # exactly 16 bytes
        ciphertext = crypto.aes_ecb_encrypt(aes_key, plaintext)
        recovered = crypto.aes_ecb_decrypt(aes_key, ciphertext)
        assert recovered == plaintext

    def test_ecb_same_blocks_same_ciphertext(self, aes_key, crypto: CryptoOperations):
        block = b"A" * 16
        ct1 = crypto.aes_ecb_encrypt(aes_key, block)
        ct2 = crypto.aes_ecb_encrypt(aes_key, block)
        assert ct1 == ct2  # ECB is deterministic
