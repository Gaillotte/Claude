"""Tests for AES-GCM (authenticated encryption) and AES-CTR (stream cipher)."""

import os
import pytest
import pkcs11

from pkcs11_app.aead import AEADOperations


class TestAESGCM:
    def test_encrypt_decrypt_roundtrip(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        plaintext = b"GCM authenticated message"
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, plaintext)
        recovered = AEADOperations.aes_gcm_decrypt(key, ct, nonce)
        assert recovered == plaintext

    def test_with_explicit_nonce(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        nonce = os.urandom(12)
        ct, returned_nonce = AEADOperations.aes_gcm_encrypt(key, b"explicit nonce", nonce=nonce)
        assert returned_nonce == nonce
        recovered = AEADOperations.aes_gcm_decrypt(key, ct, nonce)
        assert recovered == b"explicit nonce"

    def test_with_aad(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        aad = b"additional authenticated data"
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"secret", aad=aad)
        recovered = AEADOperations.aes_gcm_decrypt(key, ct, nonce, aad=aad)
        assert recovered == b"secret"

    def test_ciphertext_includes_tag(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        plaintext = b"test"
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, plaintext, tag_bits=128)
        # Ciphertext should be plaintext + 16-byte tag
        assert len(ct) == len(plaintext) + 16

    def test_tag_bits_96(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"test", tag_bits=96)
        recovered = AEADOperations.aes_gcm_decrypt(key, ct, nonce, tag_bits=96)
        assert recovered == b"test"

    def test_empty_plaintext(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"")
        recovered = AEADOperations.aes_gcm_decrypt(key, ct, nonce)
        assert recovered == b""

    def test_large_plaintext(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        plaintext = os.urandom(1024 * 64)
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, plaintext)
        recovered = AEADOperations.aes_gcm_decrypt(key, ct, nonce)
        assert recovered == plaintext

    def test_wrong_nonce_raises(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"secret")
        wrong_nonce = os.urandom(12)
        with pytest.raises(pkcs11.PKCS11Error):
            AEADOperations.aes_gcm_decrypt(key, ct, wrong_nonce)

    def test_aes_128_gcm(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session, key_length=128, label="gcm-128")
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"AES-128 GCM test")
        assert AEADOperations.aes_gcm_decrypt(key, ct, nonce) == b"AES-128 GCM test"

    def test_different_nonces_produce_different_ciphertexts(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        plaintext = b"same plaintext"
        ct1, _ = AEADOperations.aes_gcm_encrypt(key, plaintext)
        ct2, _ = AEADOperations.aes_gcm_encrypt(key, plaintext)
        assert ct1 != ct2


class TestAESCTR:
    def test_encrypt_decrypt_roundtrip(self, user_session):
        key = AEADOperations.generate_ctr_key(user_session)
        plaintext = b"CTR mode test data"
        ct, nonce = AEADOperations.aes_ctr_encrypt(key, plaintext)
        recovered = AEADOperations.aes_ctr_decrypt(key, ct, nonce)
        assert recovered == plaintext

    def test_explicit_nonce(self, user_session):
        key = AEADOperations.generate_ctr_key(user_session)
        nonce = os.urandom(8)
        ct, returned_nonce = AEADOperations.aes_ctr_encrypt(key, b"explicit", nonce=nonce)
        assert returned_nonce == nonce
        assert AEADOperations.aes_ctr_decrypt(key, ct, nonce) == b"explicit"

    def test_ciphertext_same_length_as_plaintext(self, user_session):
        key = AEADOperations.generate_ctr_key(user_session)
        plaintext = b"CTR stream"
        ct, nonce = AEADOperations.aes_ctr_encrypt(key, plaintext)
        assert len(ct) == len(plaintext)

    def test_ctr_is_symmetric(self, user_session):
        """Encrypting ciphertext with same nonce decrypts it (XOR property)."""
        key = AEADOperations.generate_ctr_key(user_session)
        nonce = os.urandom(8)
        ct, _ = AEADOperations.aes_ctr_encrypt(key, b"test CTR XOR!!!!!", nonce=nonce)
        recovered = AEADOperations.aes_ctr_encrypt(key, ct, nonce=nonce)[0]
        assert recovered == b"test CTR XOR!!!!!"

    def test_large_data(self, user_session):
        key = AEADOperations.generate_ctr_key(user_session)
        plaintext = os.urandom(4096)
        ct, nonce = AEADOperations.aes_ctr_encrypt(key, plaintext)
        assert AEADOperations.aes_ctr_decrypt(key, ct, nonce) == plaintext

    def test_aes_128_ctr(self, user_session):
        key = AEADOperations.generate_ctr_key(user_session, key_length=128, label="ctr-128")
        ct, nonce = AEADOperations.aes_ctr_encrypt(key, b"AES-128 CTR")
        assert AEADOperations.aes_ctr_decrypt(key, ct, nonce) == b"AES-128 CTR"
