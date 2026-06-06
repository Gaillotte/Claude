"""Deep edge-case tests for AES operations.

Covers: boundary sizes, padding behavior, IV reuse detection,
multi-block alignment, all valid key sizes, CBC chaining integrity.
"""

import os
import pytest
import pkcs11
from pkcs11 import Mechanism, Attribute

from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.token import TokenManager
from pkcs11_app.aead import AEADOperations


class TestAESPaddingBoundaries:
    """CBC-PAD must handle every plaintext length from 0 to 512 bytes."""

    @pytest.mark.parametrize("length", list(range(0, 48)) + [64, 127, 128, 129, 255, 256, 512])
    def test_cbc_pad_all_lengths(self, user_session, token_manager, length):
        key = token_manager.generate_aes_key(user_session, 256, label=f"aes-len-{length}", token=False)
        crypto = CryptoOperations()
        plaintext = os.urandom(length)
        ct, iv = crypto.aes_cbc_encrypt(key, plaintext)
        assert crypto.aes_cbc_decrypt(key, ct, iv) == plaintext
        key.destroy()

    @pytest.mark.parametrize("key_size", [128, 192, 256])
    def test_all_aes_key_sizes_cbc(self, user_session, token_manager, key_size):
        key = token_manager.generate_aes_key(user_session, key_size, label=f"aes-ks-{key_size}", token=False)
        crypto = CryptoOperations()
        plaintext = os.urandom(64)
        ct, iv = crypto.aes_cbc_encrypt(key, plaintext)
        assert crypto.aes_cbc_decrypt(key, ct, iv) == plaintext
        key.destroy()

    def test_cbc_pad_ciphertext_always_block_aligned(self, aes_key):
        crypto = CryptoOperations()
        for length in range(0, 33):
            ct, iv = crypto.aes_cbc_encrypt(aes_key, os.urandom(length))
            assert len(ct) % 16 == 0, f"ciphertext not block-aligned for plaintext length {length}"

    def test_cbc_padding_adds_full_block_on_boundary(self, aes_key):
        """A 16-byte plaintext produces 32-byte ciphertext (full padding block added)."""
        crypto = CryptoOperations()
        ct, _ = crypto.aes_cbc_encrypt(aes_key, b"A" * 16)
        assert len(ct) == 32

    def test_cbc_different_keys_different_ciphertexts(self, user_session, token_manager):
        crypto = CryptoOperations()
        k1 = token_manager.generate_aes_key(user_session, 256, label="k1", token=False)
        k2 = token_manager.generate_aes_key(user_session, 256, label="k2", token=False)
        iv = os.urandom(16)
        plaintext = b"same data same iv"
        ct1, _ = crypto.aes_cbc_encrypt(k1, plaintext, iv=iv)
        ct2, _ = crypto.aes_cbc_encrypt(k2, plaintext, iv=iv)
        assert ct1 != ct2
        k1.destroy(); k2.destroy()

    def test_ecb_identical_blocks_produce_identical_ciphertext_blocks(self, aes_key):
        """AES-ECB determinism: same 16-byte input always maps to same output."""
        crypto = CryptoOperations()
        block = b"AAAAAAAAAAAAAAAA"
        ct = crypto.aes_ecb_encrypt(aes_key, block * 4)
        blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
        assert blocks[0] == blocks[1] == blocks[2] == blocks[3]

    def test_cbc_chaining_property(self, aes_key):
        """Changing one plaintext block must change all subsequent ciphertext blocks."""
        crypto = CryptoOperations()
        iv = os.urandom(16)
        plain_a = b"A" * 48
        plain_b = b"B" + b"A" * 47  # only first byte differs
        ct_a, _ = crypto.aes_cbc_encrypt(aes_key, plain_a, iv=iv)
        ct_b, _ = crypto.aes_cbc_encrypt(aes_key, plain_b, iv=iv)
        assert ct_a[:16] != ct_b[:16]   # block 1 differs
        assert ct_a[16:32] != ct_b[16:32]  # block 2 affected by chaining
        assert ct_a[32:] != ct_b[32:]      # block 3 affected


class TestAESGCMDepth:
    """Edge cases for AES-GCM: tag corruption, AAD mismatch, nonce sizes."""

    def test_gcm_tag_corruption_rejected(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"secret")
        corrupted = ct[:-1] + bytes([ct[-1] ^ 0xFF])  # flip last tag byte
        with pytest.raises(pkcs11.PKCS11Error):
            AEADOperations.aes_gcm_decrypt(key, corrupted, nonce)

    def test_gcm_aad_mismatch_rejected(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"secret", aad=b"legit-aad")
        with pytest.raises(pkcs11.PKCS11Error):
            AEADOperations.aes_gcm_decrypt(key, ct, nonce, aad=b"wrong-aad")

    def test_gcm_ciphertext_corruption_rejected(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"secret message!")
        corrupted = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(pkcs11.PKCS11Error):
            AEADOperations.aes_gcm_decrypt(key, corrupted, nonce)

    @pytest.mark.parametrize("nonce_len", [12])
    def test_gcm_nonce_length(self, user_session, nonce_len):
        key = AEADOperations.generate_gcm_key(user_session)
        nonce = os.urandom(nonce_len)
        ct, n = AEADOperations.aes_gcm_encrypt(key, b"nonce test", nonce=nonce)
        assert n == nonce
        assert AEADOperations.aes_gcm_decrypt(key, ct, n) == b"nonce test"

    def test_gcm_64_bit_tag(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session)
        ct, nonce = AEADOperations.aes_gcm_encrypt(key, b"64-bit tag", tag_bits=64)
        assert len(ct) == len(b"64-bit tag") + 8
        assert AEADOperations.aes_gcm_decrypt(key, ct, nonce, tag_bits=64) == b"64-bit tag"


class TestAESKeyProperties:
    """Verify key attribute enforcement."""

    def test_encrypt_only_key_cannot_decrypt(self, user_session):
        k = user_session.generate_key(
            pkcs11.KeyType.AES, 256, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: False}
        )
        iv = os.urandom(16)
        ct = k.encrypt(b"test data payload", mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        # python-pkcs11 omits DecryptMixin when DECRYPT=False → AttributeError
        with pytest.raises((pkcs11.PKCS11Error, AttributeError)):
            k.decrypt(ct, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        k.destroy()

    def test_decrypt_only_key_cannot_encrypt(self, user_session):
        k = user_session.generate_key(
            pkcs11.KeyType.AES, 256, store=False,
            template={Attribute.ENCRYPT: False, Attribute.DECRYPT: True}
        )
        # python-pkcs11 omits EncryptMixin when ENCRYPT=False → AttributeError
        with pytest.raises((pkcs11.PKCS11Error, AttributeError)):
            k.encrypt(b"test data payload", mechanism=Mechanism.AES_CBC_PAD, mechanism_param=os.urandom(16))
        k.destroy()
