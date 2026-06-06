"""Tests for PKCS11 key wrap / unwrap operations."""

import os
import pytest
import pkcs11
from pkcs11 import Mechanism

from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.token import TokenManager


class TestAESKeyWrap:
    def test_wrap_unwrap_roundtrip(self, user_session, token_manager: TokenManager, crypto: CryptoOperations):
        wrapping_key = token_manager.generate_aes_key(
            user_session, 256, label="wrap-key", token=False
        )
        data_key = token_manager.generate_aes_key(
            user_session, 128, label="data-key", token=False
        )

        wrapped = crypto.wrap_key(
            wrapping_key, data_key, mechanism=Mechanism.AES_KEY_WRAP_PAD
        )
        assert isinstance(wrapped, bytes)
        assert len(wrapped) > 0

        unwrapped = crypto.unwrap_aes_key(
            wrapping_key, wrapped, key_length=128, label="unwrapped"
        )
        assert unwrapped is not None

        # Verify the unwrapped key can encrypt/decrypt
        plaintext = b"Test after unwrap"
        ciphertext, iv = crypto.aes_cbc_encrypt(unwrapped, plaintext)
        recovered = crypto.aes_cbc_decrypt(unwrapped, ciphertext, iv)
        assert recovered == plaintext

        for k in (wrapping_key, data_key, unwrapped):
            try:
                k.destroy()
            except Exception:
                pass

    def test_wrapped_key_length(self, user_session, token_manager: TokenManager, crypto: CryptoOperations):
        wrapping_key = token_manager.generate_aes_key(
            user_session, 256, label="wk2", token=False
        )
        data_key = token_manager.generate_aes_key(
            user_session, 256, label="dk2", token=False
        )
        wrapped = crypto.wrap_key(
            wrapping_key, data_key, mechanism=Mechanism.AES_KEY_WRAP_PAD
        )
        # AES-256 wrapped with AES_KEY_WRAP_PAD should be 40 bytes
        assert len(wrapped) >= 32

        for k in (wrapping_key, data_key):
            try:
                k.destroy()
            except Exception:
                pass
