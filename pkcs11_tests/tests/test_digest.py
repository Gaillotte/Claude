"""Tests for PKCS11 digest (hash) operations."""

import hashlib
import pytest
import pkcs11
from pkcs11 import Mechanism

from pkcs11_app.crypto import CryptoOperations


class TestDigest:
    def test_sha1(self, user_session, crypto: CryptoOperations):
        data = b"Hello"
        result = crypto.digest(user_session, data, Mechanism.SHA_1)
        expected = hashlib.sha1(data).digest()
        assert result == expected

    def test_sha256(self, user_session, crypto: CryptoOperations):
        data = b"Hello"
        result = crypto.digest(user_session, data, Mechanism.SHA256)
        expected = hashlib.sha256(data).digest()
        assert result == expected

    def test_sha384(self, user_session, crypto: CryptoOperations):
        data = b"Hello"
        result = crypto.digest(user_session, data, Mechanism.SHA384)
        expected = hashlib.sha384(data).digest()
        assert result == expected

    def test_sha512(self, user_session, crypto: CryptoOperations):
        data = b"Hello"
        result = crypto.digest(user_session, data, Mechanism.SHA512)
        expected = hashlib.sha512(data).digest()
        assert result == expected

    def test_sha256_default(self, user_session, crypto: CryptoOperations):
        data = b"default mechanism"
        result = crypto.digest(user_session, data)
        expected = hashlib.sha256(data).digest()
        assert result == expected

    def test_empty_input(self, user_session, crypto: CryptoOperations):
        result = crypto.digest(user_session, b"", Mechanism.SHA256)
        expected = hashlib.sha256(b"").digest()
        assert result == expected

    def test_large_input(self, user_session, crypto: CryptoOperations):
        import os
        data = os.urandom(1024 * 256)
        result = crypto.digest(user_session, data, Mechanism.SHA256)
        expected = hashlib.sha256(data).digest()
        assert result == expected

    def test_sha256_length(self, user_session, crypto: CryptoOperations):
        result = crypto.digest(user_session, b"test", Mechanism.SHA256)
        assert len(result) == 32

    def test_sha512_length(self, user_session, crypto: CryptoOperations):
        result = crypto.digest(user_session, b"test", Mechanism.SHA512)
        assert len(result) == 64
