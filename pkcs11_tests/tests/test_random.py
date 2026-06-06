"""Tests for PKCS11 random number generation."""

import pytest
from pkcs11_app.crypto import CryptoOperations


class TestRandom:
    def test_generate_random_bytes(self, user_session, crypto: CryptoOperations):
        data = crypto.generate_random(user_session, 32)
        assert isinstance(data, bytes)
        assert len(data) == 32

    def test_different_calls_differ(self, user_session, crypto: CryptoOperations):
        r1 = crypto.generate_random(user_session, 32)
        r2 = crypto.generate_random(user_session, 32)
        assert r1 != r2  # astronomically unlikely to be equal

    def test_various_lengths(self, user_session, crypto: CryptoOperations):
        for length in (1, 8, 16, 32, 64, 128, 256, 512, 1024):
            data = crypto.generate_random(user_session, length)
            assert len(data) == length

    def test_random_not_all_zeros(self, user_session, crypto: CryptoOperations):
        data = crypto.generate_random(user_session, 64)
        assert data != b"\x00" * 64
