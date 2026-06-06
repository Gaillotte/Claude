"""Tests for HMAC (all SHA variants), AES-CMAC, DES3-CMAC."""

import os
import pytest
import pkcs11
from pkcs11 import Mechanism, Attribute

from pkcs11_app.mac import MACOperations


class TestHMAC:
    @pytest.mark.parametrize("mech,expected_len", [
        (Mechanism.SHA_1_HMAC, 20),
        (Mechanism.SHA224_HMAC, 28),
        (Mechanism.SHA256_HMAC, 32),
        (Mechanism.SHA384_HMAC, 48),
        (Mechanism.SHA512_HMAC, 64),
    ])
    def test_hmac_sign_verify(self, user_session, mech, expected_len):
        key = MACOperations.generate_hmac_key(user_session, mechanism=mech)
        mac = MACOperations.hmac_sign(key, b"test data", mechanism=mech)
        assert len(mac) == expected_len
        assert MACOperations.hmac_verify(key, b"test data", mac, mechanism=mech) is True
        key.destroy()

    def test_hmac_wrong_data_fails(self, user_session):
        key = MACOperations.generate_hmac_key(user_session)
        mac = MACOperations.hmac_sign(key, b"original")
        assert MACOperations.hmac_verify(key, b"tampered", mac) is False
        key.destroy()

    def test_hmac_wrong_mac_fails(self, user_session):
        key = MACOperations.generate_hmac_key(user_session)
        assert MACOperations.hmac_verify(key, b"data", b"\x00" * 32) is False
        key.destroy()

    def test_hmac_default_is_sha256(self, user_session):
        key = MACOperations.generate_hmac_key(user_session)
        mac = MACOperations.hmac_sign(key, b"test")
        assert len(mac) == 32
        key.destroy()

    def test_hmac_label(self, user_session):
        key = MACOperations.generate_hmac_key(user_session, label="my-hmac")
        assert key[Attribute.LABEL] == "my-hmac"
        key.destroy()

    def test_hmac_large_data(self, user_session):
        key = MACOperations.generate_hmac_key(user_session)
        data = os.urandom(64 * 1024)
        mac = MACOperations.hmac_sign(key, data)
        assert MACOperations.hmac_verify(key, data, mac) is True
        key.destroy()

    def test_hmac_empty_data(self, user_session):
        key = MACOperations.generate_hmac_key(user_session)
        mac = MACOperations.hmac_sign(key, b"")
        assert len(mac) == 32
        assert MACOperations.hmac_verify(key, b"", mac) is True
        key.destroy()

    def test_hmac_sign_returns_bytes(self, user_session):
        key = MACOperations.generate_hmac_key(user_session)
        mac = MACOperations.hmac_sign(key, b"static test")
        assert isinstance(mac, bytes)
        key.destroy()

    def test_hmac_verify_bad_length(self, user_session):
        key = MACOperations.generate_hmac_key(user_session)
        assert MACOperations.hmac_verify(key, b"data", b"\x00" * 4) is False
        key.destroy()


class TestAESCMAC:
    def test_cmac_sign_verify(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        mac = MACOperations.aes_cmac_sign(key, b"hello cmac")
        assert len(mac) == 16
        assert MACOperations.aes_cmac_verify(key, b"hello cmac", mac) is True

    def test_cmac_wrong_data_fails(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        mac = MACOperations.aes_cmac_sign(key, b"original")
        assert MACOperations.aes_cmac_verify(key, b"tampered", mac) is False

    def test_cmac_128_key(self, user_session):
        key = MACOperations.generate_cmac_key(user_session, key_length=128)
        mac = MACOperations.aes_cmac_sign(key, b"test 128")
        assert MACOperations.aes_cmac_verify(key, b"test 128", mac) is True

    def test_cmac_256_key(self, user_session):
        key = MACOperations.generate_cmac_key(user_session, key_length=256, label="cmac-256")
        mac = MACOperations.aes_cmac_sign(key, b"test 256")
        assert len(mac) == 16
        assert MACOperations.aes_cmac_verify(key, b"test 256", mac) is True

    def test_cmac_empty_data(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        mac = MACOperations.aes_cmac_sign(key, b"")
        assert isinstance(mac, bytes)

    def test_cmac_bad_mac_fails(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        assert MACOperations.aes_cmac_verify(key, b"data", b"\x00" * 16) is False

    def test_cmac_large_data(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        data = os.urandom(32 * 1024)
        mac = MACOperations.aes_cmac_sign(key, data)
        assert MACOperations.aes_cmac_verify(key, data, mac) is True


class TestDES3CMAC:
    def test_des3_cmac_sign_verify(self, user_session):
        key = MACOperations.generate_des3_cmac_key(user_session)
        mac = MACOperations.des3_cmac_sign(key, b"hello des3 cmac")
        assert len(mac) == 8
        assert MACOperations.des3_cmac_verify(key, b"hello des3 cmac", mac) is True

    def test_des3_cmac_wrong_data_fails(self, user_session):
        key = MACOperations.generate_des3_cmac_key(user_session)
        mac = MACOperations.des3_cmac_sign(key, b"original")
        assert MACOperations.des3_cmac_verify(key, b"tampered", mac) is False

    def test_des3_cmac_bad_mac_fails(self, user_session):
        key = MACOperations.generate_des3_cmac_key(user_session)
        assert MACOperations.des3_cmac_verify(key, b"data", b"\x00" * 8) is False

    def test_des3_cmac_large_data(self, user_session):
        key = MACOperations.generate_des3_cmac_key(user_session)
        data = os.urandom(8 * 1024)
        mac = MACOperations.des3_cmac_sign(key, data)
        assert MACOperations.des3_cmac_verify(key, data, mac) is True
