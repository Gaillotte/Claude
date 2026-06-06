"""Deep edge-case tests for MAC operations.

Covers: HMAC key isolation, CMAC truncation detection,
MAC-then-encrypt ordering, all boundary data sizes,
HMAC reference vectors (RFC 4231).
"""

import os
import hmac
import hashlib
import pytest
import pkcs11
from pkcs11 import Mechanism, Attribute

from pkcs11_app.mac import MACOperations


class TestHMACReferenceVectors:
    """Cross-check PKCS11 HMAC output against Python's hmac module (RFC 4231)."""

    @pytest.mark.parametrize("hash_name,mech,ksize", [
        ("sha1",   Mechanism.SHA_1_HMAC,   160),
        ("sha256", Mechanism.SHA256_HMAC,  256),
        ("sha384", Mechanism.SHA384_HMAC,  384),
        ("sha512", Mechanism.SHA512_HMAC,  512),
    ])
    def test_hmac_matches_reference(self, user_session, hash_name, mech, ksize):
        raw_key = os.urandom(ksize // 8)
        key = user_session.create_object({
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.GENERIC_SECRET,
            pkcs11.Attribute.VALUE: raw_key,
            pkcs11.Attribute.SIGN: True,
            pkcs11.Attribute.VERIFY: True,
            pkcs11.Attribute.TOKEN: False,
            pkcs11.Attribute.SENSITIVE: False,
            pkcs11.Attribute.EXTRACTABLE: True,
        })
        data = os.urandom(128)
        pkcs11_mac = MACOperations.hmac_sign(key, data, mechanism=mech)
        ref_mac = hmac.new(raw_key, data, hash_name).digest()
        assert pkcs11_mac == ref_mac
        key.destroy()


class TestHMACKeyIsolation:
    def test_different_keys_different_macs(self, user_session):
        k1 = MACOperations.generate_hmac_key(user_session, label="mac-iso-1")
        k2 = MACOperations.generate_hmac_key(user_session, label="mac-iso-2")
        data = b"same data"
        mac1 = MACOperations.hmac_sign(k1, data)
        mac2 = MACOperations.hmac_sign(k2, data)
        assert mac1 != mac2
        k1.destroy(); k2.destroy()

    def test_mac_cross_key_verification_fails(self, user_session):
        k1 = MACOperations.generate_hmac_key(user_session, label="mac-cross-1")
        k2 = MACOperations.generate_hmac_key(user_session, label="mac-cross-2")
        data = b"data"
        mac_from_k1 = MACOperations.hmac_sign(k1, data)
        assert MACOperations.hmac_verify(k2, data, mac_from_k1) is False
        k1.destroy(); k2.destroy()


class TestCMACDataSizes:
    @pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 64, 256, 1024])
    def test_aes_cmac_all_lengths(self, user_session, length):
        key = MACOperations.generate_cmac_key(user_session, label=f"cmac-{length}")
        data = os.urandom(length)
        mac = MACOperations.aes_cmac_sign(key, data)
        assert len(mac) == 16
        assert MACOperations.aes_cmac_verify(key, data, mac) is True
        key.destroy()

    def test_cmac_single_bit_flip_detected(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        data = os.urandom(64)
        mac = MACOperations.aes_cmac_sign(key, data)
        tampered = bytearray(data)
        tampered[0] ^= 0x01
        assert MACOperations.aes_cmac_verify(key, bytes(tampered), mac) is False
        key.destroy()

    def test_cmac_appended_byte_detected(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        data = os.urandom(32)
        mac = MACOperations.aes_cmac_sign(key, data)
        assert MACOperations.aes_cmac_verify(key, data + b"\x00", mac) is False
        key.destroy()

    def test_cmac_truncated_data_detected(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        data = os.urandom(32)
        mac = MACOperations.aes_cmac_sign(key, data)
        assert MACOperations.aes_cmac_verify(key, data[:-1], mac) is False
        key.destroy()

    def test_cmac_mac_truncation_detected(self, user_session):
        key = MACOperations.generate_cmac_key(user_session)
        data = os.urandom(32)
        mac = MACOperations.aes_cmac_sign(key, data)
        assert MACOperations.aes_cmac_verify(key, data, mac[:-1]) is False
        key.destroy()


class TestDES3CMACDepth:
    @pytest.mark.parametrize("length", [0, 1, 7, 8, 9, 64, 512])
    def test_des3_cmac_all_lengths(self, user_session, length):
        key = MACOperations.generate_des3_cmac_key(user_session, label=f"d3cmac-{length}")
        data = os.urandom(length)
        mac = MACOperations.des3_cmac_sign(key, data)
        assert len(mac) == 8
        assert MACOperations.des3_cmac_verify(key, data, mac) is True
        key.destroy()


class TestMACThenEncrypt:
    """MAC-then-encrypt pattern: integrity check survives encryption."""

    def test_mac_then_encrypt_aes_cbc(self, user_session, token_manager):
        from pkcs11_app.crypto import CryptoOperations

        mac_key = MACOperations.generate_hmac_key(user_session, label="mac-enc-mac")
        enc_key = token_manager.generate_aes_key(user_session, 256, label="mac-enc-enc", token=False)
        crypto = CryptoOperations()

        plaintext = b"Sensitive payload"
        mac = MACOperations.hmac_sign(mac_key, plaintext)
        payload = plaintext + mac  # MAC appended

        ct, iv = crypto.aes_cbc_encrypt(enc_key, payload)

        # Decrypt and verify MAC
        decrypted = crypto.aes_cbc_decrypt(enc_key, ct, iv)
        recovered_plain = decrypted[:len(plaintext)]
        recovered_mac   = decrypted[len(plaintext):]

        assert recovered_plain == plaintext
        assert MACOperations.hmac_verify(mac_key, recovered_plain, recovered_mac) is True

        mac_key.destroy(); enc_key.destroy()
