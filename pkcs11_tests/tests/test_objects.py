"""Tests for token object operations: data objects, key import, persistence, EdDSA, RSA-X509, AES-CBC(no pad), DES3-ECB."""

import os
import pytest
import pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType, Mechanism

from pkcs11_app.objects import ObjectOperations
from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.token import TokenManager


class TestDataObjects:
    def test_create_and_read(self, user_session):
        obj = ObjectOperations.create_data_object(user_session, label="test-data", data=b"hello")
        assert ObjectOperations.read_data_object(obj) == b"hello"
        obj.destroy()

    def test_label_attribute(self, user_session):
        obj = ObjectOperations.create_data_object(user_session, label="my-label", data=b"val")
        assert obj[Attribute.LABEL] == "my-label"
        obj.destroy()

    def test_class_is_data(self, user_session):
        obj = ObjectOperations.create_data_object(user_session, label="cls-data", data=b"x")
        assert obj[Attribute.CLASS] == ObjectClass.DATA
        obj.destroy()

    def test_binary_data(self, user_session):
        raw = os.urandom(256)
        obj = ObjectOperations.create_data_object(user_session, label="bin-data", data=raw)
        assert ObjectOperations.read_data_object(obj) == raw
        obj.destroy()

    def test_list_data_objects(self, user_session):
        obj = ObjectOperations.create_data_object(user_session, label="list-data", data=b"x")
        data_objs = TokenManager.list_objects(user_session, object_class=ObjectClass.DATA)
        assert any(o[Attribute.LABEL] == "list-data" for o in data_objs)
        obj.destroy()


class TestKeyImport:
    def test_import_aes_key(self, user_session):
        raw = os.urandom(32)
        key = ObjectOperations.import_aes_key(user_session, raw, label="imp-aes")
        assert key[Attribute.KEY_TYPE] == KeyType.AES
        assert key[Attribute.LABEL] == "imp-aes"
        key.destroy()

    def test_imported_key_encrypts(self, user_session):
        raw = os.urandom(32)
        key = ObjectOperations.import_aes_key(user_session, raw, label="imp-enc")
        crypto = CryptoOperations()
        plaintext = b"imported key data"
        ct, iv = crypto.aes_cbc_encrypt(key, plaintext)
        recovered = crypto.aes_cbc_decrypt(key, ct, iv)
        assert recovered == plaintext
        key.destroy()

    def test_import_same_key_twice_encrypts_same(self, user_session):
        raw = os.urandom(32)
        k1 = ObjectOperations.import_aes_key(user_session, raw, label="imp-k1")
        k2 = ObjectOperations.import_aes_key(user_session, raw, label="imp-k2")
        iv = os.urandom(16)
        ct1 = k1.encrypt(b"test data1234567", mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        ct2 = k2.encrypt(b"test data1234567", mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        assert ct1 == ct2
        k1.destroy(); k2.destroy()

    def test_import_generic_secret_key(self, user_session):
        raw = os.urandom(32)
        key = ObjectOperations.import_generic_secret_key(user_session, raw, label="imp-gen")
        assert key[Attribute.KEY_TYPE] == KeyType.GENERIC_SECRET
        key.destroy()


class TestTokenPersistence:
    def test_create_persistent_key(self, user_session):
        label = f"persist-{os.urandom(4).hex()}"
        key = ObjectOperations.create_persistent_aes_key(user_session, label=label)
        assert key[Attribute.TOKEN] is True
        key.destroy()

    def test_find_persistent_key(self, user_session):
        label = f"findme-{os.urandom(4).hex()}"
        key = ObjectOperations.create_persistent_aes_key(user_session, label=label)
        found = ObjectOperations.find_persistent_key(user_session, label)
        assert found is not None
        assert found[Attribute.LABEL] == label
        key.destroy()

    def test_find_nonexistent_returns_none(self, user_session):
        found = ObjectOperations.find_persistent_key(user_session, "__does_not_exist__")
        assert found is None

    def test_persistent_key_survives_session_reopen(self, session_manager):
        label = f"survive-{os.urandom(4).hex()}"
        with session_manager.open_user_session() as s1:
            key = ObjectOperations.create_persistent_aes_key(s1, label=label)
        with session_manager.open_user_session() as s2:
            found = ObjectOperations.find_persistent_key(s2, label)
            assert found is not None
            found.destroy()


class TestObjectCopy:
    def test_copy_data_object(self, user_session):
        original = ObjectOperations.create_data_object(user_session, label="orig", data=b"data")
        copy = ObjectOperations.copy_object(original, new_label="copy")
        assert copy[Attribute.LABEL] == "copy"
        assert ObjectOperations.read_data_object(copy) == b"data"
        original.destroy()
        copy.destroy()


class TestEdDSA:
    def test_ed25519_keypair_generation(self, user_session):
        pub, priv = ObjectOperations.generate_ed25519_keypair(user_session)
        assert pub is not None
        assert priv is not None
        pub.destroy(); priv.destroy()

    def test_ed25519_sign_verify(self, user_session):
        pub, priv = ObjectOperations.generate_ed25519_keypair(user_session, label="ed25519-sv")
        data = b"Ed25519 signature test"
        sig = ObjectOperations.eddsa_sign(priv, data)
        assert len(sig) == 64
        assert ObjectOperations.eddsa_verify(pub, data, sig) is True
        pub.destroy(); priv.destroy()

    def test_ed25519_verify_bad_signature(self, user_session):
        pub, priv = ObjectOperations.generate_ed25519_keypair(user_session, label="ed25519-bad")
        assert ObjectOperations.eddsa_verify(pub, b"data", b"\x00" * 4) is False
        pub.destroy(); priv.destroy()

    def test_ed25519_sign_large_data(self, user_session):
        pub, priv = ObjectOperations.generate_ed25519_keypair(user_session, label="ed25519-lg")
        data = os.urandom(10_000)
        sig = ObjectOperations.eddsa_sign(priv, data)
        assert ObjectOperations.eddsa_verify(pub, data, sig) is True
        pub.destroy(); priv.destroy()


class TestRSAX509:
    def test_rsa_x509_encrypt_decrypt(self, user_session, token_manager: TokenManager):
        import hashlib
        pub, priv = token_manager.generate_rsa_keypair(user_session, key_length=1024, label="rsa-x509", token=False)
        # RSA-X509 is raw RSA: input must be padded to key size (128 bytes for 1024-bit)
        data = hashlib.sha256(b"test").digest()
        padded = b"\x00" * (128 - len(data)) + data
        ct = ObjectOperations.rsa_raw_encrypt(pub, padded)
        pt = ObjectOperations.rsa_raw_decrypt(priv, ct)
        assert pt == padded
        pub.destroy(); priv.destroy()

    def test_rsa_x509_ciphertext_length(self, user_session, token_manager: TokenManager):
        import hashlib
        pub, priv = token_manager.generate_rsa_keypair(user_session, key_length=1024, label="rsa-x509-len", token=False)
        data = b"\x00" * 128
        ct = ObjectOperations.rsa_raw_encrypt(pub, data)
        assert len(ct) == 128
        pub.destroy(); priv.destroy()


class TestAESCBCNoPadding:
    def test_encrypt_decrypt(self, user_session, aes_key):
        iv = os.urandom(16)
        plaintext = b"0123456789abcdef"  # exactly 16 bytes
        ct = ObjectOperations.aes_cbc_nopad_encrypt(aes_key, plaintext, iv)
        pt = ObjectOperations.aes_cbc_nopad_decrypt(aes_key, ct, iv)
        assert pt == plaintext

    def test_ciphertext_same_length(self, user_session, aes_key):
        iv = os.urandom(16)
        plaintext = b"A" * 32
        ct = ObjectOperations.aes_cbc_nopad_encrypt(aes_key, plaintext, iv)
        assert len(ct) == 32

    def test_different_ivs_different_ciphertexts(self, user_session, aes_key):
        plaintext = b"same plaintext!!"
        ct1 = ObjectOperations.aes_cbc_nopad_encrypt(aes_key, plaintext, os.urandom(16))
        ct2 = ObjectOperations.aes_cbc_nopad_encrypt(aes_key, plaintext, os.urandom(16))
        assert ct1 != ct2


class TestDES3ECB:
    def test_des3_ecb_encrypt_decrypt(self, user_session):
        from pkcs11_app.token import TokenManager
        key = TokenManager.generate_des3_key(user_session, label="des3-ecb-t", token=False)
        plaintext = b"12345678"  # DES3-ECB block size = 8
        ct = ObjectOperations.des3_ecb_encrypt(key, plaintext)
        pt = ObjectOperations.des3_ecb_decrypt(key, ct)
        assert pt == plaintext
        key.destroy()

    def test_des3_ecb_deterministic(self, user_session):
        from pkcs11_app.token import TokenManager
        key = TokenManager.generate_des3_key(user_session, label="des3-ecb-d", token=False)
        block = b"ABCDEFGH"
        ct1 = ObjectOperations.des3_ecb_encrypt(key, block)
        ct2 = ObjectOperations.des3_ecb_encrypt(key, block)
        assert ct1 == ct2
        key.destroy()
