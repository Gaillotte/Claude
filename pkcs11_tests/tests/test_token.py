"""Tests for token management: key generation, object listing, destruction."""

import pytest
import pkcs11
from pkcs11 import ObjectClass, KeyType

from pkcs11_app.token import TokenManager
from pkcs11_app.session import SessionManager


class TestTokenInfo:
    def test_token_info_fields(self, token_manager: TokenManager):
        info = token_manager.get_token_info()
        assert "label" in info
        assert "manufacturer_id" in info
        assert "model" in info
        assert "serial" in info
        assert "flags" in info

    def test_token_label_matches_config(self, token_manager: TokenManager):
        info = token_manager.get_token_info()
        assert token_manager.library.config.token_label in info["label"]


class TestObjectListing:
    def test_list_objects_empty_session(self, user_session):
        objs = TokenManager.list_objects(user_session)
        assert isinstance(objs, list)

    def test_list_objects_by_class(self, user_session, aes_key):
        objs = TokenManager.list_objects(user_session, object_class=ObjectClass.SECRET_KEY)
        assert any(o[pkcs11.Attribute.LABEL] == "test-aes" for o in objs)

    def test_list_objects_by_label(self, user_session, aes_key):
        objs = TokenManager.list_objects(user_session, label="test-aes")
        assert len(objs) >= 1

    def test_find_object_found(self, user_session, aes_key):
        obj = TokenManager.find_object(user_session, ObjectClass.SECRET_KEY, "test-aes")
        assert obj is not None

    def test_find_object_not_found(self, user_session):
        obj = TokenManager.find_object(user_session, ObjectClass.SECRET_KEY, "__missing__")
        assert obj is None


class TestAESKeyGeneration:
    def test_generate_aes_256(self, user_session, token_manager: TokenManager):
        key = token_manager.generate_aes_key(user_session, 256, label="aes256-tmp", token=False)
        assert key is not None
        key.destroy()

    def test_generate_aes_128(self, user_session, token_manager: TokenManager):
        key = token_manager.generate_aes_key(user_session, 128, label="aes128-tmp", token=False)
        assert key is not None
        key.destroy()

    def test_generate_aes_192(self, user_session, token_manager: TokenManager):
        key = token_manager.generate_aes_key(user_session, 192, label="aes192-tmp", token=False)
        assert key is not None
        key.destroy()

    def test_aes_key_class(self, aes_key):
        assert aes_key[pkcs11.Attribute.CLASS] == ObjectClass.SECRET_KEY

    def test_aes_key_type(self, aes_key):
        assert aes_key[pkcs11.Attribute.KEY_TYPE] == KeyType.AES

    def test_aes_key_label(self, aes_key):
        assert aes_key[pkcs11.Attribute.LABEL] == "test-aes"


class TestDES3KeyGeneration:
    def test_generate_des3(self, user_session, token_manager: TokenManager):
        key = token_manager.generate_des3_key(user_session, label="des3-tmp", token=False)
        assert key is not None
        assert key[pkcs11.Attribute.KEY_TYPE] == KeyType.DES3
        key.destroy()


class TestRSAKeyGeneration:
    def test_generate_rsa_2048(self, rsa_keypair):
        pub, priv = rsa_keypair
        assert pub is not None
        assert priv is not None

    def test_rsa_public_key_class(self, rsa_keypair):
        pub, _ = rsa_keypair
        assert pub[pkcs11.Attribute.CLASS] == ObjectClass.PUBLIC_KEY

    def test_rsa_private_key_class(self, rsa_keypair):
        _, priv = rsa_keypair
        assert priv[pkcs11.Attribute.CLASS] == ObjectClass.PRIVATE_KEY

    def test_rsa_key_type(self, rsa_keypair):
        pub, priv = rsa_keypair
        assert pub[pkcs11.Attribute.KEY_TYPE] == KeyType.RSA
        assert priv[pkcs11.Attribute.KEY_TYPE] == KeyType.RSA

    def test_rsa_key_label(self, rsa_keypair):
        pub, _ = rsa_keypair
        assert pub[pkcs11.Attribute.LABEL] == "test-rsa"


class TestECKeyGeneration:
    def test_generate_ec_secp256r1(self, ec_keypair):
        pub, priv = ec_keypair
        assert pub is not None
        assert priv is not None

    def test_ec_public_key_class(self, ec_keypair):
        pub, _ = ec_keypair
        assert pub[pkcs11.Attribute.CLASS] == ObjectClass.PUBLIC_KEY

    def test_ec_private_key_class(self, ec_keypair):
        _, priv = ec_keypair
        assert priv[pkcs11.Attribute.CLASS] == ObjectClass.PRIVATE_KEY

    def test_ec_key_type(self, ec_keypair):
        pub, priv = ec_keypair
        assert pub[pkcs11.Attribute.KEY_TYPE] == KeyType.EC


class TestObjectDestruction:
    def test_destroy_object(self, user_session, token_manager: TokenManager):
        key = token_manager.generate_aes_key(user_session, 256, label="to-destroy", token=False)
        TokenManager.destroy_object(key)
        obj = TokenManager.find_object(user_session, ObjectClass.SECRET_KEY, "to-destroy")
        assert obj is None

    def test_destroy_all_objects(self, user_session, token_manager: TokenManager):
        for i in range(3):
            token_manager.generate_aes_key(user_session, 128, label=f"bulk-{i}", token=False)
        destroyed = TokenManager.destroy_all_objects(user_session)
        assert destroyed >= 3
        remaining = TokenManager.list_objects(user_session)
        assert len(remaining) == 0
