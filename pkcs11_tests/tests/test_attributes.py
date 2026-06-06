"""Tests for PKCS11 object attribute reading and searching."""

import pytest
import pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType

from pkcs11_app.token import TokenManager


class TestObjectAttributes:
    def test_aes_key_attributes(self, aes_key):
        assert aes_key[Attribute.CLASS] == ObjectClass.SECRET_KEY
        assert aes_key[Attribute.KEY_TYPE] == KeyType.AES
        assert aes_key[Attribute.LABEL] == "test-aes"
        assert aes_key[Attribute.ENCRYPT] is True
        assert aes_key[Attribute.DECRYPT] is True

    def test_rsa_public_key_attributes(self, rsa_keypair):
        pub, _ = rsa_keypair
        assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
        assert pub[Attribute.KEY_TYPE] == KeyType.RSA
        assert pub[Attribute.ENCRYPT] is True
        assert pub[Attribute.VERIFY] is True

    def test_rsa_private_key_sensitive(self, rsa_keypair):
        _, priv = rsa_keypair
        assert priv[Attribute.SENSITIVE] is True
        assert priv[Attribute.EXTRACTABLE] is False

    def test_ec_public_key_attributes(self, ec_keypair):
        pub, _ = ec_keypair
        assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
        assert pub[Attribute.KEY_TYPE] == KeyType.EC
        assert pub[Attribute.VERIFY] is True

    def test_ec_private_key_attributes(self, ec_keypair):
        _, priv = ec_keypair
        assert priv[Attribute.SIGN] is True
        assert priv[Attribute.SENSITIVE] is True

    def test_list_objects_filters_by_class(self, user_session, aes_key, rsa_keypair):
        secret_keys = TokenManager.list_objects(user_session, object_class=ObjectClass.SECRET_KEY)
        pub_keys = TokenManager.list_objects(user_session, object_class=ObjectClass.PUBLIC_KEY)
        priv_keys = TokenManager.list_objects(user_session, object_class=ObjectClass.PRIVATE_KEY)

        secret_classes = {k[Attribute.CLASS] for k in secret_keys}
        pub_classes = {k[Attribute.CLASS] for k in pub_keys}
        priv_classes = {k[Attribute.CLASS] for k in priv_keys}

        if secret_classes:
            assert secret_classes == {ObjectClass.SECRET_KEY}
        if pub_classes:
            assert pub_classes == {ObjectClass.PUBLIC_KEY}
        if priv_classes:
            assert priv_classes == {ObjectClass.PRIVATE_KEY}
