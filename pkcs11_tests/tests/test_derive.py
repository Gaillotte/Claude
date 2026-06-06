"""Tests for ECDH key agreement, DH key agreement, and DSA sign/verify."""

import os
import pytest
import pkcs11
from pkcs11 import Attribute

from pkcs11_app.derive import DeriveOperations
from pkcs11_app.crypto import CryptoOperations


class TestECDH:
    def test_ecdh_derive_produces_key(self, user_session):
        pub_a, priv_a = DeriveOperations.generate_ecdh_keypair(user_session, label="ecdh-a")
        pub_b, priv_b = DeriveOperations.generate_ecdh_keypair(user_session, label="ecdh-b")
        ec_point_b = pub_b[Attribute.EC_POINT]
        shared = DeriveOperations.ecdh_derive_aes_key(priv_a, ec_point_b)
        assert shared is not None
        for k in (pub_a, priv_a, pub_b, priv_b, shared):
            try: k.destroy()
            except Exception: pass

    def test_ecdh_shared_secret_usable_for_aes(self, user_session):
        pub_a, priv_a = DeriveOperations.generate_ecdh_keypair(user_session, label="ecdh-enc-a")
        pub_b, priv_b = DeriveOperations.generate_ecdh_keypair(user_session, label="ecdh-enc-b")
        shared_a = DeriveOperations.ecdh_derive_aes_key(priv_a, pub_b[Attribute.EC_POINT], label="sa")
        shared_b = DeriveOperations.ecdh_derive_aes_key(priv_b, pub_a[Attribute.EC_POINT], label="sb")
        # Both sides derive the same key material — verify by encrypt/decrypt
        crypto = CryptoOperations()
        plaintext = b"ECDH shared secret"
        ct, iv = crypto.aes_cbc_encrypt(shared_a, plaintext)
        recovered = crypto.aes_cbc_decrypt(shared_b, ct, iv)
        assert recovered == plaintext
        for k in (pub_a, priv_a, pub_b, priv_b, shared_a, shared_b):
            try: k.destroy()
            except Exception: pass

    def test_ecdh_secp384r1(self, user_session):
        pub_a, priv_a = DeriveOperations.generate_ecdh_keypair(user_session, curve_name="secp384r1", label="ecdh-384-a")
        pub_b, priv_b = DeriveOperations.generate_ecdh_keypair(user_session, curve_name="secp384r1", label="ecdh-384-b")
        shared = DeriveOperations.ecdh_derive_aes_key(priv_a, pub_b[Attribute.EC_POINT], key_length=256)
        assert shared is not None
        for k in (pub_a, priv_a, pub_b, priv_b, shared):
            try: k.destroy()
            except Exception: pass

    def test_ecdh_secp521r1(self, user_session):
        pub_a, priv_a = DeriveOperations.generate_ecdh_keypair(user_session, curve_name="secp521r1", label="ecdh-521-a")
        pub_b, priv_b = DeriveOperations.generate_ecdh_keypair(user_session, curve_name="secp521r1", label="ecdh-521-b")
        shared = DeriveOperations.ecdh_derive_aes_key(priv_a, pub_b[Attribute.EC_POINT], key_length=256)
        assert shared is not None
        for k in (pub_a, priv_a, pub_b, priv_b, shared):
            try: k.destroy()
            except Exception: pass

    def test_ecdh_keypair_has_derive_attribute(self, user_session):
        pub, priv = DeriveOperations.generate_ecdh_keypair(user_session, label="ecdh-attr")
        assert priv[Attribute.DERIVE] is True
        pub.destroy(); priv.destroy()


class TestDH:
    def test_dh_params_generation(self, user_session):
        params = DeriveOperations.generate_dh_params(user_session, key_size=512)
        assert params is not None

    def test_dh_keypair_generation(self, user_session):
        params = DeriveOperations.generate_dh_params(user_session, key_size=512)
        pub, priv = DeriveOperations.generate_dh_keypair(params, label="dh-pair")
        assert pub is not None
        assert priv is not None
        pub.destroy(); priv.destroy()

    def test_dh_derive_produces_secret(self, user_session):
        params = DeriveOperations.generate_dh_params(user_session, key_size=512)
        pub_a, priv_a = DeriveOperations.generate_dh_keypair(params, label="dh-a")
        pub_b, priv_b = DeriveOperations.generate_dh_keypair(params, label="dh-b")
        secret = DeriveOperations.dh_derive_secret(priv_a, pub_b[Attribute.VALUE])
        assert secret is not None
        for k in (pub_a, priv_a, pub_b, priv_b, secret):
            try: k.destroy()
            except Exception: pass

    def test_dh_shared_secrets_match(self, user_session):
        params = DeriveOperations.generate_dh_params(user_session, key_size=512)
        pub_a, priv_a = DeriveOperations.generate_dh_keypair(params, label="dh-match-a")
        pub_b, priv_b = DeriveOperations.generate_dh_keypair(params, label="dh-match-b")
        secret_a = DeriveOperations.dh_derive_secret(priv_a, pub_b[Attribute.VALUE], label="sa")
        secret_b = DeriveOperations.dh_derive_secret(priv_b, pub_a[Attribute.VALUE], label="sb")
        val_a = secret_a[Attribute.VALUE]
        val_b = secret_b[Attribute.VALUE]
        assert val_a == val_b
        for k in (pub_a, priv_a, pub_b, priv_b, secret_a, secret_b):
            try: k.destroy()
            except Exception: pass


class TestDSA:
    def test_dsa_params_generation(self, user_session):
        params = DeriveOperations.generate_dsa_params(user_session, key_size=1024)
        assert params is not None

    def test_dsa_keypair_generation(self, user_session):
        params = DeriveOperations.generate_dsa_params(user_session, key_size=1024)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label="dsa-pair")
        assert pub is not None
        assert priv is not None
        pub.destroy(); priv.destroy()

    def test_dsa_sign_verify_roundtrip(self, user_session):
        params = DeriveOperations.generate_dsa_params(user_session, key_size=1024)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label="dsa-sv")
        data = b"DSA signed message"
        sig = DeriveOperations.dsa_sign(priv, data)
        assert DeriveOperations.dsa_verify(pub, data, sig) is True
        pub.destroy(); priv.destroy()

    def test_dsa_verify_bad_signature_fails(self, user_session):
        params = DeriveOperations.generate_dsa_params(user_session, key_size=1024)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label="dsa-bad")
        assert DeriveOperations.dsa_verify(pub, b"data", b"\x00" * 40) is False
        pub.destroy(); priv.destroy()

    def test_dsa_sign_large_data(self, user_session):
        params = DeriveOperations.generate_dsa_params(user_session, key_size=1024)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label="dsa-large")
        data = os.urandom(10_000)
        sig = DeriveOperations.dsa_sign(priv, data)
        assert DeriveOperations.dsa_verify(pub, data, sig) is True
        pub.destroy(); priv.destroy()
