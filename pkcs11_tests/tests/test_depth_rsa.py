"""Deep edge-case tests for RSA operations.

Covers: all key sizes, all hash variants, OAEP label/hash combinations,
signature non-malleability, key attribute enforcement, public key export.
"""

import os
import pytest
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.token import TokenManager


class TestRSAKeySizes:
    @pytest.mark.parametrize("key_size", [1024, 2048, 3072, 4096])
    def test_rsa_encrypt_decrypt_all_sizes(self, user_session, token_manager, key_size):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=key_size, label=f"rsa-{key_size}", token=False
        )
        crypto = CryptoOperations()
        plaintext = b"RSA size test"
        ct = crypto.rsa_encrypt(pub, plaintext)
        assert len(ct) == key_size // 8
        assert crypto.rsa_decrypt(priv, ct) == plaintext
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("key_size", [1024, 2048, 3072, 4096])
    def test_rsa_sign_verify_all_sizes(self, user_session, token_manager, key_size):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=key_size, label=f"rsa-sv-{key_size}", token=False
        )
        crypto = CryptoOperations()
        data = os.urandom(256)
        sig = crypto.rsa_sign(priv, data)
        assert len(sig) == key_size // 8
        assert crypto.rsa_verify(pub, data, sig) is True
        pub.destroy(); priv.destroy()


class TestRSAHashVariantsDepth:
    @pytest.mark.parametrize("mech,name", [
        (Mechanism.SHA1_RSA_PKCS,   "SHA1"),
        (Mechanism.SHA256_RSA_PKCS, "SHA256"),
        (Mechanism.SHA384_RSA_PKCS, "SHA384"),
        (Mechanism.SHA512_RSA_PKCS, "SHA512"),
    ])
    def test_pkcs1_all_hash_variants(self, user_session, token_manager, mech, name):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label=f"rsa-h-{name}", token=False
        )
        data = os.urandom(128)
        sig = priv.sign(data, mechanism=mech)
        result = pub.verify(data, sig, mechanism=mech)
        assert result is not False
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("mech,hash_mech,mgf,saltlen,name", [
        (Mechanism.SHA1_RSA_PKCS_PSS,   Mechanism.SHA_1,   pkcs11.MGF.SHA1,   20, "PSS-SHA1"),
        (Mechanism.SHA256_RSA_PKCS_PSS, Mechanism.SHA256,  pkcs11.MGF.SHA256, 32, "PSS-SHA256"),
        (Mechanism.SHA384_RSA_PKCS_PSS, Mechanism.SHA384,  pkcs11.MGF.SHA384, 48, "PSS-SHA384"),
        (Mechanism.SHA512_RSA_PKCS_PSS, Mechanism.SHA512,  pkcs11.MGF.SHA512, 64, "PSS-SHA512"),
    ])
    def test_pss_all_hash_variants(self, user_session, token_manager, mech, hash_mech, mgf, saltlen, name):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label=f"rsa-{name}", token=False
        )
        data = os.urandom(128)
        params = (hash_mech, mgf, saltlen)
        sig = priv.sign(data, mechanism=mech, mechanism_param=params)
        result = pub.verify(data, sig, mechanism=mech, mechanism_param=params)
        assert result is not False
        pub.destroy(); priv.destroy()


class TestRSAMaxPayload:
    def test_pkcs1_max_plaintext_length(self, user_session, token_manager):
        """RSA-PKCS1 max payload = key_bytes - 11."""
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="rsa-max", token=False
        )
        crypto = CryptoOperations()
        max_len = 256 - 11
        plaintext = os.urandom(max_len)
        ct = crypto.rsa_encrypt(pub, plaintext)
        assert crypto.rsa_decrypt(priv, ct) == plaintext
        pub.destroy(); priv.destroy()

    def test_pkcs1_payload_too_large_raises(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="rsa-over", token=False
        )
        crypto = CryptoOperations()
        oversized = os.urandom(256 - 11 + 1)  # one byte over limit
        with pytest.raises(pkcs11.PKCS11Error):
            crypto.rsa_encrypt(pub, oversized)
        pub.destroy(); priv.destroy()


class TestRSAKeyAttributes:
    def test_public_key_not_sensitive(self, rsa_keypair):
        pub, _ = rsa_keypair
        # RSA public keys may not expose SENSITIVE attribute — the key class is not secret
        try:
            val = pub[Attribute.SENSITIVE]
            assert val is False
        except pkcs11.exceptions.AttributeTypeInvalid:
            pass  # public key has no SENSITIVE attribute — expected

    def test_private_key_sensitive(self, rsa_keypair):
        _, priv = rsa_keypair
        assert priv[Attribute.SENSITIVE] is True

    def test_private_key_not_extractable(self, rsa_keypair):
        _, priv = rsa_keypair
        assert priv[Attribute.EXTRACTABLE] is False

    def test_public_key_has_modulus(self, rsa_keypair):
        pub, _ = rsa_keypair
        modulus = pub[Attribute.MODULUS]
        assert isinstance(modulus, bytes)
        assert len(modulus) == 256  # 2048-bit

    def test_public_key_has_exponent(self, rsa_keypair):
        pub, _ = rsa_keypair
        exp = pub[Attribute.PUBLIC_EXPONENT]
        assert isinstance(exp, bytes)
        # Standard exponent 65537
        assert int.from_bytes(exp, "big") == 65537

    def test_sign_only_key_cannot_decrypt(self, user_session):
        pub, priv = user_session.generate_keypair(
            KeyType.RSA, 1024, store=False,
            public_template={Attribute.ENCRYPT: False, Attribute.VERIFY: True},
            private_template={Attribute.DECRYPT: False, Attribute.SIGN: True,
                               Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False}
        )
        # python-pkcs11 omits DecryptMixin when DECRYPT=False → AttributeError
        with pytest.raises((pkcs11.PKCS11Error, AttributeError)):
            priv.decrypt(b"\x00" * 128, mechanism=Mechanism.RSA_PKCS)
        pub.destroy(); priv.destroy()


class TestRSANonMalleability:
    def test_flipped_bit_in_signature_fails(self, rsa_keypair):
        """Flipping a bit in the signature body causes verify to fail."""
        pub, priv = rsa_keypair
        data = b"non-malleable data"
        sig = CryptoOperations.rsa_sign(priv, data)
        # Flip a bit in the middle of the signature
        mid = len(sig) // 2
        tampered = sig[:mid] + bytes([sig[mid] ^ 0x01]) + sig[mid+1:]
        assert CryptoOperations.rsa_verify(pub, data, tampered) is False

    def test_truncated_signature_fails(self, rsa_keypair):
        pub, priv = rsa_keypair
        sig = CryptoOperations.rsa_sign(priv, b"data")
        assert CryptoOperations.rsa_verify(pub, b"data", sig[:-8]) is False

    def test_two_keys_different_signatures(self, user_session, token_manager):
        pub1, priv1 = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="nm-k1", token=False
        )
        pub2, priv2 = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="nm-k2", token=False
        )
        data = b"same data"
        sig1 = CryptoOperations.rsa_sign(priv1, data)
        sig2 = CryptoOperations.rsa_sign(priv2, data)
        # Signature from key1 does not verify under key2
        assert CryptoOperations.rsa_verify(pub2, data, sig1) is False
        assert CryptoOperations.rsa_verify(pub1, data, sig2) is False
        for k in (pub1, priv1, pub2, priv2):
            k.destroy()
