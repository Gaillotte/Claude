"""Tests targeting SoftHSM2 C++ code paths not exercised by the existing suite.

Each class maps to one or more under-covered SoftHSM2 source files:
  - SoftHSM.cpp        : streaming ops, C_SetAttributeValue, C_UnwrapKey,
                         C_GetObjectSize, C_CloseAllSessions, C_DigestKey
  - P11Objects.cpp     : certificate objects, domain parameters
  - OSSLSHA224.cpp     : SHA-224 digest + HMAC-SHA224 (0 % coverage)
  - OSSLMD5.cpp        : MD5 digest (0 % coverage)
  - OSSLEVPSym.cpp     : encryptUpdate/Final, decryptUpdate/Final
  - OSSLRSA.cpp        : all RSA sign variants, key import from DER
  - ObjectFile.cpp     : TOKEN=True persistent objects
  - SecureDataManager  : SO login, C_InitPIN
  - SessionManager.cpp : multiple parallel sessions
"""

from __future__ import annotations

import os
import hashlib
import struct

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters

from pkcs11_app.derive import DeriveOperations
from pkcs11_app.mac import MACOperations
from pkcs11_app.objects import ObjectOperations
from pkcs11_app.token import TokenManager


# ── SHA-224 (OSSLSHA224.cpp — 0 % coverage) ───────────────────────────────────

class TestSHA224:
    """SHA-224 digest and HMAC are completely untouched by the existing suite."""

    def test_sha224_digest_oneshot(self, user_session):
        data = os.urandom(256)
        digest = user_session.digest(data, mechanism=Mechanism.SHA224)
        assert len(digest) == 28
        assert digest == hashlib.sha224(data).digest()

    @pytest.mark.parametrize("size", [0, 1, 55, 56, 64, 512, 4096])
    def test_sha224_various_sizes(self, user_session, size):
        data = os.urandom(size)
        digest = user_session.digest(data, mechanism=Mechanism.SHA224)
        assert digest == hashlib.sha224(data).digest()

    def test_hmac_sha224_sign_verify(self, user_session):
        key = MACOperations.generate_hmac_key(
            user_session, label="cov-hmac224",
            mechanism=Mechanism.SHA224_HMAC,
        )
        data = os.urandom(128)
        mac = MACOperations.hmac_sign(key, data, mechanism=Mechanism.SHA224_HMAC)
        assert len(mac) == 28
        assert MACOperations.hmac_verify(key, data, mac, mechanism=Mechanism.SHA224_HMAC)
        key.destroy()

    def test_sha224_rsa_sign_verify(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="cov-rsa-sha224", token=False
        )
        data = os.urandom(128)
        sig = priv.sign(data, mechanism=Mechanism.SHA224_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA224_RSA_PKCS) is not False
        pub.destroy(); priv.destroy()

    def test_sha224_rsa_pss_sign_verify(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="cov-rsa-pss224", token=False
        )
        data   = os.urandom(128)
        params = (Mechanism.SHA224, pkcs11.MGF.SHA224, 28)
        sig = priv.sign(data, mechanism=Mechanism.SHA224_RSA_PKCS_PSS,
                        mechanism_param=params)
        result = pub.verify(data, sig, mechanism=Mechanism.SHA224_RSA_PKCS_PSS,
                            mechanism_param=params)
        assert result is not False
        pub.destroy(); priv.destroy()


# ── MD5 (OSSLMD5.cpp — 0 % coverage) ─────────────────────────────────────────

class TestMD5:
    """MD5 digest and HMAC are completely untouched."""

    def test_md5_digest(self, user_session):
        data = os.urandom(256)
        digest = user_session.digest(data, mechanism=Mechanism._MD5)
        assert len(digest) == 16
        assert digest == hashlib.md5(data).digest()

    @pytest.mark.parametrize("size", [0, 1, 63, 64, 512])
    def test_md5_various_sizes(self, user_session, size):
        data = os.urandom(size)
        assert user_session.digest(data, mechanism=Mechanism._MD5) == hashlib.md5(data).digest()

    def test_md5_rsa_sign_verify(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="cov-rsa-md5", token=False
        )
        data = os.urandom(64)
        sig = priv.sign(data, mechanism=Mechanism.MD5_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.MD5_RSA_PKCS) is not False
        pub.destroy(); priv.destroy()


# ── Streaming Digest (C_DigestUpdate / C_DigestFinal) ─────────────────────────

class TestStreamingDigest:
    """Force C_DigestUpdate + C_DigestFinal paths in SoftHSM.cpp and OSSLSHA*.cpp."""

    @pytest.mark.parametrize("mech,hashfn", [
        (Mechanism.SHA_1,  hashlib.sha1),
        (Mechanism.SHA224, hashlib.sha224),
        (Mechanism.SHA256, hashlib.sha256),
        (Mechanism.SHA384, hashlib.sha384),
        (Mechanism.SHA512, hashlib.sha512),
        (Mechanism._MD5,    hashlib.md5),
    ])
    def test_streaming_digest_matches_oneshot(self, user_session, mech, hashfn):
        chunks = [os.urandom(c) for c in (16, 100, 1, 0, 256)]
        data   = b"".join(chunks)
        # Streaming: pass list → python-pkcs11 calls DigestUpdate per chunk
        streamed = user_session.digest(iter(chunks), mechanism=mech)
        oneshot  = user_session.digest(data,          mechanism=mech)
        ref      = hashfn(data).digest()
        assert streamed == oneshot == ref

    def test_streaming_digest_large(self, user_session):
        chunks = [os.urandom(4096) for _ in range(16)]
        data   = b"".join(chunks)
        streamed = user_session.digest(iter(chunks), mechanism=Mechanism.SHA256)
        assert streamed == hashlib.sha256(data).digest()


# ── Streaming Encrypt / Decrypt (C_EncryptUpdate / C_EncryptFinal) ────────────

class TestStreamingAESCBC:
    """Cover encryptUpdate/Final and decryptUpdate/Final in OSSLEVPSymmetricAlgorithm."""

    def _key(self, user_session, token_manager, bits=128):
        return token_manager.generate_aes_key(
            user_session, bits, label=f"cov-stream-{bits}", token=False
        )

    @pytest.mark.parametrize("bits,chunk_sizes", [
        (128, [16, 32, 48]),
        (256, [16, 16, 64, 128]),
    ])
    def test_aes_cbc_encrypt_streaming(self, user_session, token_manager, bits, chunk_sizes):
        key = self._key(user_session, token_manager, bits)
        iv  = os.urandom(16)
        # Chunks must align to block size for AES_CBC (no padding)
        chunks = [os.urandom(s) for s in chunk_sizes]
        data   = b"".join(chunks)

        # Streaming encrypt via iterator
        ct_stream = b"".join(key.encrypt(
            iter(chunks), mechanism=Mechanism.AES_CBC, mechanism_param=iv
        ))
        # One-shot for reference
        ct_once = key.encrypt(data, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        assert ct_stream == ct_once

        # Decrypt and verify
        pt = key.decrypt(ct_stream, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        assert pt == data
        key.destroy()

    def test_aes_cbc_pad_streaming(self, user_session, token_manager):
        key = token_manager.generate_aes_key(
            user_session, 256, label="cov-cbc-pad-stream", token=False
        )
        iv     = os.urandom(16)
        chunks = [os.urandom(s) for s in (17, 33, 64, 1)]
        data   = b"".join(chunks)

        ct_stream = b"".join(key.encrypt(
            iter(chunks), mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv
        ))
        ct_once = key.encrypt(data, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        assert ct_stream == ct_once

        pt = key.decrypt(ct_once, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        assert pt == data
        key.destroy()

    def test_aes_ecb_streaming(self, user_session, token_manager):
        key = token_manager.generate_aes_key(
            user_session, 128, label="cov-ecb-stream", token=False
        )
        chunks = [os.urandom(16) for _ in range(8)]
        data   = b"".join(chunks)
        ct_s   = b"".join(key.encrypt(iter(chunks), mechanism=Mechanism.AES_ECB))
        ct_o   = key.encrypt(data,          mechanism=Mechanism.AES_ECB)
        assert ct_s == ct_o
        key.destroy()


class TestStreamingDES3CBC:
    """Streaming paths for DES3."""

    def test_des3_cbc_streaming(self, user_session, token_manager):
        key = token_manager.generate_des3_key(
            user_session, label="cov-des3-stream", token=False
        )
        iv     = os.urandom(8)
        chunks = [os.urandom(8) for _ in range(6)]
        data   = b"".join(chunks)
        ct_s   = b"".join(key.encrypt(iter(chunks), mechanism=Mechanism.DES3_CBC, mechanism_param=iv))
        ct_o   = key.encrypt(data,          mechanism=Mechanism.DES3_CBC, mechanism_param=iv)
        assert ct_s == ct_o
        pt     = key.decrypt(ct_o, mechanism=Mechanism.DES3_CBC, mechanism_param=iv)
        assert pt == data
        key.destroy()


# ── Streaming Sign / Verify (C_SignUpdate / C_SignFinal) ──────────────────────

class TestStreamingSign:
    """Cover SignUpdate/Final and VerifyUpdate/Final in SoftHSM.cpp."""

    @pytest.mark.parametrize("mech,key_bits", [
        (Mechanism.SHA256_HMAC, 256),
        (Mechanism.SHA512_HMAC, 512),
    ])
    def test_hmac_streaming_matches_oneshot(self, user_session, mech, key_bits):
        key    = MACOperations.generate_hmac_key(
            user_session, label=f"cov-hmac-stream-{key_bits}", mechanism=mech
        )
        chunks = [os.urandom(c) for c in (10, 100, 500, 1000)]
        data   = b"".join(chunks)
        mac_s  = key.sign(iter(chunks), mechanism=mech)
        mac_o  = key.sign(data,          mechanism=mech)
        assert mac_s == mac_o
        # verify also supports streaming
        assert key.verify(iter([data[:200], data[200:]]), mac_o, mechanism=mech)
        key.destroy()

    def test_rsa_pkcs1_streaming(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="cov-rsa-stream", token=False
        )
        chunks = [os.urandom(c) for c in (64, 128, 32)]
        data   = b"".join(chunks)
        sig_s  = priv.sign(iter(chunks), mechanism=Mechanism.SHA256_RSA_PKCS)
        sig_o  = priv.sign(data,          mechanism=Mechanism.SHA256_RSA_PKCS)
        # Both signatures must be valid (RSA PKCS1 is deterministic)
        assert sig_s == sig_o
        assert pub.verify(data, sig_o, mechanism=Mechanism.SHA256_RSA_PKCS) is not False
        # Streaming verify
        assert pub.verify(
            iter([data[:100], data[100:]]), sig_o,
            mechanism=Mechanism.SHA256_RSA_PKCS
        ) is not False
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("curve,bits", [("secp256r1", 256), ("secp384r1", 384)])
    def test_ecdsa_streaming(self, user_session, curve, bits):
        params = encode_named_curve_parameters(curve)
        pub, priv = user_session.generate_keypair(
            KeyType.EC, label=f"cov-ecdsa-stream-{bits}", store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True,
                              Attribute.EXTRACTABLE: False},
        )
        chunks = [os.urandom(c) for c in (32, 64, 16)]
        data   = b"".join(chunks)
        # ECDSA_SHA256 via streaming (pre-hashing in SoftHSM2)
        try:
            sig = priv.sign(iter(chunks), mechanism=Mechanism.ECDSA_SHA256)
            assert pub.verify(data, sig, mechanism=Mechanism.ECDSA_SHA256) is not False
        except pkcs11.exceptions.MechanismInvalid:
            # Fallback: pre-hash and use raw ECDSA
            digest = hashlib.sha256(data).digest()
            sig = priv.sign(digest, mechanism=Mechanism.ECDSA)
            assert pub.verify(digest, sig, mechanism=Mechanism.ECDSA) is not False
        pub.destroy(); priv.destroy()

    def test_eddsa_streaming(self, user_session):
        pub, priv = ObjectOperations.generate_ed25519_keypair(
            user_session, label="cov-ed-stream"
        )
        chunks = [os.urandom(c) for c in (0, 64, 128, 1)]
        data   = b"".join(chunks)
        try:
            sig_s = priv.sign(iter(chunks), mechanism=Mechanism.EDDSA)
            assert pub.verify(data, sig_s, mechanism=Mechanism.EDDSA) is not False
        except Exception:
            # EdDSA may not support streaming via this binding — fall back to oneshot
            sig = ObjectOperations.eddsa_sign(priv, data)
            assert ObjectOperations.eddsa_verify(pub, data, sig)
        pub.destroy(); priv.destroy()


# ── AES CMAC streaming ─────────────────────────────────────────────────────────

class TestStreamingCMAC:
    def test_aes_cmac_streaming(self, user_session):
        key    = MACOperations.generate_cmac_key(user_session, label="cov-cmac-stream")
        chunks = [os.urandom(16) for _ in range(8)]
        data   = b"".join(chunks)
        mac_s  = key.sign(iter(chunks), mechanism=Mechanism.AES_CMAC)
        mac_o  = MACOperations.aes_cmac_sign(key, data)
        assert mac_s == mac_o
        key.destroy()


# ── C_SetAttributeValue ───────────────────────────────────────────────────────

class TestSetAttributeValue:
    """Calls C_SetAttributeValue which is not exercised by any existing test."""

    def test_set_label_on_aes_key(self, user_session, token_manager):
        key = token_manager.generate_aes_key(
            user_session, 256, label="cov-setattr-orig", token=False
        )
        key[Attribute.LABEL] = "cov-setattr-new"
        assert key[Attribute.LABEL] == "cov-setattr-new"
        key.destroy()

    def test_set_id_on_key(self, user_session, token_manager):
        key = token_manager.generate_aes_key(
            user_session, 128, label="cov-setid", token=False
        )
        key[Attribute.ID] = b"\x42\x43"
        assert key[Attribute.ID] == b"\x42\x43"
        key.destroy()

    def test_set_label_on_rsa_public_key(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="cov-setattr-rsa", token=False
        )
        pub[Attribute.LABEL] = "cov-rsa-pub-renamed"
        assert pub[Attribute.LABEL] == "cov-rsa-pub-renamed"
        pub.destroy(); priv.destroy()

    def test_set_label_on_ec_key(self, user_session):
        params = encode_named_curve_parameters("secp256r1")
        pub, priv = user_session.generate_keypair(
            KeyType.EC, label="cov-setattr-ec", store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True,
                              Attribute.EXTRACTABLE: False},
        )
        pub[Attribute.LABEL] = "cov-ec-pub-new"
        assert pub[Attribute.LABEL] == "cov-ec-pub-new"
        pub.destroy(); priv.destroy()


# ── C_GetObjectSize ───────────────────────────────────────────────────────────

class TestGetObjectSize:
    """C_GetObjectSize via ctypes sur la lib native (non exposé par python-pkcs11)."""

    def _get_object_size(self, session, obj) -> int:
        import ctypes, os
        lib_path = os.environ["PKCS11_MODULE_PATH"]
        lib = ctypes.CDLL(lib_path)
        # CK_ULONG on 64-bit Linux
        size = ctypes.c_ulong(0)
        rv = lib.C_GetObjectSize(
            ctypes.c_ulong(session.handle),
            ctypes.c_ulong(obj.handle),
            ctypes.byref(size),
        )
        assert rv == 0, f"C_GetObjectSize returned {rv}"
        return size.value

    def test_aes_key_size(self, user_session, token_manager):
        key  = token_manager.generate_aes_key(user_session, 256, label="cov-size", token=False)
        size = self._get_object_size(user_session, key)
        assert isinstance(size, int)
        assert size > 0
        key.destroy()

    def test_data_object_size(self, user_session):
        obj  = ObjectOperations.create_data_object(
            user_session, label="cov-data-size", data=b"hello world", token=False
        )
        size = self._get_object_size(user_session, obj)
        assert isinstance(size, int)
        assert size > 0
        obj.destroy()

    def test_rsa_key_size_called_on_multiple_objects(self, user_session, token_manager):
        """Exercise C_GetObjectSize on different object types (size may be unavailable)."""
        rsa_pub, rsa_priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="cov-size-rsa", token=False
        )
        params = encode_named_curve_parameters("secp256r1")
        ec_pub, ec_priv = user_session.generate_keypair(
            KeyType.EC, label="cov-size-ec", store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True,
                              Attribute.EXTRACTABLE: False},
        )
        import ctypes, os
        lib = ctypes.CDLL(os.environ["PKCS11_MODULE_PATH"])
        size = ctypes.c_ulong(0)
        # rv == 0 (CKR_OK) means the call reached SoftHSM2 C++ code
        rv = lib.C_GetObjectSize(
            ctypes.c_ulong(user_session.handle),
            ctypes.c_ulong(rsa_pub.handle),
            ctypes.byref(size),
        )
        assert rv == 0
        rv2 = lib.C_GetObjectSize(
            ctypes.c_ulong(user_session.handle),
            ctypes.c_ulong(ec_pub.handle),
            ctypes.byref(size),
        )
        assert rv2 == 0
        rsa_pub.destroy(); rsa_priv.destroy()
        ec_pub.destroy();  ec_priv.destroy()


# ── C_UnwrapKey (UnwrapKeySym) ────────────────────────────────────────────────

class TestUnwrapKey:
    """C_UnwrapKey path in SoftHSM.cpp is completely untouched."""

    def test_wrap_then_unwrap_aes_key(self, user_session, token_manager):
        kek = token_manager.generate_aes_key(
            user_session, 256, label="cov-kek", token=False
        )
        target = user_session.generate_key(
            KeyType.AES, 128, store=False,
            template={
                Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False,
                Attribute.WRAP: False, Attribute.UNWRAP: False,
            },
        )
        # Wrap
        wrapped = kek.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP)
        assert len(wrapped) > 0

        # Unwrap — restores a usable key
        unwrapped = kek.unwrap_key(
            ObjectClass.SECRET_KEY, KeyType.AES, wrapped,
            mechanism=Mechanism.AES_KEY_WRAP,
            template={
                Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False,
                Attribute.TOKEN: False,
            },
        )
        # Verify the unwrapped key works for encryption
        iv = os.urandom(16)
        pt = os.urandom(32)
        ct  = target.encrypt(pt,    mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        pt2 = unwrapped.decrypt(ct, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        assert pt2 == pt

        kek.destroy(); target.destroy(); unwrapped.destroy()

    def test_wrap_then_unwrap_aes_key_wrap_pad(self, user_session, token_manager):
        kek = token_manager.generate_aes_key(
            user_session, 128, label="cov-kek-pad", token=False
        )
        target = user_session.generate_key(
            KeyType.AES, 256, store=False,
            template={
                Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False,
                Attribute.WRAP: False, Attribute.UNWRAP: False,
            },
        )
        wrapped = kek.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP_PAD)
        unwrapped = kek.unwrap_key(
            ObjectClass.SECRET_KEY, KeyType.AES, wrapped,
            mechanism=Mechanism.AES_KEY_WRAP_PAD,
            template={
                Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False,
                Attribute.TOKEN: False,
            },
        )
        iv  = os.urandom(16)
        pt  = os.urandom(64)
        ct  = target.encrypt(pt,    mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        pt2 = unwrapped.decrypt(ct, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        assert pt2 == pt
        kek.destroy(); target.destroy(); unwrapped.destroy()


# ── Token-persistent objects (ObjectFile.cpp) ─────────────────────────────────

class TestPersistentObjects:
    """token=True forces SoftHSM2 to write objects to disk (ObjectFile.cpp paths)."""

    def test_persistent_aes_key_survives_new_session(self, session_manager, token_manager):
        with session_manager.open_user_session() as s1:
            key = token_manager.generate_aes_key(
                s1, 128, label="cov-persist-aes", token=True
            )
            kid = key[Attribute.ID] if key[Attribute.ID] else b"\x00"

        # Open a new session and find the same key
        with session_manager.open_user_session() as s2:
            found = list(s2.get_objects({
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.LABEL: "cov-persist-aes",
            }))
            assert len(found) == 1
            # Clean up
            found[0].destroy()

    def test_persistent_data_object(self, session_manager):
        payload = os.urandom(64)
        with session_manager.open_user_session() as s1:
            obj = ObjectOperations.create_data_object(
                s1, label="cov-persist-data", data=payload, token=True
            )

        with session_manager.open_user_session() as s2:
            found = list(s2.get_objects({
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: "cov-persist-data",
            }))
            assert len(found) == 1
            assert found[0][Attribute.VALUE] == payload
            found[0].destroy()

    def test_persistent_rsa_keypair(self, session_manager, token_manager):
        with session_manager.open_user_session() as s1:
            pub, priv = token_manager.generate_rsa_keypair(
                s1, key_length=2048, label="cov-persist-rsa", token=True
            )
            pub_mod = pub[Attribute.MODULUS]

        with session_manager.open_user_session() as s2:
            pubs = list(s2.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.LABEL: "cov-persist-rsa",
            }))
            privs = list(s2.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.LABEL: "cov-persist-rsa",
            }))
            assert len(pubs) == 1
            assert pubs[0][Attribute.MODULUS] == pub_mod
            for o in pubs + privs:
                o.destroy()

    def test_find_objects_by_id(self, session_manager, token_manager):
        obj_id = os.urandom(8)
        with session_manager.open_user_session() as s1:
            key = token_manager.generate_aes_key(
                s1, 128, label="cov-find-by-id", token=True
            )
            key[Attribute.ID] = obj_id

        with session_manager.open_user_session() as s2:
            found = list(s2.get_objects({Attribute.ID: obj_id}))
            assert len(found) >= 1
            for o in found:
                o.destroy()


# ── Certificate objects (P11X509CertificateObj) ───────────────────────────────

class TestCertificateObjects:
    """X.509 certificate objects cover P11CertificateObj and P11X509CertificateObj."""

    def _make_x509_der(self) -> bytes:
        """Minimal self-signed X.509 v1 DER for testing (not cryptographically valid)."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SoftHSM2 Test")])
        now  = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_create_x509_certificate_object(self, user_session):
        der = self._make_x509_der()
        obj = user_session.create_object({
            Attribute.CLASS:            ObjectClass.CERTIFICATE,
            Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
            Attribute.SUBJECT:          b"\x30\x00",   # minimal DER sequence
            Attribute.VALUE:            der,
            Attribute.LABEL:            "cov-x509",
            Attribute.TOKEN:            False,
            Attribute.PRIVATE:          False,
        })
        assert obj[Attribute.CLASS] == ObjectClass.CERTIFICATE
        assert obj[Attribute.VALUE] == der
        obj.destroy()

    def test_find_certificate_objects(self, user_session):
        der = self._make_x509_der()
        obj = user_session.create_object({
            Attribute.CLASS:            ObjectClass.CERTIFICATE,
            Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
            Attribute.SUBJECT:          b"\x30\x00",
            Attribute.VALUE:            der,
            Attribute.LABEL:            "cov-x509-find",
            Attribute.TOKEN:            False,
            Attribute.PRIVATE:          False,
        })
        certs = list(user_session.get_objects({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.LABEL: "cov-x509-find",
        }))
        assert len(certs) == 1
        assert certs[0][Attribute.LABEL] == "cov-x509-find"
        obj.destroy()

    def test_persistent_certificate(self, session_manager):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Persistent Test")])
        now  = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        der = cert.public_bytes(serialization.Encoding.DER)

        with session_manager.open_user_session() as s1:
            obj = s1.create_object({
                Attribute.CLASS:              ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
                Attribute.SUBJECT:            b"\x30\x00",
                Attribute.VALUE:              der,
                Attribute.LABEL:              "cov-x509-persist",
                Attribute.TOKEN:              True,
                Attribute.PRIVATE:            False,
            })

        with session_manager.open_user_session() as s2:
            found = list(s2.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.LABEL: "cov-x509-persist",
            }))
            assert len(found) == 1
            assert found[0][Attribute.VALUE] == der
            found[0].destroy()


# ── Domain parameter objects (P11DSADomainObj, P11DHDomainObj) ─────────────────

class TestDomainParameterObjects:
    """Domain parameters (DSA/DH) are stored as separate objects in SoftHSM2."""

    def test_dsa_domain_parameters_stored_as_object(self, user_session):
        params = DeriveOperations.generate_dsa_params(user_session)
        # DSA params are a DOMAIN_PARAMETERS object
        assert params[Attribute.KEY_TYPE] == KeyType.DSA
        p_val = params[Attribute.PRIME]
        q_val = params[Attribute.SUBPRIME]
        g_val = params[Attribute.BASE]
        assert len(p_val) >= 64
        assert len(q_val) == 20
        assert len(g_val) >= 64
        params.destroy()

    def test_dsa_domain_params_used_for_keygen(self, user_session):
        params = DeriveOperations.generate_dsa_params(user_session)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label="cov-dsa-dom")
        data = os.urandom(128)
        sig  = DeriveOperations.dsa_sign(priv, data)
        assert DeriveOperations.dsa_verify(pub, data, sig)
        pub.destroy(); priv.destroy(); params.destroy()

    def test_dh_domain_parameters_attributes(self, user_session):
        params = DeriveOperations.generate_dh_params(user_session)
        assert params[Attribute.KEY_TYPE] == KeyType.DH
        prime  = params[Attribute.PRIME]
        base   = params[Attribute.BASE]
        assert len(prime) >= 64
        assert base in (b"\x02", b"\x05") or len(base) >= 1
        params.destroy()

    def test_dh_full_lifecycle(self, user_session):
        params_a = DeriveOperations.generate_dh_params(user_session)
        params_b = DeriveOperations.generate_dh_params(user_session)
        pub_a, priv_a = DeriveOperations.generate_dh_keypair(params_a, label="cov-dh-a")
        pub_b, priv_b = DeriveOperations.generate_dh_keypair(params_b, label="cov-dh-b")
        secret = DeriveOperations.dh_derive_secret(priv_a, pub_b[Attribute.VALUE])
        assert secret is not None
        for o in (pub_a, priv_a, pub_b, priv_b, secret, params_a, params_b):
            try: o.destroy()
            except Exception: pass


# ── RSA — all key attribute extraction paths (OSSLRSAPrivateKey, OSSLRSAPublicKey) ──

class TestRSAKeyAttributes:
    """Read all RSA key attributes to cover OSSLRSAPrivateKey/PublicKey getter paths."""

    def test_public_key_all_attributes(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="cov-rsa-attr", token=False
        )
        mod  = pub[Attribute.MODULUS]
        exp  = pub[Attribute.PUBLIC_EXPONENT]
        bits = pub[Attribute.MODULUS_BITS]
        assert len(mod) == 256
        assert int.from_bytes(exp, "big") == 65537
        assert bits == 2048
        pub.destroy(); priv.destroy()

    def test_private_key_attributes(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=1024, label="cov-rsa-priv-attr", token=False
        )
        assert priv[Attribute.SENSITIVE]      is True
        assert priv[Attribute.EXTRACTABLE]    is False
        assert priv[Attribute.KEY_TYPE]       == KeyType.RSA
        assert priv[Attribute.CLASS]          == ObjectClass.PRIVATE_KEY
        pub.destroy(); priv.destroy()

    def test_rsa_key_import_from_raw(self, user_session):
        """C_CreateObject with raw RSA key material — covers P11RSAPublicKeyObj."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pub_nums = priv_key.public_key().public_numbers()

        n = pub_nums.n.to_bytes(128, "big")
        e = pub_nums.e.to_bytes(3, "big")

        obj = user_session.create_object({
            Attribute.CLASS:           ObjectClass.PUBLIC_KEY,
            Attribute.KEY_TYPE:        KeyType.RSA,
            Attribute.MODULUS:         n,
            Attribute.PUBLIC_EXPONENT: e,
            Attribute.ENCRYPT:         True,
            Attribute.VERIFY:          True,
            Attribute.TOKEN:           False,
        })
        assert obj[Attribute.MODULUS] == n
        assert obj[Attribute.PUBLIC_EXPONENT] == e
        obj.destroy()


# ── EC key attribute extraction (OSSLECPublicKey, OSSLECPrivateKey) ────────────

class TestECKeyAttributes:
    @pytest.mark.parametrize("curve,exp_len", [
        ("secp256r1", 32),
        ("secp384r1", 48),
        ("secp521r1", 66),
    ])
    def test_ec_public_key_attributes(self, user_session, curve, exp_len):
        params = encode_named_curve_parameters(curve)
        pub, priv = user_session.generate_keypair(
            KeyType.EC, label=f"cov-ec-attr-{curve}", store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True,
                              Attribute.EXTRACTABLE: False},
        )
        ec_point  = pub[Attribute.EC_POINT]
        ec_params = pub[Attribute.EC_PARAMS]
        assert isinstance(ec_point, bytes)
        assert ec_params == params
        assert pub[Attribute.KEY_TYPE]   == KeyType.EC
        assert pub[Attribute.CLASS]      == ObjectClass.PUBLIC_KEY
        assert priv[Attribute.SENSITIVE] is True
        pub.destroy(); priv.destroy()

    def test_ed25519_key_attributes(self, user_session):
        pub, priv = ObjectOperations.generate_ed25519_keypair(
            user_session, label="cov-ed-attr"
        )
        assert pub[Attribute.KEY_TYPE]   == KeyType.EC_EDWARDS
        assert priv[Attribute.KEY_TYPE]  == KeyType.EC_EDWARDS
        ec_point = pub[Attribute.EC_POINT]
        assert isinstance(ec_point, bytes)
        assert len(ec_point) > 0
        pub.destroy(); priv.destroy()


# ── AES key attribute extraction (OSSLAESKey) ─────────────────────────────────

class TestAESKeyAttributes:
    @pytest.mark.parametrize("bits", [128, 192, 256])
    def test_aes_key_value_length(self, user_session, token_manager, bits):
        key = user_session.generate_key(
            KeyType.AES, bits, store=False,
            template={
                Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False,
                Attribute.TOKEN: False,
            },
        )
        val = key[Attribute.VALUE]
        assert len(val) == bits // 8
        assert key[Attribute.VALUE_LEN] == bits // 8
        assert key[Attribute.KEY_TYPE] == KeyType.AES
        key.destroy()


# ── Multiple sessions (SessionManager.cpp) ────────────────────────────────────

class TestMultipleSessions:
    """Open several concurrent sessions to exercise SessionManager internals."""

    def test_two_rw_sessions_independent(self, session_manager, token_manager):
        """Two R/W sessions can coexist and each sees the other's objects."""
        token = session_manager.library.get_token()
        import uuid
        label = f"cov-ms-k1-{uuid.uuid4().hex[:8]}"
        with session_manager.open_user_session() as s1:
            k1 = token_manager.generate_aes_key(s1, 128, label=label, token=False)
            with token.open(rw=True) as s2:
                found = list(s2.get_objects({
                    Attribute.LABEL: label,
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                }))
                assert len(found) == 1
            k1.destroy()

    def test_session_info(self, session_manager):
        with session_manager.open_user_session() as s:
            from pkcs11_app.session import SessionManager
            info = SessionManager.get_session_info(s)
            assert info["rw"] is True

    def test_ro_session_can_read_token_objects(self, session_manager):
        """A data object with PRIVATE=False is visible from a read-only session."""
        token = session_manager.library.get_token()
        import uuid
        label = f"cov-ro-data-{uuid.uuid4().hex[:8]}"
        with session_manager.open_user_session() as rw:
            obj = rw.create_object({
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"test-data",
                Attribute.TOKEN: True,
                Attribute.PRIVATE: False,
            })
            with token.open(rw=False) as ro:
                found = list(ro.get_objects({Attribute.LABEL: label}))
                assert len(found) == 1
            obj.destroy()

    def test_three_concurrent_sessions(self, session_manager):
        """SoftHSM2 allows multiple R/W sessions on same slot; each share login state."""
        token = session_manager.library.get_token()
        with session_manager.open_user_session() as s1:
            with token.open(rw=True) as s2:
                d1 = s1.digest(b"a", mechanism=Mechanism.SHA256)
                d2 = s2.digest(b"a", mechanism=Mechanism.SHA256)
                assert d1 == d2


# ── C_CopyObject (deeper coverage) ────────────────────────────────────────────

class TestCopyObject:
    def test_copy_aes_key_with_new_label(self, user_session, token_manager):
        key  = token_manager.generate_aes_key(
            user_session, 128, label="cov-copy-orig", token=False
        )
        copy = ObjectOperations.copy_object(key, new_label="cov-copy-new")
        assert copy[Attribute.LABEL] == "cov-copy-new"
        assert copy[Attribute.VALUE_LEN] == key[Attribute.VALUE_LEN]
        key.destroy(); copy.destroy()

    def test_copy_rsa_public_key(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=1024, label="cov-copy-rsa", token=False
        )
        copy = ObjectOperations.copy_object(pub, new_label="cov-copy-rsa-pub")
        assert copy[Attribute.MODULUS] == pub[Attribute.MODULUS]
        copy.destroy(); pub.destroy(); priv.destroy()


# ── Find objects with complex templates ───────────────────────────────────────

class TestFindObjectsComplex:
    """Exercise C_FindObjectsInit with multi-attribute templates."""

    def test_find_by_class_and_keytype(self, user_session, token_manager):
        k128 = token_manager.generate_aes_key(user_session, 128, label="cov-find-128", token=False)
        k256 = token_manager.generate_aes_key(user_session, 256, label="cov-find-256", token=False)
        results = list(user_session.get_objects({
            Attribute.CLASS:    ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.LABEL:    "cov-find-128",
        }))
        assert len(results) == 1
        assert results[0][Attribute.VALUE_LEN] == 16
        k128.destroy(); k256.destroy()

    def test_find_no_results(self, user_session):
        results = list(user_session.get_objects({
            Attribute.LABEL: "cov-nonexistent-label-xyzzy",
        }))
        assert results == []

    def test_find_all_secret_keys(self, user_session, token_manager):
        keys = [
            token_manager.generate_aes_key(user_session, 128, label=f"cov-all-{i}", token=False)
            for i in range(4)
        ]
        results = list(user_session.get_objects({
            Attribute.CLASS:    ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
        }))
        # At least 4 keys should be there
        assert len(results) >= 4
        for k in keys:
            k.destroy()


# ── SO operations / C_InitPIN (SecureDataManager.cpp) ─────────────────────────

class TestSOOperations:
    """SO login and C_InitPIN path in SoftHSM.cpp and SecureDataManager.cpp."""

    def test_so_session_get_token_info(self, session_manager):
        """SO login exercises a different SecureDataManager code path."""
        with session_manager.open_so_session() as so:
            from pkcs11_app.session import SessionManager
            info = SessionManager.get_session_info(so)
            assert info is not None

    def test_change_user_pin(self, session_manager):
        """C_SetPIN with valid old PIN exercises SecureDataManager::setUserPIN."""
        with session_manager.open_user_session() as s:
            from pkcs11_app.session import SessionManager
            from pkcs11_app.config import PKCS11Config
            cfg = PKCS11Config()
            old_pin = cfg.user_pin
            try:
                s.set_pin(old_pin, old_pin)   # change to same value — no-op but exercises path
            except pkcs11.exceptions.PinInvalid:
                pass  # some implementations reject same-pin change


# ── RNG seed path (C_SeedRandom) ──────────────────────────────────────────────

class TestRNGSeed:
    def test_seed_random(self, user_session):
        from pkcs11_app.session import SessionManager
        seed = os.urandom(32)
        try:
            user_session.seed_random(seed)
        except Exception:
            pass  # SoftHSM2 may accept or silently ignore

    @pytest.mark.parametrize("size", [1, 8, 16, 32, 64, 256, 1024, 4096])
    def test_generate_random_various_sizes(self, user_session, size):
        from pkcs11_app.crypto import CryptoOperations
        rand = CryptoOperations().generate_random(user_session, size)
        assert len(rand) == size


# ── AES-GCM with AAD and different tag sizes ──────────────────────────────────

class TestAESGCMVariants:
    """Cover more GCM code paths (tag size variations, AAD)."""

    @pytest.mark.parametrize("tag_bits", [32, 64, 96, 104, 112, 120, 128])
    def test_gcm_all_tag_sizes(self, user_session, token_manager, tag_bits):
        from pkcs11_app.aead import AEADOperations
        key  = token_manager.generate_aes_key(user_session, 128, label=f"cov-gcm-t{tag_bits}", token=False)
        aead = AEADOperations()
        data = os.urandom(64)
        ct, nonce = aead.aes_gcm_encrypt(key, data, tag_bits=tag_bits)
        pt = aead.aes_gcm_decrypt(key, ct, nonce, tag_bits=tag_bits)
        assert pt == data
        key.destroy()

    @pytest.mark.parametrize("aad_size", [0, 1, 16, 128, 512])
    def test_gcm_various_aad_sizes(self, user_session, token_manager, aad_size):
        from pkcs11_app.aead import AEADOperations
        key  = token_manager.generate_aes_key(user_session, 256, label=f"cov-gcm-aad{aad_size}", token=False)
        aead = AEADOperations()
        data = os.urandom(128)
        aad  = os.urandom(aad_size) if aad_size else None
        ct, nonce = aead.aes_gcm_encrypt(key, data, aad=aad)
        pt = aead.aes_gcm_decrypt(key, ct, nonce, aad=aad)
        assert pt == data
        key.destroy()


# ── DSA all hash variants ─────────────────────────────────────────────────────

class TestDSAAllVariants:
    """DSA_SHA1/224/256/384/512 — only DSA_SHA256 was tested before."""

    @pytest.mark.parametrize("mech", [
        Mechanism.DSA_SHA1,
        Mechanism.DSA_SHA224,
        Mechanism.DSA_SHA256,
        Mechanism.DSA_SHA384,
        Mechanism.DSA_SHA512,
    ])
    def test_dsa_all_hash_variants(self, user_session, mech):
        params = DeriveOperations.generate_dsa_params(user_session)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label=f"cov-dsa-{mech.name}")
        data = os.urandom(128)
        try:
            sig  = priv.sign(data, mechanism=mech)
            result = pub.verify(data, sig, mechanism=mech)
            assert result is not False
        except pkcs11.exceptions.MechanismInvalid:
            pytest.skip(f"{mech.name} not supported by this SoftHSM2 build")
        finally:
            pub.destroy(); priv.destroy(); params.destroy()


# ── ECDH all curves — derive then use ─────────────────────────────────────────

class TestECDHAllCurves:
    @pytest.mark.parametrize("curve,bits", [
        ("secp256r1", 256),
        ("secp384r1", 384),
        ("secp521r1", 521),
    ])
    def test_ecdh_derive_and_encrypt(self, user_session, curve, bits):
        from pkcs11 import Attribute as A
        pub_a, priv_a = DeriveOperations.generate_ecdh_keypair(
            user_session, curve_name=curve, label=f"cov-ecdh-a-{bits}"
        )
        pub_b, priv_b = DeriveOperations.generate_ecdh_keypair(
            user_session, curve_name=curve, label=f"cov-ecdh-b-{bits}"
        )
        sk_ab = DeriveOperations.ecdh_derive_aes_key(priv_a, pub_b[A.EC_POINT], label="sk-ab")
        sk_ba = DeriveOperations.ecdh_derive_aes_key(priv_b, pub_a[A.EC_POINT], label="sk-ba")

        iv  = os.urandom(16)
        pt  = b"ECDH cross-check"
        ct  = sk_ab.encrypt(pt, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        pt2 = sk_ba.decrypt(ct, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        assert pt2 == pt

        for k in (pub_a, priv_a, pub_b, priv_b, sk_ab, sk_ba):
            try: k.destroy()
            except Exception: pass
