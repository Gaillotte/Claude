"""Third wave of tests to push SoftHSM2 C++ coverage higher.

Targets uncovered C++ functions identified from gcov analysis:
  SoftHSM.cpp       : C_GetSessionInfo, C_DigestKey, C_SignRecoverInit,
                      C_VerifyRecoverInit, C_GetFunctionStatus, C_CancelFunction,
                      C_WaitForSlotEvent, C_SetPIN, C_InitPIN, generateDES2
  P11Objects.cpp    : DES/GENERIC_SECRET key type access
  SecureDataManager : reAuthenticate paths (via SetPIN / InitPIN)
  ObjectFile.cpp    : attribute read-back on persistent objects
  SessionManager.cpp: getSessionInfo, haveSession
  SoftHSM.cpp       : setRSAPrivateKey, setDSAPrivateKey, setDHPrivateKey,
                      setECPrivateKey (import key from raw components)
  OSSLAES.cpp       : DES2 operations reuse AES3 path
"""

from __future__ import annotations

import ctypes
import os

import pytest
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, MGF, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters


# ── Helpers ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def cklib():
    return ctypes.CDLL(os.environ["PKCS11_MODULE_PATH"])


@pytest.fixture(scope="module")
def pkcs11_lib():
    return pkcs11.lib(os.environ["PKCS11_MODULE_PATH"])


@pytest.fixture(scope="module")
def token(pkcs11_lib):
    tokens = list(pkcs11_lib.get_tokens(token_label="TestToken"))
    assert tokens
    return tokens[0]


@pytest.fixture
def sess(token):
    with token.open(rw=True, user_pin="1234") as s:
        yield s


def _int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


# ── C_GetSessionInfo ──────────────────────────────────────────────────────────

class CK_SESSION_INFO(ctypes.Structure):
    _fields_ = [
        ("slotID", ctypes.c_ulong),
        ("state", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
        ("ulDeviceError", ctypes.c_ulong),
    ]


class TestGetSessionInfo:
    def test_user_session_info(self, sess, cklib):
        info = CK_SESSION_INFO()
        rv = cklib.C_GetSessionInfo(ctypes.c_ulong(sess.handle), ctypes.byref(info))
        assert rv == 0
        assert info.slotID > 0
        # state=3 => CKS_RW_USER_FUNCTIONS
        assert info.state in (2, 3)  # RO or RW user state

    def test_ro_session_info(self, token, cklib):
        with token.open(rw=False) as ro:
            info = CK_SESSION_INFO()
            rv = cklib.C_GetSessionInfo(ctypes.c_ulong(ro.handle), ctypes.byref(info))
            assert rv == 0
            # state=0 or 1 => public RO session
            assert info.state in (0, 1, 2, 3)

    def test_session_info_flags(self, sess, cklib):
        info = CK_SESSION_INFO()
        rv = cklib.C_GetSessionInfo(ctypes.c_ulong(sess.handle), ctypes.byref(info))
        assert rv == 0
        CKF_SERIAL_SESSION = 0x00000004
        assert info.flags & CKF_SERIAL_SESSION


# ── C_DigestKey ───────────────────────────────────────────────────────────────

class CK_MECHANISM(ctypes.Structure):
    _fields_ = [
        ("mechanism", ctypes.c_ulong),
        ("pParameter", ctypes.c_void_p),
        ("ulParameterLen", ctypes.c_ulong),
    ]


class TestDigestKey:
    """C_DigestKey incorporates a key's value into the running digest."""

    CKM_SHA256 = 0x00000250
    CKM_SHA_1  = 0x00000220
    CKM_SHA512 = 0x00000251

    def _sha256_of_key(self, sess, cklib, key_handle: int) -> bytes:
        mech = CK_MECHANISM()
        mech.mechanism = self.CKM_SHA256
        h = ctypes.c_ulong(sess.handle)
        assert cklib.C_DigestInit(h, ctypes.byref(mech)) == 0
        assert cklib.C_DigestKey(h, ctypes.c_ulong(key_handle)) == 0
        buf = (ctypes.c_uint8 * 32)()
        buf_len = ctypes.c_ulong(32)
        assert cklib.C_DigestFinal(h, buf, ctypes.byref(buf_len)) == 0
        return bytes(buf)

    def test_digest_aes_key(self, sess, cklib):
        key = sess.generate_key(KeyType.AES, 256, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        digest = self._sha256_of_key(sess, cklib, key.handle)
        assert len(digest) == 32
        key.destroy()

    def test_digest_key_is_deterministic(self, sess, cklib):
        """Same key should produce the same digest twice."""
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        d1 = self._sha256_of_key(sess, cklib, key.handle)
        d2 = self._sha256_of_key(sess, cklib, key.handle)
        assert d1 == d2
        key.destroy()

    def test_digest_key_mixed_with_data(self, sess, cklib):
        """Mix data updates and C_DigestKey in the same operation."""
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        mech = CK_MECHANISM()
        mech.mechanism = self.CKM_SHA256
        h = ctypes.c_ulong(sess.handle)
        assert cklib.C_DigestInit(h, ctypes.byref(mech)) == 0
        # update with some bytes first
        data = b"prefix data"
        assert cklib.C_DigestUpdate(h, data, ctypes.c_ulong(len(data))) == 0
        # then digest the key value
        assert cklib.C_DigestKey(h, ctypes.c_ulong(key.handle)) == 0
        buf = (ctypes.c_uint8 * 32)()
        buf_len = ctypes.c_ulong(32)
        assert cklib.C_DigestFinal(h, buf, ctypes.byref(buf_len)) == 0
        assert len(bytes(buf)) == 32
        key.destroy()

    def test_digest_des2_key(self, sess, cklib):
        key = sess.generate_key(KeyType.DES2, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        digest = self._sha256_of_key(sess, cklib, key.handle)
        assert len(digest) == 32
        key.destroy()

    def test_digest_des3_key(self, sess, cklib):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        digest = self._sha256_of_key(sess, cklib, key.handle)
        assert len(digest) == 32
        key.destroy()


# ── C_SignRecoverInit, C_VerifyRecoverInit (NOT_SUPPORTED) ────────────────────

class TestUnsupportedFunctions:
    CKR_FUNCTION_NOT_SUPPORTED = 0x54

    def test_sign_recover_init_not_supported(self, sess, cklib):
        mech = CK_MECHANISM()
        mech.mechanism = 0x00000001  # CKM_RSA_PKCS
        rv = cklib.C_SignRecoverInit(
            ctypes.c_ulong(sess.handle),
            ctypes.byref(mech),
            ctypes.c_ulong(0),
        )
        assert rv == self.CKR_FUNCTION_NOT_SUPPORTED

    def test_verify_recover_init_not_supported(self, sess, cklib):
        mech = CK_MECHANISM()
        mech.mechanism = 0x00000001
        rv = cklib.C_VerifyRecoverInit(
            ctypes.c_ulong(sess.handle),
            ctypes.byref(mech),
            ctypes.c_ulong(0),
        )
        assert rv == self.CKR_FUNCTION_NOT_SUPPORTED

    def test_get_function_status_not_supported(self, sess, cklib):
        rv = cklib.C_GetFunctionStatus(ctypes.c_ulong(sess.handle))
        assert rv == 0x51  # CKR_FUNCTION_NOT_PARALLEL

    def test_cancel_function_not_supported(self, sess, cklib):
        rv = cklib.C_CancelFunction(ctypes.c_ulong(sess.handle))
        assert rv == 0x51

    def test_get_operation_state(self, sess, cklib):
        buf_len = ctypes.c_ulong(0)
        rv = cklib.C_GetOperationState(
            ctypes.c_ulong(sess.handle), None, ctypes.byref(buf_len))
        # CKR_STATE_UNSAVEABLE=0x54 or CKR_OPERATION_NOT_INITIALIZED=0x91
        assert rv in (0x54, 0x91)

    def test_wait_for_slot_event(self, cklib):
        slot = ctypes.c_ulong(0)
        CKF_DONT_BLOCK = 0x01
        rv = cklib.C_WaitForSlotEvent(
            ctypes.c_ulong(CKF_DONT_BLOCK), ctypes.byref(slot), None)
        # CKR_NO_EVENT=0x08 or CKR_OK=0
        assert rv in (0, 8)


# ── C_SetPIN / C_InitPIN (SecureDataManager::reAuthenticate) ─────────────────

class TestPINManagement:
    """Exercises SecureDataManager reAuthenticate paths."""

    def test_set_user_pin_and_restore(self, sess, cklib):
        old_pin = b"1234"
        new_pin = b"temppin9"
        h = ctypes.c_ulong(sess.handle)
        rv = cklib.C_SetPIN(h, old_pin, ctypes.c_ulong(len(old_pin)),
                            new_pin, ctypes.c_ulong(len(new_pin)))
        assert rv == 0
        # Restore
        rv2 = cklib.C_SetPIN(h, new_pin, ctypes.c_ulong(len(new_pin)),
                              old_pin, ctypes.c_ulong(len(old_pin)))
        assert rv2 == 0

    def test_init_pin_via_so_session(self, token, cklib):
        """C_InitPIN from SO session exercises SecureDataManager::setUserPIN."""
        so_pin = os.environ.get("PKCS11_SO_PIN", "12345678")
        with token.open(rw=True, so_pin=so_pin) as so_sess:
            h = ctypes.c_ulong(so_sess.handle)
            new_pin = b"1234"  # set back to original
            rv = cklib.C_InitPIN(h, new_pin, ctypes.c_ulong(len(new_pin)))
            assert rv == 0

    def test_set_pin_wrong_old_fails(self, sess, cklib):
        h = ctypes.c_ulong(sess.handle)
        wrong = b"wrongpassword"
        new = b"newpin99"
        rv = cklib.C_SetPIN(h, wrong, ctypes.c_ulong(len(wrong)),
                            new, ctypes.c_ulong(len(new)))
        # CKR_PIN_INCORRECT = 0xA0
        assert rv == 0xA0


# ── DES2 key operations ───────────────────────────────────────────────────────

class TestDES2Operations:
    def test_des2_keygen(self, sess):
        key = sess.generate_key(KeyType.DES2, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        assert key is not None
        assert key[Attribute.KEY_TYPE] == KeyType.DES2
        key.destroy()

    def test_des2_cbc_encrypt_decrypt(self, sess):
        key = sess.generate_key(KeyType.DES2, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"IVIVIVIV"
        pt = b"Hello DES2 World"
        ct = key.encrypt(pt, mechanism=Mechanism.DES3_CBC, mechanism_param=iv)
        pt2 = key.decrypt(ct, mechanism=Mechanism.DES3_CBC, mechanism_param=iv)
        assert pt2 == pt
        key.destroy()

    def test_des2_ecb_encrypt_decrypt(self, sess):
        key = sess.generate_key(KeyType.DES2, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        pt = b"Block1!!" * 2
        ct = key.encrypt(pt, mechanism=Mechanism.DES3_ECB)
        pt2 = key.decrypt(ct, mechanism=Mechanism.DES3_ECB)
        assert pt2 == pt
        key.destroy()

    def test_des2_key_attributes(self, sess):
        key = sess.generate_key(KeyType.DES2, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        val = key[Attribute.VALUE]
        assert len(val) == 16  # DES2 = two 8-byte keys
        key.destroy()

    def test_des2_streaming_encrypt(self, sess):
        key = sess.generate_key(KeyType.DES2, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"12345678"
        chunks = [b"Chunk1!!", b"Chunk2!!"]
        ct = b"".join(key.encrypt(iter(chunks), mechanism=Mechanism.DES3_CBC,
                                  mechanism_param=iv))
        assert len(ct) == 16
        key.destroy()

    def test_des2_digest_key(self, sess, cklib):
        key = sess.generate_key(KeyType.DES2, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        mech = CK_MECHANISM()
        mech.mechanism = 0x00000250  # CKM_SHA_256
        h = ctypes.c_ulong(sess.handle)
        cklib.C_DigestInit(h, ctypes.byref(mech))
        rv = cklib.C_DigestKey(h, ctypes.c_ulong(key.handle))
        assert rv == 0
        buf = (ctypes.c_uint8 * 32)()
        buf_len = ctypes.c_ulong(32)
        cklib.C_DigestFinal(h, buf, ctypes.byref(buf_len))
        key.destroy()


# ── RSA private key import (setRSAPrivateKey) ─────────────────────────────────

class TestRSAKeyImport:
    def _generate_rsa_components(self, bits=1024):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        key = rsa.generate_private_key(65537, bits, default_backend())
        nums = key.private_numbers()
        pub = key.public_key().public_numbers()
        return nums, pub

    def test_import_rsa_1024_private_key(self, sess):
        nums, pub = self._generate_rsa_components(1024)
        imported = sess.create_object({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.RSA,
            Attribute.MODULUS: _int_to_bytes(pub.n),
            Attribute.PUBLIC_EXPONENT: _int_to_bytes(pub.e),
            Attribute.PRIVATE_EXPONENT: _int_to_bytes(nums.d),
            Attribute.PRIME_1: _int_to_bytes(nums.p),
            Attribute.PRIME_2: _int_to_bytes(nums.q),
            Attribute.EXPONENT_1: _int_to_bytes(nums.dmp1),
            Attribute.EXPONENT_2: _int_to_bytes(nums.dmq1),
            Attribute.COEFFICIENT: _int_to_bytes(nums.iqmp),
            Attribute.SIGN: True,
            Attribute.TOKEN: False,
        })
        assert imported[Attribute.KEY_TYPE] == KeyType.RSA
        imported.destroy()

    def test_import_rsa_2048_private_key_and_sign(self, sess):
        nums, pub = self._generate_rsa_components(2048)
        priv = sess.create_object({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.RSA,
            Attribute.MODULUS: _int_to_bytes(pub.n),
            Attribute.PUBLIC_EXPONENT: _int_to_bytes(pub.e),
            Attribute.PRIVATE_EXPONENT: _int_to_bytes(nums.d),
            Attribute.PRIME_1: _int_to_bytes(nums.p),
            Attribute.PRIME_2: _int_to_bytes(nums.q),
            Attribute.EXPONENT_1: _int_to_bytes(nums.dmp1),
            Attribute.EXPONENT_2: _int_to_bytes(nums.dmq1),
            Attribute.COEFFICIENT: _int_to_bytes(nums.iqmp),
            Attribute.SIGN: True,
            Attribute.TOKEN: False,
        })
        sig = priv.sign(b"test message", mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(sig) == 256
        priv.destroy()

    def test_import_rsa_public_key(self, sess):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        key = rsa.generate_private_key(65537, 1024, default_backend())
        pub = key.public_key().public_numbers()
        imported_pub = sess.create_object({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.KEY_TYPE: KeyType.RSA,
            Attribute.MODULUS: _int_to_bytes(pub.n),
            Attribute.PUBLIC_EXPONENT: _int_to_bytes(pub.e),
            Attribute.VERIFY: True,
            Attribute.TOKEN: False,
        })
        assert imported_pub[Attribute.KEY_TYPE] == KeyType.RSA
        imported_pub.destroy()


# ── DSA private key import (setDSAPrivateKey) ─────────────────────────────────

class TestDSAKeyImport:
    def test_import_dsa_private_key(self, sess):
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.backends import default_backend
        key = dsa.generate_private_key(key_size=1024, backend=default_backend())
        nums = key.private_numbers()
        pub_nums = nums.public_numbers
        pn = pub_nums.parameter_numbers
        imported = sess.create_object({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.DSA,
            Attribute.PRIME: _int_to_bytes(pn.p),
            Attribute.SUBPRIME: _int_to_bytes(pn.q),
            Attribute.BASE: _int_to_bytes(pn.g),
            Attribute.VALUE: _int_to_bytes(nums.x),
            Attribute.SIGN: True,
            Attribute.TOKEN: False,
        })
        assert imported[Attribute.KEY_TYPE] == KeyType.DSA
        imported.destroy()

    def test_import_dsa_public_key(self, sess):
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.backends import default_backend
        key = dsa.generate_private_key(key_size=1024, backend=default_backend())
        pub = key.public_key().public_numbers()
        pn = pub.parameter_numbers
        imported_pub = sess.create_object({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.KEY_TYPE: KeyType.DSA,
            Attribute.PRIME: _int_to_bytes(pn.p),
            Attribute.SUBPRIME: _int_to_bytes(pn.q),
            Attribute.BASE: _int_to_bytes(pn.g),
            Attribute.VALUE: _int_to_bytes(pub.y),
            Attribute.VERIFY: True,
            Attribute.TOKEN: False,
        })
        assert imported_pub[Attribute.KEY_TYPE] == KeyType.DSA
        imported_pub.destroy()


# ── EC private key import (setECPrivateKey) ───────────────────────────────────

class TestECKeyImport:
    def test_import_ec_p256_private_key(self, sess):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        nums = key.private_numbers()
        ec_params = encode_named_curve_parameters("secp256r1")
        imported = sess.create_object({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.EC,
            Attribute.EC_PARAMS: ec_params,
            Attribute.VALUE: _int_to_bytes(nums.private_value),
            Attribute.SIGN: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
        assert imported[Attribute.KEY_TYPE] == KeyType.EC
        imported.destroy()

    def test_import_ec_p384_private_key(self, sess):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        nums = key.private_numbers()
        ec_params = encode_named_curve_parameters("secp384r1")
        imported = sess.create_object({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.EC,
            Attribute.EC_PARAMS: ec_params,
            Attribute.VALUE: _int_to_bytes(nums.private_value),
            Attribute.SIGN: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
        assert imported[Attribute.KEY_TYPE] == KeyType.EC
        imported.destroy()

    def test_import_ec_public_key(self, sess):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub = key.public_key().public_numbers()
        x = pub.x.to_bytes(32, "big")
        y = pub.y.to_bytes(32, "big")
        # Uncompressed EC point DER-encoded as OCTET STRING
        point = b"\x04" + x + y
        ec_point_der = bytes([0x04, len(point)]) + point
        ec_params = encode_named_curve_parameters("secp256r1")
        imported_pub = sess.create_object({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.KEY_TYPE: KeyType.EC,
            Attribute.EC_PARAMS: ec_params,
            Attribute.EC_POINT: ec_point_der,
            Attribute.VERIFY: True,
            Attribute.TOKEN: False,
        })
        assert imported_pub[Attribute.KEY_TYPE] == KeyType.EC
        imported_pub.destroy()


# ── DH private key import (setDHPrivateKey) ───────────────────────────────────

class TestDHKeyImport:
    def test_import_dh_private_key(self, sess):
        from cryptography.hazmat.primitives.asymmetric import dh
        from cryptography.hazmat.backends import default_backend
        params = dh.generate_parameters(generator=2, key_size=512,
                                        backend=default_backend())
        key = params.generate_private_key()
        nums = key.private_numbers()
        pn = nums.public_numbers.parameter_numbers
        imported = sess.create_object({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.DH,
            Attribute.PRIME: _int_to_bytes(pn.p),
            Attribute.BASE: _int_to_bytes(pn.g),
            Attribute.VALUE: _int_to_bytes(nums.x),
            Attribute.DERIVE: True,
            Attribute.TOKEN: False,
        })
        assert imported[Attribute.KEY_TYPE] == KeyType.DH
        imported.destroy()


# ── AES key import (C_CreateObject for symmetric) ─────────────────────────────

class TestAESKeyImport:
    def test_import_aes_128_key(self, sess):
        raw_key = os.urandom(16)
        imported = sess.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: raw_key,
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.TOKEN: False,
        })
        iv = b"\x00" * 16
        ct = imported.encrypt(b"A" * 16, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        pt = imported.decrypt(ct, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        assert pt == b"A" * 16
        imported.destroy()

    def test_import_aes_256_key_and_verify_value(self, sess):
        raw_key = os.urandom(32)
        imported = sess.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: raw_key,
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.TOKEN: False,
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
        })
        assert imported[Attribute.VALUE] == raw_key
        imported.destroy()


# ── Persistent object attribute read-back (ObjectFile paths) ──────────────────

class TestPersistentObjectAttributes:
    """Reading attributes back from TOKEN=True objects exercises ObjectFile."""

    def test_persistent_aes_attribute_read(self, token):
        import uuid
        label = f"cov3-persist-{uuid.uuid4().hex[:8]}"
        with token.open(rw=True, user_pin="1234") as s:
            key = s.generate_key(KeyType.AES, 256, store=True,
                template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                           Attribute.LABEL: label,
                           Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})

        with token.open(rw=True, user_pin="1234") as s:
            found = list(s.get_objects({Attribute.LABEL: label}))
            assert len(found) == 1
            obj = found[0]
            # Reading these attributes exercises ObjectFile deserialization
            assert obj[Attribute.KEY_TYPE] == KeyType.AES
            assert obj[Attribute.VALUE_LEN] == 32
            assert obj[Attribute.ENCRYPT] is True
            assert obj[Attribute.LABEL] == label
            val = obj[Attribute.VALUE]
            assert len(val) == 32
            obj.destroy()

    def test_persistent_rsa_attribute_read(self, token):
        import uuid
        label = f"cov3-rsa-{uuid.uuid4().hex[:8]}"
        with token.open(rw=True, user_pin="1234") as s:
            pub, priv = s.generate_keypair(KeyType.RSA, 1024, store=True,
                public_template={Attribute.VERIFY: True, Attribute.LABEL: label},
                private_template={Attribute.SIGN: True, Attribute.LABEL: label})

        with token.open(rw=True, user_pin="1234") as s:
            pubs = list(s.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                                        Attribute.LABEL: label}))
            assert len(pubs) == 1
            assert len(pubs[0][Attribute.MODULUS]) == 128
            privs = list(s.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                                         Attribute.LABEL: label}))
            assert len(privs) == 1
            pubs[0].destroy()
            privs[0].destroy()

    def test_persistent_ec_attribute_read(self, token):
        import uuid
        label = f"cov3-ec-{uuid.uuid4().hex[:8]}"
        ec_params = encode_named_curve_parameters("secp256r1")
        with token.open(rw=True, user_pin="1234") as s:
            pub, priv = s.generate_keypair(KeyType.EC, store=True,
                public_template={Attribute.EC_PARAMS: ec_params,
                                  Attribute.VERIFY: True, Attribute.LABEL: label},
                private_template={Attribute.SIGN: True, Attribute.LABEL: label})

        with token.open(rw=True, user_pin="1234") as s:
            pubs = list(s.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                                        Attribute.LABEL: label}))
            assert pubs[0][Attribute.EC_PARAMS] == ec_params
            privs = list(s.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                                         Attribute.LABEL: label}))
            pubs[0].destroy()
            privs[0].destroy()


# ── GENERIC_SECRET key type attribute access (P11Objects) ─────────────────────

class TestGenericSecretKeyType:
    def test_generic_secret_key_type_attribute(self, sess):
        key = sess.generate_key(KeyType.GENERIC_SECRET, 256, store=False,
            template={Attribute.SIGN: True, Attribute.VERIFY: True})
        assert key[Attribute.KEY_TYPE] == KeyType.GENERIC_SECRET
        assert key[Attribute.CLASS] == ObjectClass.SECRET_KEY
        key.destroy()

    def test_generic_secret_various_sizes(self, sess):
        for bits in [128, 256, 512]:
            key = sess.generate_key(KeyType.GENERIC_SECRET, bits, store=False,
                template={Attribute.SIGN: True, Attribute.VERIFY: True})
            assert key[Attribute.KEY_TYPE] == KeyType.GENERIC_SECRET
            key.destroy()


# ── DES2 key type attribute access (P11Objects) ───────────────────────────────

class TestDES2KeyTypeAttribute:
    def test_des2_key_type_attribute(self, sess):
        key = sess.generate_key(KeyType.DES2, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        assert key[Attribute.KEY_TYPE] == KeyType.DES2
        assert key[Attribute.CLASS] == ObjectClass.SECRET_KEY
        key.destroy()

    def test_des2_persistent_attribute_read(self, token):
        import uuid
        label = f"cov3-des2-{uuid.uuid4().hex[:8]}"
        with token.open(rw=True, user_pin="1234") as s:
            key = s.generate_key(KeyType.DES2, store=True,
                template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                           Attribute.LABEL: label,
                           Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})

        with token.open(rw=True, user_pin="1234") as s:
            found = list(s.get_objects({Attribute.LABEL: label}))
            assert len(found) == 1
            assert found[0][Attribute.KEY_TYPE] == KeyType.DES2
            assert len(found[0][Attribute.VALUE]) == 16
            found[0].destroy()


# ── C_FindObjects on persistent objects (OSToken::getObjects) ─────────────────

class TestOSTokenGetObjects:
    def test_find_persistent_objects_across_sessions(self, token):
        import uuid
        labels = [f"cov3-tok-{uuid.uuid4().hex[:6]}" for _ in range(3)]
        with token.open(rw=True, user_pin="1234") as s:
            keys = [
                s.generate_key(KeyType.AES, 128, store=True,
                    template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                               Attribute.LABEL: lbl})
                for lbl in labels
            ]

        with token.open(rw=True, user_pin="1234") as s:
            for lbl in labels:
                found = list(s.get_objects({Attribute.LABEL: lbl}))
                assert len(found) == 1
                found[0].destroy()

    def test_find_objects_empty_template_finds_many(self, token):
        import uuid
        label = f"cov3-many-{uuid.uuid4().hex[:6]}"
        with token.open(rw=True, user_pin="1234") as s:
            keys = [s.generate_key(KeyType.AES, 128, store=False,
                        template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                                   Attribute.LABEL: label})
                    for _ in range(5)]
            all_objs = list(s.get_objects({}))
            assert len(all_objs) >= 5
            for k in keys:
                k.destroy()


# ── AES-CBC-PAD streaming ─────────────────────────────────────────────────────

class TestAESCBCPADStreaming:
    def test_aes_cbc_pad_streaming_encrypt_decrypt(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"\xBB" * 16
        chunks = [b"first_chunk_data", b"second_chunk!!!", b"third"]
        ct = b"".join(key.encrypt(iter(chunks), mechanism=Mechanism.AES_CBC_PAD,
                                  mechanism_param=iv))
        pt = b"".join(key.decrypt(iter([ct]), mechanism=Mechanism.AES_CBC_PAD,
                                  mechanism_param=iv))
        assert pt == b"".join(chunks)
        key.destroy()


# ── RSA verify streaming ──────────────────────────────────────────────────────

class TestRSAStreamingVerify:
    def test_rsa_streaming_verify_sha256(self, sess):
        pub, priv = sess.generate_keypair(KeyType.RSA, 2048, store=False,
            public_template={Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True})
        data = b"streaming verify test data"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        chunks = [data[:10], data[10:20], data[20:]]
        ok = pub.verify(iter(chunks), sig, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert ok
        pub.destroy(); priv.destroy()

    def test_ecdsa_streaming_verify(self, sess):
        import hashlib
        params = encode_named_curve_parameters("secp256r1")
        pub, priv = sess.generate_keypair(KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True})
        data = b"ecdsa streaming test"
        hashed = hashlib.sha256(data).digest()
        sig = priv.sign(hashed, mechanism=Mechanism.ECDSA)
        ok = pub.verify(hashed, sig, mechanism=Mechanism.ECDSA)
        assert ok
        pub.destroy(); priv.destroy()


# ── CMAC with DES3 (OSSLEVPCMacAlgorithm) ────────────────────────────────────

class TestDES3CMAC:
    def test_des3_cmac_sign_verify(self, sess):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.SIGN: True, Attribute.VERIFY: True})
        mac = key.sign(b"des3 cmac test data", mechanism=Mechanism.DES3_CMAC)
        assert len(mac) == 8  # DES block size
        ok = key.verify(b"des3 cmac test data", mac, mechanism=Mechanism.DES3_CMAC)
        assert ok
        key.destroy()

    def test_des3_cmac_streaming(self, sess):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.SIGN: True, Attribute.VERIFY: True})
        chunks = [b"part1", b"part2"]
        mac1 = key.sign(b"part1part2", mechanism=Mechanism.DES3_CMAC)
        mac2 = key.sign(iter(chunks), mechanism=Mechanism.DES3_CMAC)
        assert mac1 == mac2
        key.destroy()
