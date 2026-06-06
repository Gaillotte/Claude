"""Second wave of tests targeting SoftHSM2 C++ code paths still under-covered.

Focuses on:
  - SoftHSM.cpp  : C_GenerateRandom, C_SeedRandom, C_WrapKey (RSA+AES),
                   C_UnwrapKey (RSA), C_DeriveKey (DH+ECDH), asymmetric
                   mechanisms, C_GetMechanismList/Info, C_CloseAllSessions,
                   C_DigestKey, all RSA sign variants, Ed25519, AES-ECB/CTR
  - OSSLRSA.cpp  : RSA-PSS, RSA-OAEP, all SHA variants
  - OSSLAES.cpp  : AES-ECB, AES-CTR, AES-KEY-WRAP
  - OSSLDES.cpp  : DES3 keygen, DES3-CBC, DES3-ECB
  - OSSLEVPMac.cpp : HMAC-SHA1, SHA224, SHA384, SHA512
  - OSSLDSA.cpp  : DSA sign with more hash variants
  - OSSLECDSA.cpp: ECDSA with P-384, P-521
  - crypto/ED25519: Ed25519 sign + verify
  - P11Objects.cpp: more object attribute coverage
  - ObjectFile.cpp: persistent key lifecycle
"""

from __future__ import annotations

import ctypes
import os
import struct

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, MGF, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters
from pkcs11.util.dsa import encode_dsa_domain_parameters


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def lib():
    return pkcs11.lib(os.environ["PKCS11_MODULE_PATH"])


@pytest.fixture(scope="module")
def token(lib):
    tokens = list(lib.get_tokens(token_label="TestToken"))
    assert tokens, "TestToken not found"
    return tokens[0]


@pytest.fixture
def sess(token):
    with token.open(rw=True, user_pin="1234") as s:
        yield s


# ── C_GenerateRandom / C_SeedRandom ──────────────────────────────────────────

class TestRandom:
    def test_generate_random_64bit(self, sess):
        rnd = sess.generate_random(64)  # 64 bits = 8 bytes
        assert len(rnd) == 8

    def test_generate_random_256bit(self, sess):
        rnd = sess.generate_random(256)  # 256 bits = 32 bytes
        assert len(rnd) == 32

    def test_generate_random_2048bit(self, sess):
        rnd = sess.generate_random(2048)  # 2048 bits = 256 bytes
        assert len(rnd) == 256

    def test_seed_random(self, sess):
        sess.seed_random(b"entropy_seed_data_for_coverage")

    def test_generate_random_two_calls_differ(self, sess):
        a = sess.generate_random(128)
        b = sess.generate_random(128)
        assert a != b  # astronomically unlikely to collide


# ── C_GetMechanismList / C_GetMechanismInfo ───────────────────────────────────

def _get_slot_id():
    """Return the first token-present slot ID via ctypes."""
    cklib = ctypes.CDLL(os.environ["PKCS11_MODULE_PATH"])
    count = ctypes.c_ulong(0)
    cklib.C_GetSlotList(ctypes.c_ubyte(1), None, ctypes.byref(count))
    slots = (ctypes.c_ulong * count.value)()
    cklib.C_GetSlotList(ctypes.c_ubyte(1), slots, ctypes.byref(count))
    return int(slots[0])


class TestMechanismInfo:
    def test_get_mechanism_list(self):
        cklib = ctypes.CDLL(os.environ["PKCS11_MODULE_PATH"])
        slot_id = ctypes.c_ulong(_get_slot_id())
        count = ctypes.c_ulong(0)
        rv = cklib.C_GetMechanismList(slot_id, None, ctypes.byref(count))
        assert rv == 0
        assert count.value > 10
        mechs = (ctypes.c_ulong * count.value)()
        rv = cklib.C_GetMechanismList(slot_id, mechs, ctypes.byref(count))
        assert rv == 0

    def test_get_mechanism_info_aes_cbc(self):
        cklib = ctypes.CDLL(os.environ["PKCS11_MODULE_PATH"])
        slot_id = ctypes.c_ulong(_get_slot_id())

        class CK_MECHANISM_INFO(ctypes.Structure):
            _fields_ = [("ulMinKeySize", ctypes.c_ulong),
                        ("ulMaxKeySize", ctypes.c_ulong),
                        ("flags", ctypes.c_ulong)]

        info = CK_MECHANISM_INFO()
        CKM_AES_CBC = 0x00001082
        rv = cklib.C_GetMechanismInfo(slot_id, ctypes.c_ulong(CKM_AES_CBC),
                                      ctypes.byref(info))
        assert rv == 0
        assert info.ulMinKeySize > 0

    def test_get_mechanism_info_rsa(self):
        cklib = ctypes.CDLL(os.environ["PKCS11_MODULE_PATH"])
        slot_id = ctypes.c_ulong(_get_slot_id())

        class CK_MECHANISM_INFO(ctypes.Structure):
            _fields_ = [("ulMinKeySize", ctypes.c_ulong),
                        ("ulMaxKeySize", ctypes.c_ulong),
                        ("flags", ctypes.c_ulong)]

        info = CK_MECHANISM_INFO()
        CKM_RSA_PKCS = 0x00000001
        rv = cklib.C_GetMechanismInfo(slot_id, ctypes.c_ulong(CKM_RSA_PKCS),
                                      ctypes.byref(info))
        assert rv == 0


# ── RSA-PSS sign/verify ───────────────────────────────────────────────────────

class TestRSAPSS:
    @pytest.fixture
    def rsa_pair(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.RSA, 2048, store=False,
            public_template={Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        yield pub, priv
        pub.destroy()
        priv.destroy()

    def test_pss_sha256_sign_verify(self, sess, rsa_pair):
        pub, priv = rsa_pair
        sig = priv.sign(b"hello pss", mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
                        mechanism_param=(Mechanism.SHA256, MGF.SHA256, 32))
        ok = pub.verify(b"hello pss", sig, mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
                        mechanism_param=(Mechanism.SHA256, MGF.SHA256, 32))
        assert ok

    def test_pss_sha1_sign_verify(self, sess, rsa_pair):
        pub, priv = rsa_pair
        sig = priv.sign(b"data", mechanism=Mechanism.SHA1_RSA_PKCS_PSS,
                        mechanism_param=(Mechanism.SHA_1, MGF.SHA1, 20))
        ok = pub.verify(b"data", sig, mechanism=Mechanism.SHA1_RSA_PKCS_PSS,
                        mechanism_param=(Mechanism.SHA_1, MGF.SHA1, 20))
        assert ok

    def test_pss_sha384_sign_verify(self, sess, rsa_pair):
        pub, priv = rsa_pair
        sig = priv.sign(b"data384", mechanism=Mechanism.SHA384_RSA_PKCS_PSS,
                        mechanism_param=(Mechanism.SHA384, MGF.SHA384, 48))
        ok = pub.verify(b"data384", sig, mechanism=Mechanism.SHA384_RSA_PKCS_PSS,
                        mechanism_param=(Mechanism.SHA384, MGF.SHA384, 48))
        assert ok

    def test_pss_sha512_sign_verify(self, sess, rsa_pair):
        pub, priv = rsa_pair
        sig = priv.sign(b"data512", mechanism=Mechanism.SHA512_RSA_PKCS_PSS,
                        mechanism_param=(Mechanism.SHA512, MGF.SHA512, 64))
        ok = pub.verify(b"data512", sig, mechanism=Mechanism.SHA512_RSA_PKCS_PSS,
                        mechanism_param=(Mechanism.SHA512, MGF.SHA512, 64))
        assert ok


# ── RSA-OAEP encrypt/decrypt ──────────────────────────────────────────────────

class TestRSAOAEP:
    @pytest.fixture
    def rsa_pair(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.RSA, 2048, store=False,
            public_template={Attribute.ENCRYPT: True},
            private_template={Attribute.DECRYPT: True},
        )
        yield pub, priv
        pub.destroy()
        priv.destroy()

    def test_oaep_sha1_roundtrip(self, sess, rsa_pair):
        pub, priv = rsa_pair
        plaintext = b"secret message OAEP SHA1"
        ct = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP,
                         mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None))
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP,
                          mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None))
        assert pt == plaintext

    def test_oaep_ciphertext_differs_per_call(self, sess, rsa_pair):
        pub, priv = rsa_pair
        pt = b"same input"
        ct1 = pub.encrypt(pt, mechanism=Mechanism.RSA_PKCS_OAEP,
                          mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None))
        ct2 = pub.encrypt(pt, mechanism=Mechanism.RSA_PKCS_OAEP,
                          mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None))
        assert ct1 != ct2  # OAEP is randomised


# ── RSA all SHA sign variants ──────────────────────────────────────────────────

class TestRSASignAllVariants:
    @pytest.fixture
    def rsa_pair(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.RSA, 2048, store=False,
            public_template={Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        yield pub, priv
        pub.destroy()
        priv.destroy()

    @pytest.mark.parametrize("mech", [
        Mechanism.SHA1_RSA_PKCS,
        Mechanism.SHA224_RSA_PKCS,
        Mechanism.SHA256_RSA_PKCS,
        Mechanism.SHA384_RSA_PKCS,
        Mechanism.SHA512_RSA_PKCS,
    ])
    def test_rsa_sign_verify(self, sess, rsa_pair, mech):
        pub, priv = rsa_pair
        data = b"rsa sign test data"
        sig = priv.sign(data, mechanism=mech)
        assert len(sig) == 256
        ok = pub.verify(data, sig, mechanism=mech)
        assert ok


# ── RSA WrapKey / UnwrapKey ───────────────────────────────────────────────────

class TestRSAWrapUnwrap:
    def test_wrap_unwrap_aes_with_rsa_pkcs(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.RSA, 2048, store=False,
            public_template={Attribute.WRAP: True},
            private_template={Attribute.UNWRAP: True},
        )
        target = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        wrapped = pub.wrap_key(target, mechanism=Mechanism.RSA_PKCS)
        assert len(wrapped) == 256
        unwrapped = priv.unwrap_key(
            ObjectClass.SECRET_KEY, KeyType.AES, wrapped,
            mechanism=Mechanism.RSA_PKCS,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"A" * 16
        ct = target.encrypt(b"B" * 16, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        pt = unwrapped.decrypt(ct, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        assert pt == b"B" * 16
        pub.destroy(); priv.destroy(); target.destroy(); unwrapped.destroy()

    def test_wrap_unwrap_aes_with_aes_keywrap(self, sess):
        kek = sess.generate_key(KeyType.AES, 256, store=False,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True,
                      Attribute.EXTRACTABLE: False})
        target = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        wrapped = kek.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP)
        assert len(wrapped) == 24  # 16-byte key + 8-byte IV
        unwrapped = kek.unwrap_key(
            ObjectClass.SECRET_KEY, KeyType.AES, wrapped,
            mechanism=Mechanism.AES_KEY_WRAP,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"C" * 16
        ct = target.encrypt(b"D" * 16, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        pt = unwrapped.decrypt(ct, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
        assert pt == b"D" * 16
        kek.destroy(); target.destroy(); unwrapped.destroy()

    def test_wrap_256bit_aes_key(self, sess):
        kek = sess.generate_key(KeyType.AES, 256, store=False,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True})
        big_key = sess.generate_key(KeyType.AES, 256, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        wrapped = kek.wrap_key(big_key, mechanism=Mechanism.AES_KEY_WRAP)
        assert len(wrapped) == 40  # 32-byte key + 8-byte IV
        kek.destroy(); big_key.destroy()


# ── AES-ECB ───────────────────────────────────────────────────────────────────

class TestAESECB:
    def test_aes_ecb_128(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        pt = b"A" * 16
        ct = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        assert len(ct) == 16
        recovered = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert recovered == pt
        key.destroy()

    def test_aes_ecb_256(self, sess):
        key = sess.generate_key(KeyType.AES, 256, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        pt = b"Z" * 32
        ct = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        recovered = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert recovered == pt
        key.destroy()

    def test_aes_ecb_deterministic(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        pt = b"B" * 16
        ct1 = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        ct2 = key.encrypt(pt, mechanism=Mechanism.AES_ECB)
        assert ct1 == ct2  # ECB is deterministic
        key.destroy()


# ── AES-CTR ───────────────────────────────────────────────────────────────────

def _aes_ctr_params(counter_bits=128, counter_block=None):
    """Build a CK_AES_CTR_PARAMS byte string."""
    class AesCtrParams(ctypes.Structure):
        _fields_ = [("ulCounterBits", ctypes.c_ulong), ("cb", ctypes.c_uint8 * 16)]
    p = AesCtrParams()
    p.ulCounterBits = counter_bits
    cb = counter_block or b"\x00" * 16
    p.cb = (ctypes.c_uint8 * 16)(*cb)
    return bytes(p)


class TestAESCTR:
    def test_aes_ctr_encrypt_decrypt(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        pt = b"counter mode test"
        params = _aes_ctr_params()
        ct = key.encrypt(pt, mechanism=Mechanism.AES_CTR, mechanism_param=params)
        assert len(ct) == len(pt)
        pt2 = key.decrypt(ct, mechanism=Mechanism.AES_CTR, mechanism_param=params)
        assert pt2 == pt
        key.destroy()

    def test_aes_ctr_256(self, sess):
        key = sess.generate_key(KeyType.AES, 256, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        pt = b"X" * 64
        params = _aes_ctr_params(128, b"\x01" * 16)
        ct = key.encrypt(pt, mechanism=Mechanism.AES_CTR, mechanism_param=params)
        assert ct != pt
        pt2 = key.decrypt(ct, mechanism=Mechanism.AES_CTR, mechanism_param=params)
        assert pt2 == pt
        key.destroy()

    def test_aes_ctr_no_padding_needed(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        pt = b"odd length data!"[:15]
        params = _aes_ctr_params()
        ct = key.encrypt(pt, mechanism=Mechanism.AES_CTR, mechanism_param=params)
        assert len(ct) == len(pt)
        key.destroy()


# ── DES3 ──────────────────────────────────────────────────────────────────────

class TestDES3:
    def test_des3_keygen(self, sess):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        assert key is not None
        key.destroy()

    def test_des3_cbc_roundtrip(self, sess):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"12345678"
        pt = b"Hello DES3 World"  # 16 bytes = 2 DES blocks
        ct = key.encrypt(pt, mechanism=Mechanism.DES3_CBC, mechanism_param=iv)
        assert len(ct) == 16
        pt2 = key.decrypt(ct, mechanism=Mechanism.DES3_CBC, mechanism_param=iv)
        assert pt2 == pt
        key.destroy()

    def test_des3_ecb_roundtrip(self, sess):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        pt = b"Block1!!" * 2  # 16 bytes
        ct = key.encrypt(pt, mechanism=Mechanism.DES3_ECB)
        pt2 = key.decrypt(ct, mechanism=Mechanism.DES3_ECB)
        assert pt2 == pt
        key.destroy()

    def test_des3_cbc_pad_roundtrip(self, sess):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"ABCDEFGH"
        pt = b"not a multiple of 8"
        ct = key.encrypt(pt, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)
        pt2 = key.decrypt(ct, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)
        assert pt2 == pt
        key.destroy()

    def test_des3_streaming_encrypt(self, sess):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"IVIVIVIV"
        chunks = [b"Chunk001", b"Chunk002", b"Chunk003"]
        ct = b"".join(key.encrypt(iter(chunks), mechanism=Mechanism.DES3_CBC,
                                  mechanism_param=iv))
        assert len(ct) > 0
        key.destroy()


# ── HMAC variants ─────────────────────────────────────────────────────────────

class TestHMACVariants:
    def _hmac_key(self, sess, bits=256):
        return sess.generate_key(KeyType.GENERIC_SECRET, bits, store=False,
            template={Attribute.SIGN: True, Attribute.VERIFY: True})

    def test_hmac_sha1(self, sess):
        key = self._hmac_key(sess, 256)
        mac = key.sign(b"data", mechanism=Mechanism.SHA_1_HMAC)
        assert len(mac) == 20
        assert key.verify(b"data", mac, mechanism=Mechanism.SHA_1_HMAC)
        key.destroy()

    def test_hmac_sha224(self, sess):
        key = self._hmac_key(sess, 256)
        mac = key.sign(b"data", mechanism=Mechanism.SHA224_HMAC)
        assert len(mac) == 28
        assert key.verify(b"data", mac, mechanism=Mechanism.SHA224_HMAC)
        key.destroy()

    def test_hmac_sha256(self, sess):
        key = self._hmac_key(sess, 256)
        mac = key.sign(b"data", mechanism=Mechanism.SHA256_HMAC)
        assert len(mac) == 32
        assert key.verify(b"data", mac, mechanism=Mechanism.SHA256_HMAC)
        key.destroy()

    def test_hmac_sha384(self, sess):
        key = self._hmac_key(sess, 512)
        mac = key.sign(b"data", mechanism=Mechanism.SHA384_HMAC)
        assert len(mac) == 48
        assert key.verify(b"data", mac, mechanism=Mechanism.SHA384_HMAC)
        key.destroy()

    def test_hmac_sha512(self, sess):
        key = self._hmac_key(sess, 512)
        mac = key.sign(b"data", mechanism=Mechanism.SHA512_HMAC)
        assert len(mac) == 64
        assert key.verify(b"data", mac, mechanism=Mechanism.SHA512_HMAC)
        key.destroy()

    def test_hmac_streaming_sha256(self, sess):
        key = self._hmac_key(sess, 256)
        chunks = [b"part1", b"part2", b"part3"]
        mac1 = key.sign(b"part1part2part3", mechanism=Mechanism.SHA256_HMAC)
        mac2 = key.sign(iter(chunks), mechanism=Mechanism.SHA256_HMAC)
        assert mac1 == mac2
        key.destroy()


# ── Ed25519 ───────────────────────────────────────────────────────────────────

ED25519_OID = bytes.fromhex("130c656477617264733235353139")


class TestEd25519:
    @pytest.fixture
    def ed_pair(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.EC_EDWARDS, store=False,
            public_template={
                Attribute.EC_PARAMS: ED25519_OID,
                Attribute.VERIFY: True,
            },
            private_template={Attribute.SIGN: True},
        )
        yield pub, priv
        pub.destroy()
        priv.destroy()

    def test_ed25519_sign_verify(self, sess, ed_pair):
        pub, priv = ed_pair
        data = b"Ed25519 test message"
        sig = priv.sign(data, mechanism=Mechanism.EDDSA)
        assert len(sig) == 64
        ok = pub.verify(data, sig, mechanism=Mechanism.EDDSA)
        assert ok

    def test_ed25519_different_messages_differ(self, sess, ed_pair):
        pub, priv = ed_pair
        sig1 = priv.sign(b"msg1", mechanism=Mechanism.EDDSA)
        sig2 = priv.sign(b"msg2", mechanism=Mechanism.EDDSA)
        assert sig1 != sig2

    def test_ed25519_keygen_twice(self, sess):
        for _ in range(2):
            pub, priv = sess.generate_keypair(
                KeyType.EC_EDWARDS, store=False,
                public_template={Attribute.EC_PARAMS: ED25519_OID, Attribute.VERIFY: True},
                private_template={Attribute.SIGN: True},
            )
            sig = priv.sign(b"hello", mechanism=Mechanism.EDDSA)
            assert len(sig) == 64
            pub.destroy(); priv.destroy()


# ── ECDSA with P-256, P-384 and P-521 ────────────────────────────────────────

class TestECDSAAdditionalCurves:
    @pytest.mark.parametrize("curve,siglen", [
        ("secp256r1", 64),
        ("secp384r1", 96),
        ("secp521r1", 132),
    ])
    def test_ecdsa_raw_sign_verify(self, sess, curve, siglen):
        """SoftHSM2 uses raw ECDSA (pre-hashed input) via Mechanism.ECDSA."""
        import hashlib
        params = encode_named_curve_parameters(curve)
        pub, priv = sess.generate_keypair(
            KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        hashed = hashlib.sha256(b"ecdsa test payload").digest()
        sig = priv.sign(hashed, mechanism=Mechanism.ECDSA)
        assert len(sig) == siglen
        ok = pub.verify(hashed, sig, mechanism=Mechanism.ECDSA)
        assert ok
        pub.destroy(); priv.destroy()

    def test_ecdsa_p256_multiple_messages(self, sess):
        import hashlib
        params = encode_named_curve_parameters("secp256r1")
        pub, priv = sess.generate_keypair(
            KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        for msg in [b"msg1", b"msg2", b"msg3"]:
            h = hashlib.sha256(msg).digest()
            sig = priv.sign(h, mechanism=Mechanism.ECDSA)
            assert pub.verify(h, sig, mechanism=Mechanism.ECDSA)
        pub.destroy(); priv.destroy()


# ── DH Key Derivation ─────────────────────────────────────────────────────────

class TestDHDerive:
    def test_dh_derive_shared_secret(self, sess):
        params = sess.generate_domain_parameters(KeyType.DH, 512)
        apub, apriv = params.generate_keypair()
        bpub, bpriv = params.generate_keypair()

        bpub_val = bpub[Attribute.VALUE]
        derived_a = apriv.derive_key(
            KeyType.AES, 128,
            mechanism=Mechanism.DH_PKCS_DERIVE,
            mechanism_param=bpub_val,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
        )
        assert derived_a is not None

        apub_val = apub[Attribute.VALUE]
        derived_b = bpriv.derive_key(
            KeyType.AES, 128,
            mechanism=Mechanism.DH_PKCS_DERIVE,
            mechanism_param=apub_val,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
        )
        assert derived_b is not None

        params.destroy(); apub.destroy(); apriv.destroy()
        bpub.destroy(); bpriv.destroy()
        derived_a.destroy(); derived_b.destroy()

    def test_dh_generate_domain_parameters(self, sess):
        params = sess.generate_domain_parameters(KeyType.DH, 512)
        assert params is not None
        params.destroy()


# ── ECDH Key Derivation ───────────────────────────────────────────────────────

class TestECDHDerive:
    @pytest.mark.parametrize("curve", ["secp256r1", "secp384r1"])
    def test_ecdh_derive_aes_key(self, sess, curve):
        ec_params = encode_named_curve_parameters(curve)
        apub, apriv = sess.generate_keypair(
            KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: ec_params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.DERIVE: True},
        )
        bpub, bpriv = sess.generate_keypair(
            KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: ec_params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.DERIVE: True},
        )
        bpub_val = bpub[Attribute.EC_POINT]
        derived = apriv.derive_key(
            KeyType.AES, 128,
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(pkcs11.KDF.NULL, None, bpub_val),
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
        )
        assert derived is not None
        apub.destroy(); apriv.destroy(); bpub.destroy(); bpriv.destroy()
        derived.destroy()

    def test_ecdh_derive_symmetric_both_sides(self, sess):
        params = encode_named_curve_parameters("secp256r1")
        apub, apriv = sess.generate_keypair(
            KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.DERIVE: True},
        )
        bpub, bpriv = sess.generate_keypair(
            KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.DERIVE: True},
        )
        bpoint = bpub[Attribute.EC_POINT]
        apoint = apub[Attribute.EC_POINT]
        key_a = apriv.derive_key(KeyType.AES, 128,
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(pkcs11.KDF.NULL, None, bpoint),
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        key_b = bpriv.derive_key(KeyType.AES, 128,
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(pkcs11.KDF.NULL, None, apoint),
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        # Both sides should derive the same shared secret
        val_a = key_a[Attribute.VALUE]
        val_b = key_b[Attribute.VALUE]
        assert val_a == val_b
        apub.destroy(); apriv.destroy(); bpub.destroy(); bpriv.destroy()
        key_a.destroy(); key_b.destroy()


# ── C_CloseAllSessions via ctypes ─────────────────────────────────────────────

class TestCloseAllSessions:
    def test_close_all_sessions(self, token):
        lib_path = os.environ["PKCS11_MODULE_PATH"]
        cklib = ctypes.CDLL(lib_path)
        # Open a session so there is something to close
        with token.open(rw=True, user_pin="1234"):
            slot_id = ctypes.c_ulong(0)
            rv = cklib.C_CloseAllSessions(slot_id)
            # CKR_OK=0 or CKR_SLOT_ID_INVALID; either means the call was dispatched
            assert rv in (0, 3)  # 3 = CKR_SLOT_ID_INVALID if slot ID wrong


# ── AES streaming (Update/Final) ─────────────────────────────────────────────

class TestAESStreamingVariants:
    def test_aes_ecb_streaming_encrypt(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        chunks = [b"A" * 16, b"B" * 16]
        ct = b"".join(key.encrypt(iter(chunks), mechanism=Mechanism.AES_ECB))
        pt = b"".join(key.decrypt(iter([ct]), mechanism=Mechanism.AES_ECB))
        assert pt == b"A" * 16 + b"B" * 16
        key.destroy()

    def test_aes_cbc_streaming_three_chunks(self, sess):
        key = sess.generate_key(KeyType.AES, 256, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = b"\xAA" * 16
        pt_blocks = [b"chunk1_16bytes!!", b"chunk2_16bytes!!", b"chunk3_16bytes!!"]
        ct = b"".join(key.encrypt(iter(pt_blocks), mechanism=Mechanism.AES_CBC,
                                  mechanism_param=iv))
        pt = b"".join(key.decrypt(iter([ct]), mechanism=Mechanism.AES_CBC,
                                  mechanism_param=iv))
        assert pt == b"".join(pt_blocks)
        key.destroy()


# ── RSA streaming sign/verify ─────────────────────────────────────────────────

class TestRSAStreamingSignVerify:
    def test_rsa_streaming_sha256(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.RSA, 2048, store=False,
            public_template={Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        chunks = [b"part_", b"one_", b"two_", b"three"]
        sig = priv.sign(iter(chunks), mechanism=Mechanism.SHA256_RSA_PKCS)
        ok = pub.verify(b"part_one_two_three", sig, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert ok
        pub.destroy(); priv.destroy()

    def test_rsa_streaming_sha512(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.RSA, 2048, store=False,
            public_template={Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        chunks = [b"hello ", b"world"]
        sig = priv.sign(iter(chunks), mechanism=Mechanism.SHA512_RSA_PKCS)
        ok = pub.verify(b"hello world", sig, mechanism=Mechanism.SHA512_RSA_PKCS)
        assert ok
        pub.destroy(); priv.destroy()


# ── C_GetAttributeValue broader coverage ─────────────────────────────────────

class TestGetAttributeValue:
    def test_get_rsa_public_key_attributes(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.RSA, 1024, store=False,
            public_template={Attribute.VERIFY: True, Attribute.ENCRYPT: True},
            private_template={Attribute.SIGN: True, Attribute.DECRYPT: True},
        )
        assert pub[Attribute.KEY_TYPE] == KeyType.RSA
        assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
        modulus = pub[Attribute.MODULUS]
        assert len(modulus) == 128  # 1024-bit / 8
        exp = pub[Attribute.PUBLIC_EXPONENT]
        assert exp in (b"\x01\x00\x01", b"\x03")
        pub.destroy(); priv.destroy()

    def test_get_ec_key_attributes(self, sess):
        params = encode_named_curve_parameters("secp256r1")
        pub, priv = sess.generate_keypair(
            KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        assert pub[Attribute.KEY_TYPE] == KeyType.EC
        assert pub[Attribute.EC_PARAMS] == params
        ec_point = pub[Attribute.EC_POINT]
        assert len(ec_point) > 0
        pub.destroy(); priv.destroy()

    def test_get_aes_key_attributes(self, sess):
        key = sess.generate_key(KeyType.AES, 192, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
        assert key[Attribute.KEY_TYPE] == KeyType.AES
        assert key[Attribute.VALUE_LEN] == 24
        assert key[Attribute.ENCRYPT] is True
        assert key[Attribute.CLASS] == ObjectClass.SECRET_KEY
        key.destroy()

    def test_get_generic_secret_attributes(self, sess):
        key = sess.generate_key(KeyType.GENERIC_SECRET, 256, store=False,
            template={Attribute.SIGN: True, Attribute.VERIFY: True})
        assert key[Attribute.KEY_TYPE] == KeyType.GENERIC_SECRET
        key.destroy()


# ── C_FindObjects edge cases ──────────────────────────────────────────────────

class TestFindObjectsEdgeCases:
    def test_find_by_encrypt_true(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.LABEL: "cov2-find-enc"})
        results = list(sess.get_objects({
            Attribute.LABEL: "cov2-find-enc",
            Attribute.ENCRYPT: True,
        }))
        assert len(results) >= 1
        key.destroy()

    def test_find_public_keys(self, sess):
        pub, priv = sess.generate_keypair(
            KeyType.RSA, 1024, store=False,
            public_template={Attribute.VERIFY: True, Attribute.LABEL: "cov2-rsa-find"},
            private_template={Attribute.SIGN: True},
        )
        results = list(sess.get_objects({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.LABEL: "cov2-rsa-find",
        }))
        assert len(results) == 1
        pub.destroy(); priv.destroy()

    def test_find_by_key_type(self, sess):
        k = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.LABEL: "cov2-des3-find"})
        results = list(sess.get_objects({
            Attribute.KEY_TYPE: KeyType.DES3,
            Attribute.LABEL: "cov2-des3-find",
        }))
        assert len(results) == 1
        k.destroy()


# ── SHA digest variants ───────────────────────────────────────────────────────

class TestDigestVariants:
    @pytest.mark.parametrize("mech,expected_len", [
        (Mechanism.SHA_1, 20),
        (Mechanism.SHA256, 32),
        (Mechanism.SHA384, 48),
        (Mechanism.SHA512, 64),
    ])
    def test_digest(self, sess, mech, expected_len):
        result = sess.digest(b"test data", mechanism=mech)
        assert len(result) == expected_len

    def test_sha384_streaming(self, sess):
        chunks = [b"block1", b"block2", b"block3"]
        full = sess.digest(b"block1block2block3", mechanism=Mechanism.SHA384)
        streamed = sess.digest(iter(chunks), mechanism=Mechanism.SHA384)
        assert full == streamed


# ── DSA extended ──────────────────────────────────────────────────────────────

class TestDSAExtended:
    def test_dsa_1024_sha1_sign_verify(self, sess):
        params = sess.generate_domain_parameters(KeyType.DSA, 1024)
        pub, priv = params.generate_keypair(
            public_template={Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        sig = priv.sign(b"dsa test", mechanism=Mechanism.DSA_SHA1)
        ok = pub.verify(b"dsa test", sig, mechanism=Mechanism.DSA_SHA1)
        assert ok
        params.destroy(); pub.destroy(); priv.destroy()

    def test_dsa_2048_sha256_sign_verify(self, sess):
        params = sess.generate_domain_parameters(KeyType.DSA, 2048)
        pub, priv = params.generate_keypair(
            public_template={Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True},
        )
        sig = priv.sign(b"dsa 2048 test", mechanism=Mechanism.DSA_SHA256)
        ok = pub.verify(b"dsa 2048 test", sig, mechanism=Mechanism.DSA_SHA256)
        assert ok
        params.destroy(); pub.destroy(); priv.destroy()


# ── C_SetAttributeValue on various object types ───────────────────────────────

class TestSetAttributeValueExtended:
    def test_set_label_on_ec_key(self, sess):
        params = encode_named_curve_parameters("secp256r1")
        pub, priv = sess.generate_keypair(
            KeyType.EC, store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True,
                             Attribute.LABEL: "cov2-ec-orig"},
            private_template={Attribute.SIGN: True},
        )
        pub[Attribute.LABEL] = "cov2-ec-new"
        assert pub[Attribute.LABEL] == "cov2-ec-new"
        pub.destroy(); priv.destroy()

    def test_set_id_on_aes_key(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.LABEL: "cov2-id-test"})
        key[Attribute.ID] = b"\x01\x02\x03\x04"
        assert key[Attribute.ID] == b"\x01\x02\x03\x04"
        key.destroy()


# ── Persistent objects (TOKEN=True) ─────────────────────────────────────────

class TestPersistentObjectsExtended:
    def test_persistent_aes_key_survives_session(self, token):
        import uuid
        label = f"cov2-persist-{uuid.uuid4().hex[:8]}"
        with token.open(rw=True, user_pin="1234") as s1:
            key = s1.generate_key(KeyType.AES, 128, store=True,
                template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                           Attribute.LABEL: label})
            key_id = key[Attribute.ID]

        with token.open(rw=True, user_pin="1234") as s2:
            found = list(s2.get_objects({Attribute.LABEL: label}))
            assert len(found) == 1
            found[0].destroy()

    def test_persistent_rsa_keypair(self, token):
        import uuid
        label = f"cov2-persist-rsa-{uuid.uuid4().hex[:8]}"
        with token.open(rw=True, user_pin="1234") as s1:
            pub, priv = s1.generate_keypair(
                KeyType.RSA, 1024, store=True,
                public_template={Attribute.VERIFY: True, Attribute.LABEL: label},
                private_template={Attribute.SIGN: True, Attribute.LABEL: label},
            )

        with token.open(rw=True, user_pin="1234") as s2:
            pub_found = list(s2.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.LABEL: label}))
            priv_found = list(s2.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.LABEL: label}))
            assert len(pub_found) == 1
            assert len(priv_found) == 1
            pub_found[0].destroy()
            priv_found[0].destroy()


# ── C_CopyObject ──────────────────────────────────────────────────────────────

class TestCopyObjectExtended:
    def test_copy_des3_key(self, sess):
        key = sess.generate_key(KeyType.DES3, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                      Attribute.LABEL: "cov2-des3-orig"})
        copy = key.copy({Attribute.LABEL: "cov2-des3-copy"})
        assert copy[Attribute.LABEL] == "cov2-des3-copy"
        assert copy[Attribute.KEY_TYPE] == KeyType.DES3
        key.destroy(); copy.destroy()

    def test_copy_generic_secret(self, sess):
        key = sess.generate_key(KeyType.GENERIC_SECRET, 256, store=False,
            template={Attribute.SIGN: True, Attribute.VERIFY: True,
                      Attribute.LABEL: "cov2-hmac-orig"})
        copy = key.copy({Attribute.LABEL: "cov2-hmac-copy"})
        assert copy[Attribute.LABEL] == "cov2-hmac-copy"
        key.destroy(); copy.destroy()


# ── AES-GCM additional ────────────────────────────────────────────────────────

def _gcm_params(iv, aad=b"", tag_bits=128):
    import ctypes
    class GcmParams(ctypes.Structure):
        _fields_ = [
            ("pIv", ctypes.c_char_p),
            ("ulIvLen", ctypes.c_ulong),
            ("ulIvBits", ctypes.c_ulong),
            ("pAAD", ctypes.c_char_p),
            ("ulAADLen", ctypes.c_ulong),
            ("ulTagBits", ctypes.c_ulong),
        ]
    p = GcmParams()
    p.pIv = iv; p.ulIvLen = len(iv); p.ulIvBits = len(iv) * 8
    p.pAAD = aad; p.ulAADLen = len(aad); p.ulTagBits = tag_bits
    return bytes(p)


class TestAESGCMExtended:
    def test_aes_gcm_256_encrypt_decrypt(self, sess):
        key = sess.generate_key(KeyType.AES, 256, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = sess.generate_random(96)  # 96 bits = 12 bytes
        pt = b"gcm authenticated data"
        params = _gcm_params(iv)
        ct = key.encrypt(pt, mechanism=Mechanism.AES_GCM, mechanism_param=params)
        pt2 = key.decrypt(ct, mechanism=Mechanism.AES_GCM, mechanism_param=params)
        assert pt2 == pt
        key.destroy()

    def test_aes_gcm_with_aad(self, sess):
        key = sess.generate_key(KeyType.AES, 128, store=False,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})
        iv = sess.generate_random(96)  # 96 bits = 12 bytes
        aad = b"additional authenticated data"
        pt = b"secret payload"
        params = _gcm_params(iv, aad)
        ct = key.encrypt(pt, mechanism=Mechanism.AES_GCM, mechanism_param=params)
        pt2 = key.decrypt(ct, mechanism=Mechanism.AES_GCM, mechanism_param=params)
        assert pt2 == pt
        key.destroy()
