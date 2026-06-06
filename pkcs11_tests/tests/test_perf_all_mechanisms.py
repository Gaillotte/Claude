"""Comprehensive performance benchmarks for every PKCS#11 mechanism supported
by SoftHSM2.  Results are accumulated in the ``perf_report`` session fixture
and written to ``perf_report.xlsx`` at the end of the test session.

Run:
    pytest tests/test_perf_all_mechanisms.py -v -s --no-cov

The Excel report is written to the project root regardless of whether tests
pass or fail.
"""

from __future__ import annotations

import hashlib
import os

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.util.ec import encode_named_curve_parameters

from pkcs11_app.aead import AEADOperations
from pkcs11_app.benchmark import BenchResult, run_benchmark
from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.derive import DeriveOperations
from pkcs11_app.mac import MACOperations
from pkcs11_app.objects import ObjectOperations
from pkcs11_app.report import PerfEntry, PerfReport
from pkcs11_app.token import TokenManager

pytestmark = pytest.mark.perf

# ── Payload sizes used across tests ───────────────────────────────────────────
_S64   =     64
_S1K   =   1024
_S64K  =  65536
_S1M   = 1048576

# ── Number of operations per benchmark ────────────────────────────────────────
_N_FAST   = 500   # AES, HMAC, digest
_N_MED    = 200   # RSA-verify, ECDSA-verify
_N_SLOW   = 30    # RSA-sign, ECDSA-sign
_N_KEYGEN = 20    # key generation (asymmetric)
_N_KEYGEN_FAST = 200  # AES / DES key generation

# ── Helpers ───────────────────────────────────────────────────────────────────

def _entry(result: BenchResult, category: str, mechanism: str,
           operation: str, key_bits: int = 0, notes: str = "") -> PerfEntry:
    return PerfEntry(
        category=category,
        mechanism=mechanism,
        operation=operation,
        key_bits=key_bits,
        payload_bytes=result.payload_bytes,
        ops_per_sec=result.ops_per_sec,
        latency_ms=result.latency_ms,
        throughput_mbs=result.throughput_mbs,
        notes=notes,
    )


# ── AES Symmetric ─────────────────────────────────────────────────────────────

class TestPerfAESCBC:
    @pytest.mark.parametrize("key_bits,payload", [
        (128, _S64),  (128, _S1K),  (128, _S64K), (128, _S1M),
        (192, _S1K),  (192, _S64K),
        (256, _S64),  (256, _S1K),  (256, _S64K), (256, _S1M),
    ])
    def test_aes_cbc_pad_encrypt(self, user_session, token_manager, perf_report, key_bits, payload):
        key = token_manager.generate_aes_key(user_session, key_bits, label=f"p-aes-cbc-{key_bits}", token=False)
        crypto = CryptoOperations()
        data = os.urandom(payload)
        result = run_benchmark(
            lambda: crypto.aes_cbc_encrypt(key, data),
            n_ops=_N_FAST, name=f"AES-{key_bits}-CBC-PAD-enc-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "AES", "AES_CBC_PAD", "encrypt", key_bits))
        key.destroy()

    @pytest.mark.parametrize("key_bits,payload", [
        (128, _S64),  (128, _S1K),  (128, _S64K), (128, _S1M),
        (256, _S64),  (256, _S1K),  (256, _S64K), (256, _S1M),
    ])
    def test_aes_cbc_pad_decrypt(self, user_session, token_manager, perf_report, key_bits, payload):
        key = token_manager.generate_aes_key(user_session, key_bits, label=f"p-aes-cbcd-{key_bits}", token=False)
        crypto = CryptoOperations()
        data = os.urandom(payload)
        ct, iv = crypto.aes_cbc_encrypt(key, data)
        result = run_benchmark(
            lambda: crypto.aes_cbc_decrypt(key, ct, iv),
            n_ops=_N_FAST, name=f"AES-{key_bits}-CBC-PAD-dec-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "AES", "AES_CBC_PAD", "decrypt", key_bits))
        key.destroy()


class TestPerfAESECB:
    @pytest.mark.parametrize("key_bits,payload", [
        (128, _S64), (128, _S1K), (128, _S64K),
        (256, _S64), (256, _S1K), (256, _S64K),
    ])
    def test_aes_ecb_encrypt(self, user_session, token_manager, perf_report, key_bits, payload):
        key = token_manager.generate_aes_key(user_session, key_bits, label=f"p-aes-ecb-{key_bits}", token=False)
        # payload must be multiple of 16
        data = os.urandom((payload // 16) * 16)
        result = run_benchmark(
            lambda: ObjectOperations.aes_cbc_nopad_encrypt(key, data, iv=bytes(16)),
            n_ops=_N_FAST, name=f"AES-{key_bits}-ECB-enc-{payload}B",
            payload_bytes=len(data), warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "AES", "AES_ECB", "encrypt", key_bits))
        key.destroy()


class TestPerfAESGCM:
    @pytest.mark.parametrize("key_bits,payload", [
        (128, _S64),  (128, _S1K),  (128, _S64K), (128, _S1M),
        (256, _S64),  (256, _S1K),  (256, _S64K), (256, _S1M),
    ])
    def test_aes_gcm_encrypt(self, user_session, token_manager, perf_report, key_bits, payload):
        key = token_manager.generate_aes_key(user_session, key_bits, label=f"p-aes-gcm-{key_bits}", token=False)
        aead = AEADOperations()
        data = os.urandom(payload)
        result = run_benchmark(
            lambda: aead.aes_gcm_encrypt(key, data),
            n_ops=_N_FAST, name=f"AES-{key_bits}-GCM-enc-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "AES", "AES_GCM", "encrypt", key_bits))
        key.destroy()

    @pytest.mark.parametrize("key_bits,payload", [
        (128, _S1K),  (128, _S64K),
        (256, _S1K),  (256, _S64K),
    ])
    def test_aes_gcm_decrypt(self, user_session, token_manager, perf_report, key_bits, payload):
        key = token_manager.generate_aes_key(user_session, key_bits, label=f"p-aes-gcmd-{key_bits}", token=False)
        aead = AEADOperations()
        data = os.urandom(payload)
        ct, nonce = aead.aes_gcm_encrypt(key, data)
        result = run_benchmark(
            lambda: aead.aes_gcm_decrypt(key, ct, nonce),
            n_ops=_N_FAST, name=f"AES-{key_bits}-GCM-dec-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "AES", "AES_GCM", "decrypt", key_bits))
        key.destroy()


class TestPerfAESCTR:
    @pytest.mark.parametrize("key_bits,payload", [
        (128, _S1K),  (128, _S64K),
        (256, _S1K),  (256, _S64K),
    ])
    def test_aes_ctr_encrypt(self, user_session, token_manager, perf_report, key_bits, payload):
        key = token_manager.generate_aes_key(user_session, key_bits, label=f"p-aes-ctr-{key_bits}", token=False)
        aead = AEADOperations()
        data = os.urandom(payload)
        result = run_benchmark(
            lambda: aead.aes_ctr_encrypt(key, data),
            n_ops=_N_FAST, name=f"AES-{key_bits}-CTR-enc-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "AES", "AES_CTR", "encrypt", key_bits))
        key.destroy()


# ── DES3 Symmetric ────────────────────────────────────────────────────────────

class TestPerfDES3:
    @pytest.mark.parametrize("payload", [_S64, _S1K, _S64K])
    def test_des3_cbc_pad_encrypt(self, user_session, token_manager, perf_report, payload):
        key = token_manager.generate_des3_key(user_session, label="p-des3-cbc", token=False)
        data = os.urandom(payload)
        iv   = os.urandom(8)
        result = run_benchmark(
            lambda: key.encrypt(data, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv),
            n_ops=_N_FAST, name=f"DES3-CBC-PAD-enc-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "DES3", "DES3_CBC_PAD", "encrypt", 168))
        key.destroy()

    @pytest.mark.parametrize("payload", [_S64, _S1K, _S64K])
    def test_des3_ecb_encrypt(self, user_session, token_manager, perf_report, payload):
        key = token_manager.generate_des3_key(user_session, label="p-des3-ecb", token=False)
        data = os.urandom((payload // 8) * 8)
        result = run_benchmark(
            lambda: ObjectOperations.des3_ecb_encrypt(key, data),
            n_ops=_N_FAST, name=f"DES3-ECB-enc-{payload}B",
            payload_bytes=len(data), warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "DES3", "DES3_ECB", "encrypt", 168))
        key.destroy()


# ── RSA ───────────────────────────────────────────────────────────────────────

class TestPerfRSAPKCS1:
    @pytest.mark.parametrize("key_bits", [1024, 2048, 3072, 4096])
    def test_rsa_pkcs1_sign(self, user_session, token_manager, perf_report, key_bits):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=key_bits, label=f"p-rsa-sign-{key_bits}", token=False
        )
        crypto = CryptoOperations()
        data = os.urandom(128)
        result = run_benchmark(
            lambda: crypto.rsa_sign(priv, data),
            n_ops=_N_SLOW, name=f"RSA-{key_bits}-PKCS1-sign",
            warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "RSA", "SHA256_RSA_PKCS", "sign", key_bits))
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("key_bits", [1024, 2048, 3072, 4096])
    def test_rsa_pkcs1_verify(self, user_session, token_manager, perf_report, key_bits):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=key_bits, label=f"p-rsa-verify-{key_bits}", token=False
        )
        crypto = CryptoOperations()
        data = os.urandom(128)
        sig  = crypto.rsa_sign(priv, data)
        result = run_benchmark(
            lambda: crypto.rsa_verify(pub, data, sig),
            n_ops=_N_MED, name=f"RSA-{key_bits}-PKCS1-verify",
            warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "RSA", "SHA256_RSA_PKCS", "verify", key_bits))
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("key_bits", [2048])
    def test_rsa_oaep_encrypt(self, user_session, token_manager, perf_report, key_bits):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=key_bits, label=f"p-rsa-oaep-{key_bits}", token=False
        )
        crypto = CryptoOperations()
        data = os.urandom(64)
        result = run_benchmark(
            lambda: crypto.rsa_encrypt(pub, data),
            n_ops=_N_MED, name=f"RSA-{key_bits}-OAEP-encrypt",
            payload_bytes=64, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "RSA", "RSA_PKCS_OAEP", "encrypt", key_bits))
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("key_bits", [2048])
    def test_rsa_oaep_decrypt(self, user_session, token_manager, perf_report, key_bits):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=key_bits, label=f"p-rsa-oaepd-{key_bits}", token=False
        )
        crypto = CryptoOperations()
        data = os.urandom(64)
        ct   = crypto.rsa_encrypt(pub, data)
        result = run_benchmark(
            lambda: crypto.rsa_decrypt(priv, ct),
            n_ops=_N_SLOW, name=f"RSA-{key_bits}-OAEP-decrypt",
            payload_bytes=64, warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "RSA", "RSA_PKCS_OAEP", "decrypt", key_bits))
        pub.destroy(); priv.destroy()


class TestPerfRSAPSS:
    @pytest.mark.parametrize("mech,hash_mech,mgf,saltlen,name", [
        (Mechanism.SHA1_RSA_PKCS_PSS,   Mechanism.SHA_1,  pkcs11.MGF.SHA1,   20, "SHA1"),
        (Mechanism.SHA256_RSA_PKCS_PSS, Mechanism.SHA256, pkcs11.MGF.SHA256, 32, "SHA256"),
        (Mechanism.SHA512_RSA_PKCS_PSS, Mechanism.SHA512, pkcs11.MGF.SHA512, 64, "SHA512"),
    ])
    def test_rsa_pss_sign(self, user_session, token_manager, perf_report,
                          mech, hash_mech, mgf, saltlen, name):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label=f"p-rsa-pss-{name}", token=False
        )
        data   = os.urandom(128)
        params = (hash_mech, mgf, saltlen)
        result = run_benchmark(
            lambda: priv.sign(data, mechanism=mech, mechanism_param=params),
            n_ops=_N_SLOW, name=f"RSA-2048-PSS-{name}-sign", warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "RSA", f"RSA_PKCS_PSS_{name}", "sign", 2048))
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("mech,hash_mech,mgf,saltlen,name", [
        (Mechanism.SHA256_RSA_PKCS_PSS, Mechanism.SHA256, pkcs11.MGF.SHA256, 32, "SHA256"),
        (Mechanism.SHA512_RSA_PKCS_PSS, Mechanism.SHA512, pkcs11.MGF.SHA512, 64, "SHA512"),
    ])
    def test_rsa_pss_verify(self, user_session, token_manager, perf_report,
                            mech, hash_mech, mgf, saltlen, name):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label=f"p-rsa-pssv-{name}", token=False
        )
        data   = os.urandom(128)
        params = (hash_mech, mgf, saltlen)
        sig    = priv.sign(data, mechanism=mech, mechanism_param=params)
        result = run_benchmark(
            lambda: pub.verify(data, sig, mechanism=mech, mechanism_param=params),
            n_ops=_N_MED, name=f"RSA-2048-PSS-{name}-verify", warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "RSA", f"RSA_PKCS_PSS_{name}", "verify", 2048))
        pub.destroy(); priv.destroy()


class TestPerfRSAX509:
    def test_rsa_raw_encrypt(self, user_session, token_manager, perf_report):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="p-rsa-x509e", token=False
        )
        data = os.urandom(256)  # exact key size
        result = run_benchmark(
            lambda: ObjectOperations.rsa_raw_encrypt(pub, data),
            n_ops=_N_MED, name="RSA-2048-X509-encrypt",
            payload_bytes=256, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "RSA", "RSA_X_509", "encrypt", 2048))
        pub.destroy(); priv.destroy()

    def test_rsa_raw_decrypt(self, user_session, token_manager, perf_report):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="p-rsa-x509d", token=False
        )
        data = os.urandom(256)
        ct   = ObjectOperations.rsa_raw_encrypt(pub, data)
        result = run_benchmark(
            lambda: ObjectOperations.rsa_raw_decrypt(priv, ct),
            n_ops=_N_SLOW, name="RSA-2048-X509-decrypt",
            payload_bytes=256, warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "RSA", "RSA_X_509", "decrypt", 2048))
        pub.destroy(); priv.destroy()


# ── EC ────────────────────────────────────────────────────────────────────────

class TestPerfECDSA:
    @pytest.mark.parametrize("curve,bits", [
        ("secp256r1", 256),
        ("secp384r1", 384),
        ("secp521r1", 521),
    ])
    def test_ecdsa_sign(self, user_session, perf_report, curve, bits):
        params = encode_named_curve_parameters(curve)
        pub, priv = user_session.generate_keypair(
            KeyType.EC, label=f"p-ecdsa-sign-{bits}", store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True,
                              Attribute.EXTRACTABLE: False},
        )
        digest = hashlib.sha256(os.urandom(128)).digest()
        result = run_benchmark(
            lambda: priv.sign(digest, mechanism=Mechanism.ECDSA),
            n_ops=_N_SLOW, name=f"ECDSA-{bits}-sign", warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "EC", "ECDSA", "sign", bits))
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("curve,bits", [
        ("secp256r1", 256),
        ("secp384r1", 384),
        ("secp521r1", 521),
    ])
    def test_ecdsa_verify(self, user_session, perf_report, curve, bits):
        params = encode_named_curve_parameters(curve)
        pub, priv = user_session.generate_keypair(
            KeyType.EC, label=f"p-ecdsa-verify-{bits}", store=False,
            public_template={Attribute.EC_PARAMS: params, Attribute.VERIFY: True},
            private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True,
                              Attribute.EXTRACTABLE: False},
        )
        digest = hashlib.sha256(os.urandom(128)).digest()
        sig    = priv.sign(digest, mechanism=Mechanism.ECDSA)
        result = run_benchmark(
            lambda: pub.verify(digest, sig, mechanism=Mechanism.ECDSA),
            n_ops=_N_MED, name=f"ECDSA-{bits}-verify", warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "EC", "ECDSA", "verify", bits))
        pub.destroy(); priv.destroy()


class TestPerfECDH:
    @pytest.mark.parametrize("curve,bits", [
        ("secp256r1", 256),
        ("secp384r1", 384),
        ("secp521r1", 521),
    ])
    def test_ecdh_derive(self, user_session, perf_report, curve, bits):
        pub_a, priv_a = DeriveOperations.generate_ecdh_keypair(
            user_session, curve_name=curve, label=f"p-ecdh-a-{bits}"
        )
        pub_b, priv_b = DeriveOperations.generate_ecdh_keypair(
            user_session, curve_name=curve, label=f"p-ecdh-b-{bits}"
        )
        ec_point_b = pub_b[Attribute.EC_POINT]
        derived_keys = []

        def derive_once():
            k = DeriveOperations.ecdh_derive_aes_key(priv_a, ec_point_b, label="p-dk")
            derived_keys.append(k)

        result = run_benchmark(
            derive_once,
            n_ops=_N_SLOW, name=f"ECDH-{bits}-derive", warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "EC", "ECDH1_DERIVE", "derive", bits))
        for k in derived_keys:
            try: k.destroy()
            except Exception: pass
        for k in (pub_a, priv_a, pub_b, priv_b):
            try: k.destroy()
            except Exception: pass


# ── EdDSA ─────────────────────────────────────────────────────────────────────

class TestPerfEdDSA:
    @pytest.mark.parametrize("payload", [_S64, _S1K])
    def test_eddsa_sign(self, user_session, perf_report, payload):
        pub, priv = ObjectOperations.generate_ed25519_keypair(
            user_session, label=f"p-ed-sign-{payload}"
        )
        data = os.urandom(payload)
        result = run_benchmark(
            lambda: ObjectOperations.eddsa_sign(priv, data),
            n_ops=_N_SLOW, name=f"EdDSA-Ed25519-sign-{payload}B",
            payload_bytes=payload, warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "EdDSA", "EDDSA", "sign", 256))
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("payload", [_S64, _S1K])
    def test_eddsa_verify(self, user_session, perf_report, payload):
        pub, priv = ObjectOperations.generate_ed25519_keypair(
            user_session, label=f"p-ed-verify-{payload}"
        )
        data = os.urandom(payload)
        sig  = ObjectOperations.eddsa_sign(priv, data)
        result = run_benchmark(
            lambda: ObjectOperations.eddsa_verify(pub, data, sig),
            n_ops=_N_MED, name=f"EdDSA-Ed25519-verify-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "EdDSA", "EDDSA", "verify", 256))
        pub.destroy(); priv.destroy()


# ── DSA ───────────────────────────────────────────────────────────────────────

class TestPerfDSA:
    def test_dsa_sign(self, user_session, perf_report):
        params = DeriveOperations.generate_dsa_params(user_session)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label="p-dsa-sign")
        data = os.urandom(128)
        result = run_benchmark(
            lambda: DeriveOperations.dsa_sign(priv, data),
            n_ops=_N_SLOW, name="DSA-1024-sign", warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "DSA", "DSA_SHA256", "sign", 1024))
        pub.destroy(); priv.destroy()

    def test_dsa_verify(self, user_session, perf_report):
        params = DeriveOperations.generate_dsa_params(user_session)
        pub, priv = DeriveOperations.generate_dsa_keypair(params, label="p-dsa-verify")
        data = os.urandom(128)
        sig  = DeriveOperations.dsa_sign(priv, data)
        result = run_benchmark(
            lambda: DeriveOperations.dsa_verify(pub, data, sig),
            n_ops=_N_MED, name="DSA-1024-verify", warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "DSA", "DSA_SHA256", "verify", 1024))
        pub.destroy(); priv.destroy()


# ── DH ────────────────────────────────────────────────────────────────────────

class TestPerfDH:
    def test_dh_derive(self, user_session, perf_report):
        params_a = DeriveOperations.generate_dh_params(user_session)
        params_b = DeriveOperations.generate_dh_params(user_session)
        pub_a, priv_a = DeriveOperations.generate_dh_keypair(params_a, label="p-dh-a")
        pub_b, priv_b = DeriveOperations.generate_dh_keypair(params_b, label="p-dh-b")
        pub_b_val = pub_b[Attribute.VALUE]
        derived_keys = []

        def derive_once():
            k = DeriveOperations.dh_derive_secret(priv_a, pub_b_val)
            derived_keys.append(k)

        result = run_benchmark(
            derive_once, n_ops=_N_SLOW, name="DH-1024-derive", warmup=2,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "DH", "DH_PKCS_DERIVE", "derive", 1024))
        for k in derived_keys:
            try: k.destroy()
            except Exception: pass
        for k in (pub_a, priv_a, pub_b, priv_b):
            try: k.destroy()
            except Exception: pass


# ── HMAC / MAC ────────────────────────────────────────────────────────────────

class TestPerfHMAC:
    @pytest.mark.parametrize("mech,hash_name,key_bits,payload", [
        (Mechanism.SHA_1_HMAC,   "SHA1",   160, _S64),
        (Mechanism.SHA_1_HMAC,   "SHA1",   160, _S1K),
        (Mechanism.SHA_1_HMAC,   "SHA1",   160, _S64K),
        (Mechanism.SHA256_HMAC,  "SHA256", 256, _S64),
        (Mechanism.SHA256_HMAC,  "SHA256", 256, _S1K),
        (Mechanism.SHA256_HMAC,  "SHA256", 256, _S64K),
        (Mechanism.SHA256_HMAC,  "SHA256", 256, _S1M),
        (Mechanism.SHA384_HMAC,  "SHA384", 384, _S64K),
        (Mechanism.SHA512_HMAC,  "SHA512", 512, _S64K),
        (Mechanism.SHA512_HMAC,  "SHA512", 512, _S1M),
    ])
    def test_hmac_sign(self, user_session, perf_report, mech, hash_name, key_bits, payload):
        key  = MACOperations.generate_hmac_key(user_session, label=f"p-hmac-{hash_name}-{payload}",
                                               mechanism=mech)
        data = os.urandom(payload)
        result = run_benchmark(
            lambda: MACOperations.hmac_sign(key, data, mechanism=mech),
            n_ops=_N_FAST, name=f"HMAC-{hash_name}-sign-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "HMAC", f"HMAC_{hash_name}", "sign", key_bits))
        key.destroy()


class TestPerfCMAC:
    @pytest.mark.parametrize("payload", [_S64, _S1K, _S64K])
    def test_aes_cmac_sign(self, user_session, perf_report, payload):
        key  = MACOperations.generate_cmac_key(user_session, label=f"p-aescmac-{payload}")
        data = os.urandom(payload)
        result = run_benchmark(
            lambda: MACOperations.aes_cmac_sign(key, data),
            n_ops=_N_FAST, name=f"AES-CMAC-sign-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "HMAC", "AES_CMAC", "sign", 128))
        key.destroy()

    @pytest.mark.parametrize("payload", [_S64, _S1K, _S64K])
    def test_des3_cmac_sign(self, user_session, perf_report, payload):
        key  = MACOperations.generate_des3_cmac_key(user_session, label=f"p-d3cmac-{payload}")
        data = os.urandom(payload)
        result = run_benchmark(
            lambda: MACOperations.des3_cmac_sign(key, data),
            n_ops=_N_FAST, name=f"DES3-CMAC-sign-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "HMAC", "DES3_CMAC", "sign", 168))
        key.destroy()


# ── Digest ────────────────────────────────────────────────────────────────────

class TestPerfDigest:
    @pytest.mark.parametrize("mech,name,out_bits,payload", [
        (Mechanism.SHA_1,   "SHA1",   160, _S1K),
        (Mechanism.SHA_1,   "SHA1",   160, _S64K),
        (Mechanism.SHA_1,   "SHA1",   160, _S1M),
        (Mechanism.SHA256,  "SHA256", 256, _S1K),
        (Mechanism.SHA256,  "SHA256", 256, _S64K),
        (Mechanism.SHA256,  "SHA256", 256, _S1M),
        (Mechanism.SHA384,  "SHA384", 384, _S64K),
        (Mechanism.SHA512,  "SHA512", 512, _S64K),
        (Mechanism.SHA512,  "SHA512", 512, _S1M),
    ])
    def test_digest(self, user_session, perf_report, mech, name, out_bits, payload):
        data = os.urandom(payload)
        result = run_benchmark(
            lambda: user_session.digest(data, mechanism=mech),
            n_ops=_N_FAST, name=f"{name}-{payload}B",
            payload_bytes=payload, warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "Digest", name, "digest", out_bits))


# ── Key Generation ────────────────────────────────────────────────────────────

class TestPerfKeyGeneration:
    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_keygen(self, user_session, token_manager, perf_report, key_bits):
        keys = []
        def gen():
            k = token_manager.generate_aes_key(user_session, key_bits,
                                               label=f"p-kgen-aes-{key_bits}", token=False)
            keys.append(k)

        result = run_benchmark(gen, n_ops=_N_KEYGEN_FAST,
                               name=f"AES-{key_bits}-keygen", warmup=10)
        print(f"\n  {result}")
        perf_report.add(_entry(result, "KeyGen", "AES_KEY_GEN", "keygen", key_bits))
        for k in keys:
            try: k.destroy()
            except Exception: pass

    def test_des3_keygen(self, user_session, token_manager, perf_report):
        keys = []
        def gen():
            k = token_manager.generate_des3_key(user_session, label="p-kgen-des3", token=False)
            keys.append(k)

        result = run_benchmark(gen, n_ops=_N_KEYGEN_FAST,
                               name="DES3-keygen", warmup=10)
        print(f"\n  {result}")
        perf_report.add(_entry(result, "KeyGen", "DES3_KEY_GEN", "keygen", 168))
        for k in keys:
            try: k.destroy()
            except Exception: pass

    def test_generic_secret_keygen(self, user_session, perf_report):
        keys = []
        def gen():
            k = user_session.generate_key(
                KeyType.GENERIC_SECRET, 256, store=False,
                template={Attribute.SIGN: True, Attribute.VERIFY: True,
                          Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
            )
            keys.append(k)

        result = run_benchmark(gen, n_ops=_N_KEYGEN_FAST,
                               name="GENERIC_SECRET-256-keygen", warmup=10)
        print(f"\n  {result}")
        perf_report.add(_entry(result, "KeyGen", "GENERIC_SECRET_KEY_GEN", "keygen", 256))
        for k in keys:
            try: k.destroy()
            except Exception: pass

    @pytest.mark.parametrize("curve,bits", [("secp256r1", 256), ("secp384r1", 384)])
    def test_ec_keygen(self, user_session, perf_report, curve, bits):
        ec_params = encode_named_curve_parameters(curve)
        pairs = []
        def gen():
            pub, priv = user_session.generate_keypair(
                KeyType.EC, label=f"p-kgen-ec-{bits}", store=False,
                public_template={Attribute.EC_PARAMS: ec_params, Attribute.VERIFY: True},
                private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True,
                                  Attribute.EXTRACTABLE: False},
            )
            pairs.append((pub, priv))

        result = run_benchmark(gen, n_ops=_N_KEYGEN, name=f"EC-{bits}-keygen", warmup=3)
        print(f"\n  {result}")
        perf_report.add(_entry(result, "KeyGen", "EC_KEY_PAIR_GEN", "keygen", bits))
        for pub, priv in pairs:
            try: pub.destroy(); priv.destroy()
            except Exception: pass

    @pytest.mark.parametrize("key_bits", [2048, 4096])
    def test_rsa_keygen(self, user_session, token_manager, perf_report, key_bits):
        pairs = []
        def gen():
            pub, priv = token_manager.generate_rsa_keypair(
                user_session, key_length=key_bits, label=f"p-kgen-rsa-{key_bits}", token=False
            )
            pairs.append((pub, priv))

        n = 10 if key_bits <= 2048 else 5
        result = run_benchmark(gen, n_ops=n, warmup=1,
                               name=f"RSA-{key_bits}-keygen")
        print(f"\n  {result}")
        perf_report.add(_entry(result, "KeyGen", "RSA_PKCS_KEY_PAIR_GEN", "keygen", key_bits))
        for pub, priv in pairs:
            try: pub.destroy(); priv.destroy()
            except Exception: pass

    def test_ed25519_keygen(self, user_session, perf_report):
        pairs = []
        def gen():
            pub, priv = ObjectOperations.generate_ed25519_keypair(
                user_session, label="p-kgen-ed25519"
            )
            pairs.append((pub, priv))

        result = run_benchmark(gen, n_ops=_N_KEYGEN, name="Ed25519-keygen", warmup=3)
        print(f"\n  {result}")
        perf_report.add(_entry(result, "KeyGen", "EC_EDWARDS_KEY_PAIR_GEN", "keygen", 256))
        for pub, priv in pairs:
            try: pub.destroy(); priv.destroy()
            except Exception: pass


# ── Key Wrapping ──────────────────────────────────────────────────────────────

class TestPerfKeyWrap:
    def test_aes_key_wrap(self, user_session, token_manager, perf_report):
        wrap_key = token_manager.generate_aes_key(
            user_session, 256, label="p-wrap-kek", token=False
        )
        target_key = user_session.generate_key(
            KeyType.AES, 128, store=False,
            template={
                Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False,
                Attribute.WRAP: False, Attribute.UNWRAP: False,
            },
        )
        result = run_benchmark(
            lambda: wrap_key.wrap_key(target_key, mechanism=Mechanism.AES_KEY_WRAP),
            n_ops=_N_FAST, name="AES-256-KEY_WRAP-wrap", warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "KeyWrap", "AES_KEY_WRAP", "wrap", 256))
        wrap_key.destroy(); target_key.destroy()

    def test_aes_key_wrap_pad(self, user_session, token_manager, perf_report):
        wrap_key = token_manager.generate_aes_key(
            user_session, 256, label="p-wrappad-kek", token=False
        )
        target_key = user_session.generate_key(
            KeyType.AES, 128, store=False,
            template={
                Attribute.ENCRYPT: True, Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False,
                Attribute.WRAP: False, Attribute.UNWRAP: False,
            },
        )
        result = run_benchmark(
            lambda: wrap_key.wrap_key(target_key, mechanism=Mechanism.AES_KEY_WRAP_PAD),
            n_ops=_N_FAST, name="AES-256-KEY_WRAP_PAD-wrap", warmup=5,
        )
        print(f"\n  {result}")
        perf_report.add(_entry(result, "KeyWrap", "AES_KEY_WRAP_PAD", "wrap", 256))
        wrap_key.destroy(); target_key.destroy()
