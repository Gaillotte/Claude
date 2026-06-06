"""Load tests — cryptographic throughput and latency.

Each test class targets a minimum throughput or maximum latency threshold
calibrated to SoftHSM2 on a standard x86-64 machine. Tests are marked
``load`` so they can be excluded from the fast CI gate:

    pytest -m "not load"   # skip load tests
    pytest -m load         # run only load tests

Thresholds are deliberately conservative (5–10× below measured baseline)
to avoid false failures on slow CI runners.
"""

import os
import time
import pytest
import pkcs11
from pkcs11 import Mechanism

from pkcs11_app.crypto import CryptoOperations
from pkcs11_app.mac import MACOperations
from pkcs11_app.aead import AEADOperations
from pkcs11_app.token import TokenManager
from pkcs11_app.benchmark import run_benchmark

pytestmark = pytest.mark.load

# ── Thresholds ────────────────────────────────────────────────────────────────
MIN_AES_CBC_OPS    = 500      # ops/s  (1 MB blocks)
MIN_AES_GCM_OPS    = 200      # ops/s  (1 MB blocks)
MIN_AES_CTR_OPS    = 200      # ops/s  (1 MB blocks)
MIN_HMAC256_OPS    = 5_000    # ops/s  (4 KB blocks)
MIN_AES_CMAC_OPS   = 5_000    # ops/s  (4 KB blocks)
MIN_RSA2048_SIGN   = 100      # ops/s
MIN_RSA2048_VERIFY = 2_000    # ops/s
MIN_ECDSA_SIGN     = 100      # ops/s
MIN_KEY_GEN_OPS    = 500      # AES-128 session keys/s


# ── AES ───────────────────────────────────────────────────────────────────────

class TestAESCBCThroughput:
    @pytest.mark.parametrize("size_kb,min_ops", [
        (1,    5_000),
        (64,   500),
        (1024, 50),
    ])
    def test_aes_cbc_throughput(self, user_session, token_manager, size_kb, min_ops):
        key = token_manager.generate_aes_key(user_session, 256, label=f"bench-aes-{size_kb}k", token=False)
        crypto = CryptoOperations()
        data = os.urandom(size_kb * 1024)
        iv = os.urandom(16)

        result = run_benchmark(
            lambda: crypto.aes_cbc_encrypt(key, data, iv=iv),
            n_ops=max(10, min_ops // 10),
            name=f"AES-CBC-{size_kb}KB",
            payload_bytes=len(data),
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= min_ops / 10, (
            f"AES-CBC {size_kb}KB: {result.ops_per_sec:.0f} ops/s < threshold {min_ops/10}"
        )
        key.destroy()

    def test_aes_cbc_encrypt_decrypt_1mb(self, user_session, token_manager):
        key = token_manager.generate_aes_key(user_session, 256, label="bench-aes-1mb", token=False)
        crypto = CryptoOperations()
        data = os.urandom(1024 * 1024)

        result = run_benchmark(
            lambda: crypto.aes_cbc_encrypt(key, data),
            n_ops=20, name="AES-CBC-ENC-1MB", payload_bytes=len(data)
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_AES_CBC_OPS / 10
        key.destroy()

    def test_aes_cbc_latency_small(self, user_session, token_manager):
        """Latency for 16-byte (single block) encrypt must be < 1 ms."""
        key = token_manager.generate_aes_key(user_session, 256, label="bench-aes-lat", token=False)
        crypto = CryptoOperations()
        data = b"A" * 16

        result = run_benchmark(
            lambda: crypto.aes_cbc_encrypt(key, data),
            n_ops=500, name="AES-CBC-latency-16B"
        )
        print(f"\n  {result}")
        assert result.latency_ms < 1.0, f"AES-CBC latency {result.latency_ms:.3f} ms > 1 ms"
        key.destroy()


class TestAESGCMThroughput:
    def test_gcm_encrypt_throughput_64kb(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session, label="bench-gcm-64k")
        data = os.urandom(64 * 1024)
        nonce = os.urandom(12)

        result = run_benchmark(
            lambda: AEADOperations.aes_gcm_encrypt(key, data, nonce=nonce),
            n_ops=50, name="AES-GCM-64KB", payload_bytes=len(data)
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_AES_GCM_OPS / 10

    def test_gcm_roundtrip_1mb(self, user_session):
        key = AEADOperations.generate_gcm_key(user_session, label="bench-gcm-1mb")
        data = os.urandom(1024 * 1024)

        def roundtrip():
            ct, nonce = AEADOperations.aes_gcm_encrypt(key, data)
            AEADOperations.aes_gcm_decrypt(key, ct, nonce)

        result = run_benchmark(roundtrip, n_ops=10, name="AES-GCM-RT-1MB", payload_bytes=len(data))
        print(f"\n  {result}")
        assert result.ops_per_sec >= 1  # at least 1 full roundtrip/s for 1 MB


class TestAESCTRThroughput:
    def test_ctr_throughput_64kb(self, user_session):
        key = AEADOperations.generate_ctr_key(user_session, label="bench-ctr-64k")
        data = os.urandom(64 * 1024)
        nonce = os.urandom(8)

        result = run_benchmark(
            lambda: AEADOperations.aes_ctr_encrypt(key, data, nonce=nonce),
            n_ops=50, name="AES-CTR-64KB", payload_bytes=len(data)
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_AES_CTR_OPS / 10


# ── MAC ───────────────────────────────────────────────────────────────────────

class TestHMACThroughput:
    @pytest.mark.parametrize("size_kb,min_ops", [
        (1,   20_000),
        (64,  1_000),
        (1024, 50),
    ])
    def test_hmac_sha256_throughput(self, user_session, size_kb, min_ops):
        key = MACOperations.generate_hmac_key(user_session, label=f"bench-hmac-{size_kb}k")
        data = os.urandom(size_kb * 1024)

        result = run_benchmark(
            lambda: MACOperations.hmac_sign(key, data),
            n_ops=max(10, min_ops // 20),
            name=f"HMAC-SHA256-{size_kb}KB",
            payload_bytes=len(data),
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= min_ops / 20
        key.destroy()

    def test_hmac_sha512_throughput_4kb(self, user_session):
        key = MACOperations.generate_hmac_key(
            user_session, mechanism=Mechanism.SHA512_HMAC, label="bench-hmac512"
        )
        data = os.urandom(4096)
        result = run_benchmark(
            lambda: MACOperations.hmac_sign(key, data, mechanism=Mechanism.SHA512_HMAC),
            n_ops=200, name="HMAC-SHA512-4KB", payload_bytes=len(data)
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= 1_000
        key.destroy()

    def test_aes_cmac_throughput_4kb(self, user_session):
        key = MACOperations.generate_cmac_key(user_session, label="bench-cmac")
        data = os.urandom(4096)
        result = run_benchmark(
            lambda: MACOperations.aes_cmac_sign(key, data),
            n_ops=200, name="AES-CMAC-4KB", payload_bytes=len(data)
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_AES_CMAC_OPS / 20


# ── RSA ───────────────────────────────────────────────────────────────────────

class TestRSAThroughput:
    def test_rsa2048_sign_throughput(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="bench-rsa-sign", token=False
        )
        data = os.urandom(256)
        result = run_benchmark(
            lambda: CryptoOperations.rsa_sign(priv, data),
            n_ops=100, name="RSA-2048-sign"
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_RSA2048_SIGN
        pub.destroy(); priv.destroy()

    def test_rsa2048_verify_throughput(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="bench-rsa-verify", token=False
        )
        data = os.urandom(256)
        sig = CryptoOperations.rsa_sign(priv, data)
        result = run_benchmark(
            lambda: CryptoOperations.rsa_verify(pub, data, sig),
            n_ops=500, name="RSA-2048-verify"
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_RSA2048_VERIFY
        pub.destroy(); priv.destroy()

    def test_rsa4096_sign_throughput(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=4096, label="bench-rsa4096", token=False
        )
        data = os.urandom(256)
        result = run_benchmark(
            lambda: CryptoOperations.rsa_sign(priv, data),
            n_ops=30, name="RSA-4096-sign"
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= 20  # 4096-bit is much slower
        pub.destroy(); priv.destroy()

    def test_rsa2048_oaep_roundtrip_throughput(self, user_session, token_manager):
        pub, priv = token_manager.generate_rsa_keypair(
            user_session, key_length=2048, label="bench-oaep", token=False
        )
        plaintext = os.urandom(32)

        def roundtrip():
            ct = CryptoOperations.rsa_oaep_encrypt(pub, plaintext)
            CryptoOperations.rsa_oaep_decrypt(priv, ct)

        result = run_benchmark(roundtrip, n_ops=50, name="RSA-2048-OAEP-RT")
        print(f"\n  {result}")
        assert result.ops_per_sec >= 50
        pub.destroy(); priv.destroy()


# ── EC ────────────────────────────────────────────────────────────────────────

class TestECThroughput:
    def test_ecdsa_p256_sign_throughput(self, user_session, token_manager):
        pub, priv = token_manager.generate_ec_keypair(
            user_session, label="bench-ecdsa-sign", token=False
        )
        crypto = CryptoOperations()
        data = os.urandom(256)
        result = run_benchmark(
            lambda: crypto.ecdsa_sign(priv, data),
            n_ops=200, name="ECDSA-P256-sign"
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_ECDSA_SIGN
        pub.destroy(); priv.destroy()

    def test_ecdsa_p256_verify_throughput(self, user_session, token_manager):
        pub, priv = token_manager.generate_ec_keypair(
            user_session, label="bench-ecdsa-verify", token=False
        )
        crypto = CryptoOperations()
        data = os.urandom(256)
        sig = crypto.ecdsa_sign(priv, data)
        result = run_benchmark(
            lambda: crypto.ecdsa_verify(pub, data, sig),
            n_ops=500, name="ECDSA-P256-verify"
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_ECDSA_SIGN * 2
        pub.destroy(); priv.destroy()

    @pytest.mark.parametrize("curve", ["secp256r1", "secp384r1", "secp521r1"])
    def test_ecdsa_curve_sign_latency(self, user_session, curve):
        from pkcs11.util.ec import encode_named_curve_parameters
        params = encode_named_curve_parameters(curve)
        pub, priv = user_session.generate_keypair(
            pkcs11.KeyType.EC, label=f"bench-{curve}", store=False,
            public_template={pkcs11.Attribute.EC_PARAMS: params, pkcs11.Attribute.VERIFY: True},
            private_template={pkcs11.Attribute.SIGN: True,
                               pkcs11.Attribute.SENSITIVE: True, pkcs11.Attribute.EXTRACTABLE: False}
        )
        import hashlib
        data = hashlib.sha256(os.urandom(64)).digest()
        result = run_benchmark(
            lambda: priv.sign(data, mechanism=Mechanism.ECDSA),
            n_ops=100, name=f"ECDSA-{curve}-sign"
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= 50
        pub.destroy(); priv.destroy()


# ── Digest ────────────────────────────────────────────────────────────────────

class TestDigestThroughput:
    @pytest.mark.parametrize("mech,size_kb", [
        (Mechanism.SHA256, 64),
        (Mechanism.SHA256, 1024),
        (Mechanism.SHA512, 64),
    ])
    def test_digest_throughput(self, user_session, mech, size_kb):
        from pkcs11_app.crypto import CryptoOperations
        crypto = CryptoOperations()
        data = os.urandom(size_kb * 1024)
        result = run_benchmark(
            lambda: crypto.digest(user_session, data, mech),
            n_ops=50, name=f"{mech}-{size_kb}KB", payload_bytes=len(data)
        )
        print(f"\n  {result}")
        assert result.throughput_mbs >= 10  # at least 10 MB/s


# ── Key generation ────────────────────────────────────────────────────────────

class TestKeyGenerationThroughput:
    def test_aes_128_session_key_gen_rate(self, user_session):
        """Simulate key-per-request workload: generate many ephemeral AES-128 keys."""
        keys = []

        def gen_and_store():
            k = user_session.generate_key(
                pkcs11.KeyType.AES, 128, store=False,
                template={pkcs11.Attribute.ENCRYPT: True, pkcs11.Attribute.DECRYPT: True}
            )
            keys.append(k)

        result = run_benchmark(gen_and_store, n_ops=200, name="AES-128-keygen")
        for k in keys:
            try: k.destroy()
            except Exception: pass

        print(f"\n  {result}")
        assert result.ops_per_sec >= MIN_KEY_GEN_OPS

    def test_rsa_2048_keygen_rate(self, user_session):
        pairs = []

        def gen():
            pub, priv = user_session.generate_keypair(
                pkcs11.KeyType.RSA, 2048, store=False,
                public_template={pkcs11.Attribute.ENCRYPT: True, pkcs11.Attribute.VERIFY: True},
                private_template={pkcs11.Attribute.DECRYPT: True, pkcs11.Attribute.SIGN: True,
                                   pkcs11.Attribute.SENSITIVE: True, pkcs11.Attribute.EXTRACTABLE: False},
            )
            pairs.append((pub, priv))

        result = run_benchmark(gen, n_ops=10, warmup=1, name="RSA-2048-keygen")
        for pub, priv in pairs:
            try: pub.destroy(); priv.destroy()
            except Exception: pass

        print(f"\n  {result}")
        assert result.ops_per_sec >= 3  # RSA keygen is slow; threshold conservative for CI

    def test_ec_p256_keygen_rate(self, user_session):
        from pkcs11.util.ec import encode_named_curve_parameters
        curve = encode_named_curve_parameters("secp256r1")
        pairs = []

        def gen():
            pub, priv = user_session.generate_keypair(
                pkcs11.KeyType.EC, label="bench-ec-kg", store=False,
                public_template={pkcs11.Attribute.EC_PARAMS: curve, pkcs11.Attribute.VERIFY: True},
                private_template={pkcs11.Attribute.SIGN: True,
                                   pkcs11.Attribute.SENSITIVE: True, pkcs11.Attribute.EXTRACTABLE: False},
            )
            pairs.append((pub, priv))

        result = run_benchmark(gen, n_ops=50, name="EC-P256-keygen")
        for pub, priv in pairs:
            try: pub.destroy(); priv.destroy()
            except Exception: pass

        print(f"\n  {result}")
        assert result.ops_per_sec >= 50


# ── RNG ───────────────────────────────────────────────────────────────────────

class TestRNGThroughput:
    @pytest.mark.parametrize("size_bytes,min_ops", [
        (16,   10_000),
        (256,  5_000),
        (4096, 500),
    ])
    def test_rng_throughput(self, user_session, size_bytes, min_ops):
        from pkcs11_app.crypto import CryptoOperations
        crypto = CryptoOperations()
        result = run_benchmark(
            lambda: crypto.generate_random(user_session, size_bytes),
            n_ops=max(10, min_ops // 10),
            name=f"RNG-{size_bytes}B",
            payload_bytes=size_bytes,
        )
        print(f"\n  {result}")
        assert result.ops_per_sec >= min_ops / 10


# ── BenchResult unit coverage ─────────────────────────────────────────────────

class TestBenchResultEdgeCases:
    """Unit tests for BenchResult edge-case branches (no HSM needed)."""

    def test_throughput_zero_payload(self):
        from pkcs11_app.benchmark import BenchResult
        r = BenchResult(name="t", n_ops=10, elapsed_s=1.0, payload_bytes=0)
        assert r.throughput_mbs == 0.0

    def test_throughput_zero_elapsed(self):
        from pkcs11_app.benchmark import BenchResult
        r = BenchResult(name="t", n_ops=10, elapsed_s=0.0, payload_bytes=1024)
        assert r.throughput_mbs == 0.0

    def test_str_no_payload(self):
        from pkcs11_app.benchmark import BenchResult
        r = BenchResult(name="op", n_ops=100, elapsed_s=1.0)
        assert "ops/s" in str(r)
        assert "MB/s" not in str(r)

    def test_str_with_payload(self):
        from pkcs11_app.benchmark import BenchResult
        r = BenchResult(name="op", n_ops=100, elapsed_s=1.0, payload_bytes=1024)
        assert "MB/s" in str(r)
