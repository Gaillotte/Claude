"""PKCS11 cryptographic operations: encrypt/decrypt, sign/verify, digest, wrap/unwrap."""

from __future__ import annotations

import os
import pkcs11
from pkcs11 import Mechanism, Session, KeyType, Attribute, MGF


class CryptoOperations:
    """Stateless helpers — each method receives an open, authenticated session."""

    # ------------------------------------------------------------------ #
    # Symmetric encryption — AES
    # ------------------------------------------------------------------ #

    @staticmethod
    def aes_cbc_encrypt(
        key: pkcs11.SecretKey,
        plaintext: bytes,
        iv: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(16)
        ciphertext = key.encrypt(plaintext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        return ciphertext, iv

    @staticmethod
    def aes_cbc_decrypt(
        key: pkcs11.SecretKey,
        ciphertext: bytes,
        iv: bytes,
    ) -> bytes:
        return key.decrypt(ciphertext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)

    @staticmethod
    def aes_ecb_encrypt(key: pkcs11.SecretKey, plaintext: bytes) -> bytes:
        return key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

    @staticmethod
    def aes_ecb_decrypt(key: pkcs11.SecretKey, ciphertext: bytes) -> bytes:
        return key.decrypt(ciphertext, mechanism=Mechanism.AES_ECB)

    # ------------------------------------------------------------------ #
    # Symmetric encryption — DES3
    # ------------------------------------------------------------------ #

    @staticmethod
    def des3_cbc_encrypt(
        key: pkcs11.SecretKey,
        plaintext: bytes,
        iv: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(8)
        ciphertext = key.encrypt(plaintext, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)
        return ciphertext, iv

    @staticmethod
    def des3_cbc_decrypt(
        key: pkcs11.SecretKey,
        ciphertext: bytes,
        iv: bytes,
    ) -> bytes:
        return key.decrypt(ciphertext, mechanism=Mechanism.DES3_CBC_PAD, mechanism_param=iv)

    # ------------------------------------------------------------------ #
    # RSA
    # ------------------------------------------------------------------ #

    @staticmethod
    def rsa_encrypt(pub_key: pkcs11.PublicKey, plaintext: bytes) -> bytes:
        return pub_key.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS)

    @staticmethod
    def rsa_decrypt(priv_key: pkcs11.PrivateKey, ciphertext: bytes) -> bytes:
        return priv_key.decrypt(ciphertext, mechanism=Mechanism.RSA_PKCS)

    @staticmethod
    def rsa_oaep_encrypt(pub_key: pkcs11.PublicKey, plaintext: bytes) -> bytes:
        return pub_key.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP)

    @staticmethod
    def rsa_oaep_decrypt(priv_key: pkcs11.PrivateKey, ciphertext: bytes) -> bytes:
        return priv_key.decrypt(ciphertext, mechanism=Mechanism.RSA_PKCS_OAEP)

    @staticmethod
    def rsa_sign(priv_key: pkcs11.PrivateKey, data: bytes) -> bytes:
        return priv_key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

    @staticmethod
    def rsa_verify(pub_key: pkcs11.PublicKey, data: bytes, signature: bytes) -> bool:
        try:
            result = pub_key.verify(data, signature, mechanism=Mechanism.SHA256_RSA_PKCS)
            # python-pkcs11 returns True/False or None (raises on invalid)
            return result is not False
        except (pkcs11.SignatureInvalid, pkcs11.SignatureLenRange, pkcs11.DataInvalid):
            return False

    @staticmethod
    def rsa_pss_sign(priv_key: pkcs11.PrivateKey, data: bytes) -> bytes:
        return priv_key.sign(
            data,
            mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
            mechanism_param=(Mechanism.SHA256, MGF.SHA256, 32),
        )

    @staticmethod
    def rsa_pss_verify(pub_key: pkcs11.PublicKey, data: bytes, signature: bytes) -> bool:
        try:
            result = pub_key.verify(
                data,
                signature,
                mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
                mechanism_param=(Mechanism.SHA256, MGF.SHA256, 32),
            )
            return result is not False
        except (pkcs11.SignatureInvalid, pkcs11.SignatureLenRange, pkcs11.DataInvalid):
            return False

    # ------------------------------------------------------------------ #
    # EC / ECDSA
    # SoftHSM2 uses raw ECDSA; we pre-hash with SHA-256 in software.
    # ------------------------------------------------------------------ #

    @staticmethod
    def ecdsa_sign(priv_key: pkcs11.PrivateKey, data: bytes) -> bytes:
        import hashlib
        digest = hashlib.sha256(data).digest()
        return priv_key.sign(digest, mechanism=Mechanism.ECDSA)

    @staticmethod
    def ecdsa_verify(pub_key: pkcs11.PublicKey, data: bytes, signature: bytes) -> bool:
        import hashlib
        digest = hashlib.sha256(data).digest()
        try:
            result = pub_key.verify(digest, signature, mechanism=Mechanism.ECDSA)
            return result is not False
        except (pkcs11.SignatureInvalid, pkcs11.SignatureLenRange, pkcs11.DataInvalid):
            return False

    # ------------------------------------------------------------------ #
    # Message digests
    # ------------------------------------------------------------------ #

    @staticmethod
    def digest(session: Session, data: bytes, mechanism: Mechanism = Mechanism.SHA256) -> bytes:
        return session.digest(data, mechanism=mechanism)

    # ------------------------------------------------------------------ #
    # Key wrapping
    # ------------------------------------------------------------------ #

    @staticmethod
    def wrap_key(
        wrapping_key: pkcs11.SecretKey | pkcs11.PublicKey,
        key_to_wrap: pkcs11.SecretKey,
        mechanism: Mechanism = Mechanism.AES_KEY_WRAP_PAD,
    ) -> bytes:
        return wrapping_key.wrap_key(key_to_wrap, mechanism=mechanism)

    @staticmethod
    def unwrap_aes_key(
        unwrapping_key: pkcs11.SecretKey,
        wrapped_key_data: bytes,
        key_length: int = 256,
        label: str = "unwrapped-key",
        mechanism: Mechanism = Mechanism.AES_KEY_WRAP_PAD,
    ) -> pkcs11.SecretKey:
        return unwrapping_key.unwrap_key(
            pkcs11.ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped_key_data,
            mechanism=mechanism,
            label=label,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            },
        )

    # ------------------------------------------------------------------ #
    # Random
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_random(session: Session, length: int) -> bytes:
        """Generate `length` random bytes (internally converts to bits)."""
        return session.generate_random(length * 8)
