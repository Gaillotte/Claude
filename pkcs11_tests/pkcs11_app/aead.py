"""PKCS11 authenticated encryption: AES-GCM and AES-CTR."""

from __future__ import annotations

import os
import pkcs11
from pkcs11 import Mechanism, Session, KeyType, Attribute, GCMParams, CTRParams


class AEADOperations:
    """Authenticated and stream encryption helpers."""

    # ------------------------------------------------------------------ #
    # AES-GCM
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_gcm_key(
        session: Session,
        key_length: int = 256,
        label: str = "gcm-key",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        return session.generate_key(
            KeyType.AES,
            key_length,
            label=label,
            store=token,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
        )

    @staticmethod
    def aes_gcm_encrypt(
        key: pkcs11.SecretKey,
        plaintext: bytes,
        nonce: bytes | None = None,
        aad: bytes | None = None,
        tag_bits: int = 128,
    ) -> tuple[bytes, bytes]:
        if nonce is None:
            nonce = os.urandom(12)
        params = GCMParams(nonce, aad=aad, tag_bits=tag_bits)
        ciphertext = key.encrypt(plaintext, mechanism=Mechanism.AES_GCM, mechanism_param=params)
        return ciphertext, nonce

    @staticmethod
    def aes_gcm_decrypt(
        key: pkcs11.SecretKey,
        ciphertext: bytes,
        nonce: bytes,
        aad: bytes | None = None,
        tag_bits: int = 128,
    ) -> bytes:
        params = GCMParams(nonce, aad=aad, tag_bits=tag_bits)
        return key.decrypt(ciphertext, mechanism=Mechanism.AES_GCM, mechanism_param=params)

    # ------------------------------------------------------------------ #
    # AES-CTR
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_ctr_key(
        session: Session,
        key_length: int = 256,
        label: str = "ctr-key",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        return session.generate_key(
            KeyType.AES,
            key_length,
            label=label,
            store=token,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
        )

    @staticmethod
    def aes_ctr_encrypt(
        key: pkcs11.SecretKey,
        plaintext: bytes,
        nonce: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        if nonce is None:
            # Nonce must be ≤ 15 bytes to leave room for block counter
            nonce = os.urandom(8)
        params = CTRParams(nonce)
        ciphertext = key.encrypt(plaintext, mechanism=Mechanism.AES_CTR, mechanism_param=params)
        return ciphertext, nonce

    @staticmethod
    def aes_ctr_decrypt(
        key: pkcs11.SecretKey,
        ciphertext: bytes,
        nonce: bytes,
    ) -> bytes:
        params = CTRParams(nonce)
        return key.decrypt(ciphertext, mechanism=Mechanism.AES_CTR, mechanism_param=params)
