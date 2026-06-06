"""PKCS11 MAC operations: HMAC (all SHA variants), AES-CMAC, DES3-CMAC."""

from __future__ import annotations

import pkcs11
from pkcs11 import Mechanism, Session, KeyType, Attribute


# Minimum key sizes (bits) required by SoftHSM2 per HMAC mechanism
_HMAC_KEY_SIZES = {
    Mechanism.SHA_1_HMAC:   160,
    Mechanism.SHA224_HMAC:  224,
    Mechanism.SHA256_HMAC:  256,
    Mechanism.SHA384_HMAC:  384,
    Mechanism.SHA512_HMAC:  512,
}


class MACOperations:
    """Message authentication code helpers."""

    # ------------------------------------------------------------------ #
    # HMAC
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_hmac_key(
        session: Session,
        mechanism: Mechanism = Mechanism.SHA256_HMAC,
        label: str = "hmac-key",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        key_size = _HMAC_KEY_SIZES.get(mechanism, 256)
        return session.generate_key(
            KeyType.GENERIC_SECRET,
            key_size,
            label=label,
            store=token,
            template={Attribute.SIGN: True, Attribute.VERIFY: True},
        )

    @staticmethod
    def hmac_sign(
        key: pkcs11.SecretKey,
        data: bytes,
        mechanism: Mechanism = Mechanism.SHA256_HMAC,
    ) -> bytes:
        return key.sign(data, mechanism=mechanism)

    @staticmethod
    def hmac_verify(
        key: pkcs11.SecretKey,
        data: bytes,
        mac: bytes,
        mechanism: Mechanism = Mechanism.SHA256_HMAC,
    ) -> bool:
        try:
            result = key.verify(data, mac, mechanism=mechanism)
            return result is not False
        except (pkcs11.SignatureInvalid, pkcs11.SignatureLenRange):
            return False

    # ------------------------------------------------------------------ #
    # AES-CMAC
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_cmac_key(
        session: Session,
        key_length: int = 256,
        label: str = "cmac-key",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        return session.generate_key(
            KeyType.AES,
            key_length,
            label=label,
            store=token,
            template={Attribute.SIGN: True, Attribute.VERIFY: True},
        )

    @staticmethod
    def aes_cmac_sign(key: pkcs11.SecretKey, data: bytes) -> bytes:
        return key.sign(data, mechanism=Mechanism.AES_CMAC)

    @staticmethod
    def aes_cmac_verify(key: pkcs11.SecretKey, data: bytes, mac: bytes) -> bool:
        try:
            result = key.verify(data, mac, mechanism=Mechanism.AES_CMAC)
            return result is not False
        except (pkcs11.SignatureInvalid, pkcs11.SignatureLenRange):
            return False

    # ------------------------------------------------------------------ #
    # DES3-CMAC
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_des3_cmac_key(
        session: Session,
        label: str = "des3-cmac-key",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        return session.generate_key(
            KeyType.DES3,
            label=label,
            store=token,
            template={Attribute.SIGN: True, Attribute.VERIFY: True},
        )

    @staticmethod
    def des3_cmac_sign(key: pkcs11.SecretKey, data: bytes) -> bytes:
        return key.sign(data, mechanism=Mechanism.DES3_CMAC)

    @staticmethod
    def des3_cmac_verify(key: pkcs11.SecretKey, data: bytes, mac: bytes) -> bool:
        try:
            result = key.verify(data, mac, mechanism=Mechanism.DES3_CMAC)
            return result is not False
        except (pkcs11.SignatureInvalid, pkcs11.SignatureLenRange):
            return False
