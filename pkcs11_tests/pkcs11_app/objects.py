"""PKCS11 token object management: data objects, key import, token persistence, EdDSA."""

from __future__ import annotations

import os
import pkcs11
from pkcs11 import Mechanism, Session, KeyType, Attribute, ObjectClass


# OID DER encoding for Ed25519 (1.3.101.112 = 06 03 2b 65 70)
ED25519_OID = bytes.fromhex("06032b6570")


class ObjectOperations:
    """Helpers for creating and querying PKCS11 token objects."""

    # ------------------------------------------------------------------ #
    # Data objects (CKO_DATA)
    # ------------------------------------------------------------------ #

    @staticmethod
    def create_data_object(
        session: Session,
        label: str,
        data: bytes,
        token: bool = False,
    ) -> pkcs11.Object:
        return session.create_object({
            Attribute.CLASS: ObjectClass.DATA,
            Attribute.LABEL: label,
            Attribute.VALUE: data,
            Attribute.TOKEN: token,
        })

    @staticmethod
    def read_data_object(obj: pkcs11.Object) -> bytes:
        return obj[Attribute.VALUE]

    # ------------------------------------------------------------------ #
    # Raw key import
    # ------------------------------------------------------------------ #

    @staticmethod
    def import_aes_key(
        session: Session,
        raw_key: bytes,
        label: str = "imported-aes",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        return session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: raw_key,
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.TOKEN: token,
            Attribute.LABEL: label,
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
        })

    @staticmethod
    def import_generic_secret_key(
        session: Session,
        raw_key: bytes,
        label: str = "imported-generic",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        return session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.VALUE: raw_key,
            Attribute.SIGN: True,
            Attribute.VERIFY: True,
            Attribute.TOKEN: token,
            Attribute.LABEL: label,
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
        })

    # ------------------------------------------------------------------ #
    # Token-persistent keys (stored on token)
    # ------------------------------------------------------------------ #

    @staticmethod
    def create_persistent_aes_key(
        session: Session,
        key_length: int = 256,
        label: str = "persistent-aes",
    ) -> pkcs11.SecretKey:
        return session.generate_key(
            KeyType.AES,
            key_length,
            label=label,
            store=True,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

    @staticmethod
    def find_persistent_key(
        session: Session,
        label: str,
        object_class: ObjectClass = ObjectClass.SECRET_KEY,
    ) -> pkcs11.Object | None:
        objs = list(session.get_objects({
            Attribute.CLASS: object_class,
            Attribute.LABEL: label,
            Attribute.TOKEN: True,
        }))
        return objs[0] if objs else None

    # ------------------------------------------------------------------ #
    # Object copy
    # ------------------------------------------------------------------ #

    @staticmethod
    def copy_object(
        obj: pkcs11.Object,
        new_label: str,
    ) -> pkcs11.Object:
        return obj.copy({Attribute.LABEL: new_label})

    # ------------------------------------------------------------------ #
    # EdDSA (Ed25519)
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_ed25519_keypair(
        session: Session,
        label: str = "ed25519",
        token: bool = False,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        return session.generate_keypair(
            KeyType.EC_EDWARDS,
            label=label,
            store=token,
            public_template={
                Attribute.EC_PARAMS: ED25519_OID,
                Attribute.VERIFY: True,
            },
            private_template={
                Attribute.SIGN: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
            },
        )

    @staticmethod
    def eddsa_sign(priv_key: pkcs11.PrivateKey, data: bytes) -> bytes:
        return priv_key.sign(data, mechanism=Mechanism.EDDSA)

    @staticmethod
    def eddsa_verify(pub_key: pkcs11.PublicKey, data: bytes, signature: bytes) -> bool:
        try:
            result = pub_key.verify(data, signature, mechanism=Mechanism.EDDSA)
            return result is not False
        except (pkcs11.SignatureInvalid, pkcs11.SignatureLenRange):
            return False

    # ------------------------------------------------------------------ #
    # RSA X.509 (raw RSA, no padding)
    # ------------------------------------------------------------------ #

    @staticmethod
    def rsa_raw_encrypt(pub_key: pkcs11.PublicKey, padded_data: bytes) -> bytes:
        return pub_key.encrypt(padded_data, mechanism=Mechanism.RSA_X_509)

    @staticmethod
    def rsa_raw_decrypt(priv_key: pkcs11.PrivateKey, ciphertext: bytes) -> bytes:
        return priv_key.decrypt(ciphertext, mechanism=Mechanism.RSA_X_509)

    # ------------------------------------------------------------------ #
    # AES-CBC (without PKCS7 padding) and DES3-ECB
    # ------------------------------------------------------------------ #

    @staticmethod
    def aes_cbc_nopad_encrypt(
        key: pkcs11.SecretKey,
        plaintext: bytes,
        iv: bytes,
    ) -> bytes:
        return key.encrypt(plaintext, mechanism=Mechanism.AES_CBC, mechanism_param=iv)

    @staticmethod
    def aes_cbc_nopad_decrypt(
        key: pkcs11.SecretKey,
        ciphertext: bytes,
        iv: bytes,
    ) -> bytes:
        return key.decrypt(ciphertext, mechanism=Mechanism.AES_CBC, mechanism_param=iv)

    @staticmethod
    def des3_ecb_encrypt(key: pkcs11.SecretKey, plaintext: bytes) -> bytes:
        return key.encrypt(plaintext, mechanism=Mechanism.DES3_ECB)

    @staticmethod
    def des3_ecb_decrypt(key: pkcs11.SecretKey, ciphertext: bytes) -> bytes:
        return key.decrypt(ciphertext, mechanism=Mechanism.DES3_ECB)
