"""PKCS11 token and object management."""

from __future__ import annotations

import pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType, Session
from pkcs11_app.library import PKCS11Library


class TokenManager:
    """High-level helpers for managing PKCS11 token objects."""

    def __init__(self, library: PKCS11Library | None = None) -> None:
        self.library = library or PKCS11Library()

    # ------------------------------------------------------------------ #
    # Object discovery
    # ------------------------------------------------------------------ #

    @staticmethod
    def list_objects(
        session: Session,
        object_class: ObjectClass | None = None,
        label: str | None = None,
    ) -> list[pkcs11.Object]:
        attrs: dict = {}
        if object_class is not None:
            attrs[Attribute.CLASS] = object_class
        if label is not None:
            attrs[Attribute.LABEL] = label
        return list(session.get_objects(attrs))

    @staticmethod
    def find_object(
        session: Session,
        object_class: ObjectClass,
        label: str,
    ) -> pkcs11.Object | None:
        attrs = {Attribute.CLASS: object_class, Attribute.LABEL: label}
        objects = list(session.get_objects(attrs))
        return objects[0] if objects else None

    @staticmethod
    def destroy_object(obj: pkcs11.Object) -> None:
        obj.destroy()

    @staticmethod
    def destroy_all_objects(session: Session) -> int:
        objs = list(session.get_objects({}))
        for obj in objs:
            obj.destroy()
        return len(objs)

    # ------------------------------------------------------------------ #
    # Key generation — symmetric
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_aes_key(
        session: Session,
        key_length: int = 256,
        label: str = "aes-key",
        token: bool = True,
    ) -> pkcs11.SecretKey:
        return session.generate_key(
            KeyType.AES,
            key_length,
            label=label,
            store=token,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

    @staticmethod
    def generate_des3_key(
        session: Session,
        label: str = "des3-key",
        token: bool = True,
    ) -> pkcs11.SecretKey:
        return session.generate_key(
            KeyType.DES3,
            label=label,
            store=token,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

    # ------------------------------------------------------------------ #
    # Key generation — asymmetric
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_rsa_keypair(
        session: Session,
        key_length: int = 2048,
        label: str = "rsa-key",
        token: bool = True,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        return session.generate_keypair(
            KeyType.RSA,
            key_length,
            label=label,
            store=token,
            public_template={
                Attribute.ENCRYPT: True,
                Attribute.VERIFY: True,
                Attribute.WRAP: True,
            },
            private_template={
                Attribute.DECRYPT: True,
                Attribute.SIGN: True,
                Attribute.UNWRAP: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
            },
        )

    @staticmethod
    def generate_ec_keypair(
        session: Session,
        curve: bytes | None = None,
        label: str = "ec-key",
        token: bool = True,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        from pkcs11.util.ec import encode_named_curve_parameters
        if curve is None:
            curve = encode_named_curve_parameters("secp256r1")
        return session.generate_keypair(
            KeyType.EC,
            label=label,
            store=token,
            public_template={
                Attribute.EC_PARAMS: curve,
                Attribute.VERIFY: True,
            },
            private_template={
                Attribute.SIGN: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
            },
        )

    # ------------------------------------------------------------------ #
    # Token info
    # ------------------------------------------------------------------ #

    def get_token_info(self) -> dict:
        token = self.library.get_token()
        return {
            "label": token.label,
            "manufacturer_id": token.manufacturer_id,
            "model": token.model,
            "serial": token.serial,
            "flags": token.flags,
        }
