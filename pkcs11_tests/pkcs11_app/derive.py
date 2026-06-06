"""PKCS11 key derivation: ECDH and DH (Diffie-Hellman)."""

from __future__ import annotations

import pkcs11
from pkcs11 import Mechanism, Session, KeyType, Attribute, KDF, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters


class DeriveOperations:
    """Key agreement / derivation helpers."""

    # ------------------------------------------------------------------ #
    # EC keypair generation (with DERIVE capability)
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_ecdh_keypair(
        session: Session,
        curve_name: str = "secp256r1",
        label: str = "ecdh-key",
        token: bool = False,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        curve = encode_named_curve_parameters(curve_name)
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
                Attribute.DERIVE: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
            },
        )

    @staticmethod
    def ecdh_derive_aes_key(
        private_key: pkcs11.PrivateKey,
        peer_public_ec_point: bytes,
        key_length: int = 256,
        label: str = "ecdh-derived",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        return private_key.derive_key(
            KeyType.AES,
            key_length,
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(KDF.NULL, None, peer_public_ec_point),
            label=label,
            store=token,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            },
        )

    # ------------------------------------------------------------------ #
    # DH
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_dh_params(session: Session, key_size: int = 512) -> pkcs11.DomainParameters:
        return session.generate_domain_parameters(KeyType.DH, key_size)

    @staticmethod
    def generate_dh_keypair(
        params: pkcs11.DomainParameters,
        label: str = "dh-key",
        token: bool = False,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        return params.generate_keypair(store=token, label=label)

    @staticmethod
    def dh_derive_secret(
        private_key: pkcs11.PrivateKey,
        peer_public_value: bytes,
        key_length: int = 256,
        label: str = "dh-derived",
        token: bool = False,
    ) -> pkcs11.SecretKey:
        return private_key.derive_key(
            KeyType.GENERIC_SECRET,
            key_length,
            mechanism=Mechanism.DH_PKCS_DERIVE,
            mechanism_param=peer_public_value,
            label=label,
            store=token,
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            },
        )

    # ------------------------------------------------------------------ #
    # DSA
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_dsa_params(session: Session, key_size: int = 1024) -> pkcs11.DomainParameters:
        return session.generate_domain_parameters(KeyType.DSA, key_size)

    @staticmethod
    def generate_dsa_keypair(
        params: pkcs11.DomainParameters,
        label: str = "dsa-key",
        token: bool = False,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        return params.generate_keypair(store=token, label=label)

    @staticmethod
    def dsa_sign(priv_key: pkcs11.PrivateKey, data: bytes) -> bytes:
        return priv_key.sign(data, mechanism=Mechanism.DSA_SHA256)

    @staticmethod
    def dsa_verify(pub_key: pkcs11.PublicKey, data: bytes, signature: bytes) -> bool:
        try:
            result = pub_key.verify(data, signature, mechanism=Mechanism.DSA_SHA256)
            return result is not False
        except (pkcs11.SignatureInvalid, pkcs11.SignatureLenRange):
            return False
