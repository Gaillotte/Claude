"""Tests for PKCS11 introspection: slots, token info, mechanism queries."""

import pytest
import pkcs11
from pkcs11 import Mechanism, MechanismFlag, TokenFlag

from pkcs11_app.info import InfoOperations
from pkcs11_app.library import PKCS11Library


class TestSlotInfo:
    def test_get_slots(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        slots = info.get_slots()
        assert isinstance(slots, list)
        assert len(slots) >= 1

    def test_get_slot_info_fields(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        slots = info.get_slots()
        slot_info = info.get_slot_info(slots[0])
        assert "slot_id" in slot_info
        assert "flags" in slot_info

    def test_get_slots_with_token(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        slots = info.get_slots_with_token()
        assert isinstance(slots, list)


class TestTokenInfo:
    def test_get_token_info(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        token_info = info.get_token_info()
        assert "label" in token_info
        assert "manufacturer_id" in token_info
        assert "model" in token_info
        assert "serial" in token_info
        assert "flags" in token_info

    def test_token_label_matches_config(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        token_info = info.get_token_info()
        assert pkcs11_library.config.token_label in token_info["label"]

    def test_token_flags(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        flags = info.get_token_flags()
        assert flags is not None
        # Initialized token must have USER_PIN_INITIALIZED
        assert TokenFlag.USER_PIN_INITIALIZED in flags


class TestMechanismInfo:
    def test_list_mechanisms(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        mechs = info.list_mechanisms()
        assert isinstance(mechs, list)
        assert len(mechs) >= 10

    def test_aes_mechanisms_supported(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        assert info.mechanism_supported(Mechanism.AES_KEY_GEN)
        assert info.mechanism_supported(Mechanism.AES_CBC_PAD)
        assert info.mechanism_supported(Mechanism.AES_GCM)

    def test_rsa_mechanisms_supported(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        assert info.mechanism_supported(Mechanism.RSA_PKCS_KEY_PAIR_GEN)
        assert info.mechanism_supported(Mechanism.RSA_PKCS)
        assert info.mechanism_supported(Mechanism.SHA256_RSA_PKCS)

    def test_ec_mechanisms_supported(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        assert info.mechanism_supported(Mechanism.EC_KEY_PAIR_GEN)
        assert info.mechanism_supported(Mechanism.ECDSA)
        assert info.mechanism_supported(Mechanism.ECDH1_DERIVE)

    def test_unsupported_mechanism_returns_false(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        # AES-CCM is a real PKCS11 mechanism not supported by SoftHSM2's default build
        assert info.mechanism_supported(Mechanism.AES_CCM) is False

    def test_get_mechanism_info_aes(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        mech_info = info.get_mechanism_info(Mechanism.AES_CBC_PAD)
        assert mech_info is not None
        assert mech_info.min_key_length <= mech_info.max_key_length

    def test_get_mechanism_info_rsa(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        mech_info = info.get_mechanism_info(Mechanism.RSA_PKCS)
        assert MechanismFlag.ENCRYPT in mech_info.flags or MechanismFlag.SIGN in mech_info.flags

    def test_get_all_mechanism_infos(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        all_infos = info.get_all_mechanism_infos()
        assert isinstance(all_infos, dict)
        assert len(all_infos) >= 10
        assert Mechanism.AES_CBC_PAD in all_infos

    def test_hmac_mechanism_flags(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        mech_info = info.get_mechanism_info(Mechanism.SHA256_HMAC)
        assert MechanismFlag.SIGN in mech_info.flags
        assert MechanismFlag.VERIFY in mech_info.flags

    def test_key_gen_mechanism_key_size_range(self, pkcs11_library: PKCS11Library):
        info = InfoOperations(pkcs11_library)
        mech_info = info.get_mechanism_info(Mechanism.AES_KEY_GEN)
        # SoftHSM2 reports sizes in bytes; min=16 (128-bit), max=32 (256-bit)
        assert mech_info.min_key_length <= 16
        assert mech_info.max_key_length >= 16
