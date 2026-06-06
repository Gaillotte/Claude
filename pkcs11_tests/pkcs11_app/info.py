"""PKCS11 token/slot/mechanism introspection helpers."""

from __future__ import annotations

import pkcs11
from pkcs11 import Mechanism
from pkcs11_app.library import PKCS11Library


class InfoOperations:
    """Query library, slot, token, and mechanism information."""

    def __init__(self, library: PKCS11Library | None = None) -> None:
        self.library = library or PKCS11Library()

    # ------------------------------------------------------------------ #
    # Slots
    # ------------------------------------------------------------------ #

    def get_slots(self) -> list[pkcs11.Slot]:
        return list(self.library.lib.get_slots())

    def get_slots_with_token(self) -> list[pkcs11.Slot]:
        return [s for s in self.get_slots() if s.slot_id is not None]

    def get_slot_info(self, slot: pkcs11.Slot) -> dict:
        return {
            "slot_id": slot.slot_id,
            "flags": slot.flags,
        }

    # ------------------------------------------------------------------ #
    # Token
    # ------------------------------------------------------------------ #

    def get_token_flags(self) -> pkcs11.TokenFlag:
        token = self.library.get_token()
        return token.flags

    def get_token_info(self) -> dict:
        token = self.library.get_token()
        return {
            "label": token.label,
            "manufacturer_id": token.manufacturer_id,
            "model": token.model,
            "serial": token.serial,
            "flags": token.flags,
        }

    # ------------------------------------------------------------------ #
    # Mechanisms
    # ------------------------------------------------------------------ #

    def list_mechanisms(self) -> list[Mechanism]:
        slots = self.get_slots()
        if not slots:
            return []
        return list(slots[0].get_mechanisms())

    def get_mechanism_info(self, mechanism: Mechanism) -> pkcs11.MechanismInfo:
        slots = self.get_slots()
        return slots[0].get_mechanism_info(mechanism)

    def mechanism_supported(self, mechanism: Mechanism) -> bool:
        return mechanism in self.list_mechanisms()

    def get_all_mechanism_infos(self) -> dict[Mechanism, pkcs11.MechanismInfo]:
        slots = self.get_slots()
        if not slots:
            return {}
        slot = slots[0]
        result = {}
        for m in slot.get_mechanisms():
            result[m] = slot.get_mechanism_info(m)
        return result
