"""
Mock backend — simulates TelSDK without hardware.

Mirrors the C++ mock in tests/mocks/mock_telsdk.h so that the same
behavioural scenarios can be exercised from Python tests.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .backend import IpadBackend
from .types import (
    IPAD_EID_LEN, IPAD_ICCID_LEN,
    IpadConfig, IpadDlParams, IpadEuiccInfo, IpadError, IpadEvent,
    IpadEventType, IpadLogLevel, IpadProfile, IpadProfileState, IpadStatus,
    IpadVersion,
)


# ── Mock configuration knobs ──────────────────────────────────────────────────
@dataclass
class MockConfig:
    subsystem_ready:          bool = True
    subsystem_ready_timeout:  bool = False
    fail_add_profile:         bool = False
    fail_add_profile_status:  bool = False
    fail_delete_profile:      bool = False
    fail_set_profile:         bool = False
    fail_get_profiles:        bool = False
    require_user_consent:     bool = False
    download_error_at_end:    bool = False
    download_delay_ms:        int  = 30
    # Pre-populated profiles; each entry is an IpadProfile
    initial_profiles: List[IpadProfile] = field(default_factory=list)


# ── Subscription record ───────────────────────────────────────────────────────
@dataclass
class _Subscription:
    sub_id:   int
    mask:     int
    cb:       Callable
    user_ctx: object


class MockBackend(IpadBackend):
    """In-process simulation of the IPAd library (no hardware required)."""

    # fixed EID for the mock eUICC
    _MOCK_EID = bytes.fromhex("89049032123456789012345678901234")

    def __init__(self, mock_cfg: Optional[MockConfig] = None):
        self.mock_cfg = mock_cfg or MockConfig()
        self._cfg:    Optional[IpadConfig] = None
        self._profiles: Dict[bytes, IpadProfile] = {}
        self._subs:   Dict[int, _Subscription] = {}
        self._sub_counter = 0
        self._pending_events: List[IpadEvent] = []
        self._lock = threading.Lock()
        self._log_cb:    Optional[Callable] = None
        self._log_ctx:   object = None
        self._log_level: IpadLogLevel = IpadLogLevel.NONE
        self._iccid_counter = 0
        self._initialized = False

    # ── helpers ───────────────────────────────────────────────────────────────

    def _log(self, level: IpadLogLevel, module: str, message: str) -> None:
        if self._log_cb and level.value <= self._log_level.value:
            self._log_cb(level, module, message, self._log_ctx)

    def _emit(self, evt: IpadEvent) -> None:
        with self._lock:
            for sub in self._subs.values():
                if evt.type.value & sub.mask:
                    sub.cb(evt, sub.user_ctx)

    def _next_iccid(self) -> bytes:
        self._iccid_counter += 1
        return bytes.fromhex(
            f"8901{self._iccid_counter:016X}"[:IPAD_ICCID_LEN * 2]
        )

    def _find_iccid(self, iccid: bytes) -> IpadProfile:
        p = self._profiles.get(bytes(iccid))
        if p is None:
            raise IpadError(IpadStatus.ERR_PROFILE_NOT_FOUND)
        return p

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def init(self, cfg: IpadConfig) -> None:
        if self.mock_cfg.subsystem_ready_timeout:
            raise IpadError(IpadStatus.ERR_TIMEOUT,
                            "subsystem_ready timed out")
        if not self.mock_cfg.subsystem_ready:
            raise IpadError(IpadStatus.ERR_TELSDK,
                            "subsystem not ready")
        self._cfg = cfg
        self._log_level = cfg.log_level
        for p in self.mock_cfg.initial_profiles:
            self._profiles[bytes(p.iccid)] = p
        self._initialized = True
        self._log(IpadLogLevel.INFO, "ipad", "initialized")

    def deinit(self) -> None:
        self._initialized = False
        self._log(IpadLogLevel.INFO, "ipad", "deinitialized")

    def configure(self, cfg: IpadConfig) -> None:
        self._cfg = cfg
        self._log_level = cfg.log_level
        self._log(IpadLogLevel.INFO, "ipad", "reconfigured")

    # ── Version / self-test ───────────────────────────────────────────────────

    def get_version(self) -> IpadVersion:
        return IpadVersion(
            major=1, minor=0, patch=0,
            sgp32_revision="SGP.32-v3.0",
            telsdk_version="mock-1.0",
        )

    def selftest(self) -> int:
        return 0x0000_0007  # HAL | TRANSPORT | CRYPTO bits

    # ── eUICC identity ────────────────────────────────────────────────────────

    def get_eid(self) -> bytes:
        return self._MOCK_EID

    def get_euicc_info(self) -> IpadEuiccInfo:
        eid = self._MOCK_EID
        return IpadEuiccInfo(
            eid=eid,
            eid_str=eid.hex().upper(),
            os_version="MockOS-1.0",
            profile_capacity=8,
            free_mem_kb=512,
        )

    # ── Profile management ────────────────────────────────────────────────────

    def profile_list(self) -> List[IpadProfile]:
        if self.mock_cfg.fail_get_profiles:
            raise IpadError(IpadStatus.ERR_TELSDK, "get profiles failed")
        return list(self._profiles.values())

    def profile_get(self, iccid: bytes) -> IpadProfile:
        return self._find_iccid(iccid)

    def profile_download(self, params: IpadDlParams) -> bytes:
        if not params.activation_code:
            raise IpadError(IpadStatus.ERR_INVALID_PARAM,
                            "activation_code required")

        self._log(IpadLogLevel.INFO, "ipad",
                  f"downloading profile: {params.activation_code}")

        # Simulate delay
        delay = (params.timeout_ms or
                 (self._cfg.timeout_ms if self._cfg else 0) or
                 self.mock_cfg.download_delay_ms) / 1000.0
        delay = min(delay, self.mock_cfg.download_delay_ms / 1000.0)
        time.sleep(delay)

        if self.mock_cfg.fail_add_profile:
            raise IpadError(IpadStatus.ERR_TELSDK, "add profile failed")
        if self.mock_cfg.fail_add_profile_status:
            raise IpadError(IpadStatus.ERR_EIM_REJECTED,
                            "add profile status error")
        if self.mock_cfg.download_error_at_end:
            raise IpadError(IpadStatus.ERR_TRANSPORT,
                            "download error at completion")

        iccid = self._next_iccid()
        profile = IpadProfile(
            iccid=iccid,
            state=(IpadProfileState.ENABLED
                   if params.auto_enable
                   else IpadProfileState.DISABLED),
            nickname="",
            provider="Mock Operator",
            profile_name="Mock Profile",
            is_test_profile=True,
            slot_id=self._cfg.slot_id if self._cfg else 0,
        )
        with self._lock:
            self._profiles[bytes(iccid)] = profile

        self._emit(IpadEvent(
            type=IpadEventType.PROFILE_INSTALLED,
            iccid=iccid,
            status=IpadStatus.OK,
            detail=f"installed from {params.activation_code}",
        ))
        self._log(IpadLogLevel.INFO, "ipad",
                  f"profile installed: {iccid.hex().upper()}")
        return iccid

    def profile_enable(self, iccid: bytes) -> None:
        if self.mock_cfg.fail_set_profile:
            raise IpadError(IpadStatus.ERR_TELSDK, "set profile failed")
        p = self._find_iccid(iccid)
        p.state = IpadProfileState.ENABLED
        self._emit(IpadEvent(type=IpadEventType.PROFILE_ENABLED,
                             iccid=bytes(iccid), status=IpadStatus.OK))
        self._log(IpadLogLevel.INFO, "ipad",
                  f"profile enabled: {bytes(iccid).hex().upper()}")

    def profile_disable(self, iccid: bytes) -> None:
        if self.mock_cfg.fail_set_profile:
            raise IpadError(IpadStatus.ERR_TELSDK, "set profile failed")
        p = self._find_iccid(iccid)
        p.state = IpadProfileState.DISABLED
        self._emit(IpadEvent(type=IpadEventType.PROFILE_DISABLED,
                             iccid=bytes(iccid), status=IpadStatus.OK))
        self._log(IpadLogLevel.INFO, "ipad",
                  f"profile disabled: {bytes(iccid).hex().upper()}")

    def profile_delete(self, iccid: bytes) -> None:
        if self.mock_cfg.fail_delete_profile:
            raise IpadError(IpadStatus.ERR_TELSDK, "delete profile failed")
        key = bytes(iccid)
        if key not in self._profiles:
            raise IpadError(IpadStatus.ERR_PROFILE_NOT_FOUND)
        del self._profiles[key]
        self._emit(IpadEvent(type=IpadEventType.PROFILE_DELETED,
                             iccid=key, status=IpadStatus.OK))
        self._log(IpadLogLevel.INFO, "ipad",
                  f"profile deleted: {key.hex().upper()}")

    def profile_set_nickname(self, iccid: bytes, nickname: str) -> None:
        p = self._find_iccid(iccid)
        p.nickname = nickname

    def profile_get_state(self, iccid: bytes) -> IpadProfileState:
        return self._find_iccid(iccid).state

    # ── Events ────────────────────────────────────────────────────────────────

    def event_subscribe(self, mask: int, cb: Callable,
                        user_ctx: object) -> int:
        with self._lock:
            self._sub_counter += 1
            sid = self._sub_counter
            self._subs[sid] = _Subscription(sid, mask, cb, user_ctx)
        return sid

    def event_unsubscribe(self, sub_id: int) -> None:
        with self._lock:
            self._subs.pop(sub_id, None)

    def event_pump(self, timeout_ms: int) -> None:
        time.sleep(min(timeout_ms, 10) / 1000.0)

    # ── Logging ───────────────────────────────────────────────────────────────

    def log_set_handler(self,
                        cb: Optional[Callable[[IpadLogLevel, str, str, object], None]],
                        user_ctx: object) -> None:
        self._log_cb  = cb
        self._log_ctx = user_ctx

    def log_set_level(self, level: IpadLogLevel) -> None:
        self._log_level = level

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def diag_export_json(self) -> str:
        data = {
            "library_version": "1.0.0",
            "eid": self._MOCK_EID.hex().upper(),
            "profile_count": len(self._profiles),
            "profiles": [
                {
                    "iccid": bytes(p.iccid).hex().upper(),
                    "state": p.state.name,
                    "nickname": p.nickname,
                    "provider": p.provider,
                }
                for p in self._profiles.values()
            ],
        }
        return json.dumps(data, indent=2)
