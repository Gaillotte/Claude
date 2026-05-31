"""Public types mirroring ipad.h and ipad_log.h."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional

# ── Constants ─────────────────────────────────────────────────────────────────
IPAD_EID_LEN   = 16   # 32 BCD digits stored as 16 bytes
IPAD_ICCID_LEN = 10   # 20 BCD digits stored as 10 bytes
IPAD_STR_MAX   = 64


# ── Status codes ──────────────────────────────────────────────────────────────
class IpadStatus(enum.IntEnum):
    OK                  =   0
    PENDING             =   1
    ERR_INVALID_PARAM   =  -1
    ERR_NOT_INITIALIZED =  -2
    ERR_HAL_FAILURE     =  -3
    ERR_TRANSPORT       =  -4
    ERR_TLS_HANDSHAKE   =  -5
    ERR_EIM_REJECTED    =  -6
    ERR_PROFILE_NOT_FOUND = -7
    ERR_PROFILE_ACTIVE  =  -8
    ERR_NO_MEMORY       =  -9
    ERR_CRYPTO          = -10
    ERR_TIMEOUT         = -11
    ERR_BUSY            = -12
    ERR_NOT_SUPPORTED   = -13
    ERR_TELSDK          = -14
    ERR_INTERNAL        = -99


_STATUS_MESSAGES = {
    IpadStatus.OK:                  "success",
    IpadStatus.PENDING:             "operation pending",
    IpadStatus.ERR_INVALID_PARAM:   "invalid parameter",
    IpadStatus.ERR_NOT_INITIALIZED: "library not initialized",
    IpadStatus.ERR_HAL_FAILURE:     "HAL / hardware failure",
    IpadStatus.ERR_TRANSPORT:       "transport error",
    IpadStatus.ERR_TLS_HANDSHAKE:   "TLS handshake failed",
    IpadStatus.ERR_EIM_REJECTED:    "eIM rejected the request",
    IpadStatus.ERR_PROFILE_NOT_FOUND: "profile not found",
    IpadStatus.ERR_PROFILE_ACTIVE:  "profile is active",
    IpadStatus.ERR_NO_MEMORY:       "out of memory",
    IpadStatus.ERR_CRYPTO:          "cryptographic error",
    IpadStatus.ERR_TIMEOUT:         "operation timed out",
    IpadStatus.ERR_BUSY:            "resource busy",
    IpadStatus.ERR_NOT_SUPPORTED:   "not supported",
    IpadStatus.ERR_TELSDK:          "TelSDK backend error",
    IpadStatus.ERR_INTERNAL:        "internal error",
}


def ipad_strerror(status: int) -> str:
    try:
        return _STATUS_MESSAGES.get(IpadStatus(status), "unknown status")
    except ValueError:
        return "unknown status"


# ── Enums ─────────────────────────────────────────────────────────────────────
class IpadTransport(enum.IntEnum):
    TCP  = 0
    COAP = 1
    MQTT = 2
    SMS  = 3


class IpadLogLevel(enum.IntEnum):
    NONE  = 0
    ERROR = 1
    WARN  = 2
    INFO  = 3
    DEBUG = 4


class IpadProfileState(enum.IntEnum):
    ENABLED         = 0
    DISABLED        = 1
    PENDING_INSTALL = 2
    PENDING_ENABLE  = 3
    ERROR           = 4


class IpadEventType(enum.IntFlag):
    PROFILE_INSTALLED  = 1 << 0
    PROFILE_ENABLED    = 1 << 1
    PROFILE_DISABLED   = 1 << 2
    PROFILE_DELETED    = 1 << 3
    EIM_CONNECTED      = 1 << 4
    EIM_DISCONNECTED   = 1 << 5
    NETWORK_ATTACHED   = 1 << 6
    NETWORK_DETACHED   = 1 << 7
    DOWNLOAD_PROGRESS  = 1 << 8
    ERROR              = 1 << 9
    ALL                = 0xFFFFFFFF


# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class IpadProfile:
    iccid:        bytes = field(default_factory=lambda: bytes(IPAD_ICCID_LEN))
    state:        IpadProfileState = IpadProfileState.DISABLED
    nickname:     str = ""
    provider:     str = ""
    profile_name: str = ""
    is_test_profile: bool = False
    slot_id:      int = 0


@dataclass
class IpadEuiccInfo:
    eid:              bytes = field(default_factory=lambda: bytes(IPAD_EID_LEN))
    eid_str:          str = ""
    os_version:       str = ""
    profile_capacity: int = 0
    free_mem_kb:      int = 0


@dataclass
class IpadTlsCfg:
    ca_cert_path:    Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    verify_peer:     bool = True
    tls_version_min: int = 0x0303  # TLS 1.2


@dataclass
class IpadConfig:
    eim_url:     Optional[str] = None
    eim_port:    int = 0
    transport:   IpadTransport = IpadTransport.TCP
    tls:         IpadTlsCfg = field(default_factory=IpadTlsCfg)
    timeout_ms:  int = 30000
    retry_count: int = 3
    log_level:   IpadLogLevel = IpadLogLevel.NONE
    slot_id:     int = 0
    user_ctx:    object = None


@dataclass
class IpadDlParams:
    activation_code:   Optional[str] = None
    confirmation_code: Optional[str] = None
    auto_enable:       bool = False
    timeout_ms:        int = 0  # 0 = use global


@dataclass
class IpadEvent:
    type:         IpadEventType = IpadEventType.ERROR
    iccid:        bytes = field(default_factory=lambda: bytes(IPAD_ICCID_LEN))
    status:       int = 0
    progress_pct: int = 0
    detail:       str = ""


@dataclass
class IpadVersion:
    major:          int = 1
    minor:          int = 0
    patch:          int = 0
    sgp32_revision: str = "SGP.32-v3.0"
    telsdk_version: str = "mock-1.0"


# ── Exception ─────────────────────────────────────────────────────────────────
class IpadError(Exception):
    """Raised when an IPAd API call returns a non-OK status."""

    def __init__(self, status: int, msg: str = ""):
        self.status = IpadStatus(status) if status in IpadStatus._value2member_map_ else status
        super().__init__(msg or ipad_strerror(status))


# ── Utility functions (pure Python) ──────────────────────────────────────────
def iccid_to_str(iccid: bytes) -> str:
    """Convert 10-byte binary ICCID to 20-char uppercase hex string."""
    if len(iccid) != IPAD_ICCID_LEN:
        raise ValueError(f"ICCID must be {IPAD_ICCID_LEN} bytes")
    return iccid.hex().upper()


def eid_to_str(eid: bytes) -> str:
    """Convert 16-byte binary EID to 32-char uppercase hex string."""
    if len(eid) != IPAD_EID_LEN:
        raise ValueError(f"EID must be {IPAD_EID_LEN} bytes")
    return eid.hex().upper()
