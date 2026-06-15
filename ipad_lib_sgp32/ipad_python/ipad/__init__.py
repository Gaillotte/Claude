"""
IPAd — GSMA SGP.32 IoT Profile Assistant Device library (Python port).

Provides the same semantics as the C ipad library.  Two backends are
available:

  MockBackend   — in-process simulation, no hardware required (default)
  CBackend      — thin ctypes wrapper around the compiled libipad.so

Usage::

    from ipad import IpadHandle, IpadConfig, IpadLogLevel, MockBackend

    cfg = IpadConfig(timeout_ms=5000, log_level=IpadLogLevel.DEBUG)
    with IpadHandle(cfg, backend=MockBackend()) as hdl:
        eid = hdl.get_eid()
        print(hdl.iccid_to_str(eid))
"""

from .types import (
    iccid_to_str, eid_to_str, ipad_strerror,
    IpadStatus,
    IpadTransport,
    IpadLogLevel,
    IpadProfileState,
    IpadEventType,
    IpadProfile,
    IpadEuiccInfo,
    IpadTlsCfg,
    IpadConfig,
    IpadDlParams,
    IpadEvent,
    IpadVersion,
    IpadError,
    IPAD_EID_LEN,
    IPAD_ICCID_LEN,
    IPAD_STR_MAX,
)
from .handle import IpadHandle
from .mock_backend import MockBackend
from .log_sink import (
    IpadUserLogLevel,
    IpadSinkType,
    IpadLogSink,
    log_sink_serial,
    log_sink_tcp,
)

__version__ = "1.0.0"
__all__ = [
    "IpadStatus", "IpadTransport", "IpadLogLevel", "IpadProfileState",
    "IpadEventType", "IpadProfile", "IpadEuiccInfo", "IpadTlsCfg",
    "IpadConfig", "IpadDlParams", "IpadEvent", "IpadVersion",
    "IpadError",
    "iccid_to_str", "eid_to_str", "ipad_strerror",
    "IPAD_EID_LEN", "IPAD_ICCID_LEN", "IPAD_STR_MAX",
    "IpadHandle",
    "MockBackend",
    "IpadUserLogLevel", "IpadSinkType", "IpadLogSink",
    "log_sink_serial", "log_sink_tcp",
]
