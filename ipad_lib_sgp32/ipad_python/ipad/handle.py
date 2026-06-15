"""IpadHandle — main entry point mirroring the C ipad_handle_t / API."""

from __future__ import annotations

from typing import Callable, List, Optional

from .backend import IpadBackend
from .mock_backend import MockBackend
from .types import (
    IpadConfig, IpadDlParams, IpadEuiccInfo, IpadError, IpadEvent,
    IpadEventType, IpadLogLevel, IpadProfile, IpadProfileState, IpadStatus,
    IpadVersion, iccid_to_str, eid_to_str, ipad_strerror,
)


class IpadHandle:
    """
    Python equivalent of ipad_handle_t.

    Wraps a backend and exposes the full IPAd API as methods.
    Can be used as a context manager::

        with IpadHandle(cfg) as hdl:
            eid = hdl.get_eid()
    """

    def __init__(self, cfg: IpadConfig,
                 backend: Optional[IpadBackend] = None):
        self._backend: IpadBackend = backend or MockBackend()
        self._backend.init(cfg)

    def __enter__(self) -> "IpadHandle":
        return self

    def __exit__(self, *_) -> None:
        self.deinit()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def deinit(self) -> None:
        """Release all resources."""
        self._backend.deinit()

    def configure(self, cfg: IpadConfig) -> None:
        """Update configuration at runtime."""
        self._backend.configure(cfg)

    # ── Version / self-test ───────────────────────────────────────────────────

    def get_version(self) -> IpadVersion:
        return self._backend.get_version()

    def selftest(self) -> int:
        """Run internal self-test.  Returns a bitmask of passed sub-tests."""
        return self._backend.selftest()

    # ── eUICC identity ────────────────────────────────────────────────────────

    def get_eid(self) -> bytes:
        """Return the 16-byte binary EID."""
        return self._backend.get_eid()

    def get_euicc_info(self) -> IpadEuiccInfo:
        return self._backend.get_euicc_info()

    # ── Profile management ────────────────────────────────────────────────────

    def profile_list(self) -> List[IpadProfile]:
        return self._backend.profile_list()

    def profile_get(self, iccid: bytes) -> IpadProfile:
        return self._backend.profile_get(iccid)

    def profile_download(self, params: IpadDlParams) -> bytes:
        """
        Synchronous download.  Returns the ICCID (10 bytes) of the
        newly installed profile.
        """
        return self._backend.profile_download(params)

    def profile_download_async(self, params: IpadDlParams,
                               cb: Callable[[IpadStatus, Optional[bytes]], None],
                               user_ctx: object = None) -> None:
        """
        Asynchronous download.  The callback receives (status, iccid).
        Runs the download in a daemon thread.
        """
        import threading

        def _run():
            try:
                iccid = self._backend.profile_download(params)
                cb(IpadStatus.OK, iccid, user_ctx)
            except IpadError as e:
                cb(e.status, None, user_ctx)

        t = threading.Thread(target=_run, daemon=True)
        t.start()

    def profile_enable(self, iccid: bytes) -> None:
        self._backend.profile_enable(iccid)

    def profile_disable(self, iccid: bytes) -> None:
        self._backend.profile_disable(iccid)

    def profile_delete(self, iccid: bytes) -> None:
        self._backend.profile_delete(iccid)

    def profile_set_nickname(self, iccid: bytes, nickname: str) -> None:
        self._backend.profile_set_nickname(iccid, nickname)

    def profile_get_state(self, iccid: bytes) -> IpadProfileState:
        return self._backend.profile_get_state(iccid)

    # ── Events ────────────────────────────────────────────────────────────────

    def event_subscribe(self, mask: int,
                        cb: Callable[["IpadHandle", IpadEvent], None],
                        user_ctx: object = None) -> int:
        return self._backend.event_subscribe(mask, cb, user_ctx)

    def event_unsubscribe(self, sub_id: int) -> None:
        self._backend.event_unsubscribe(sub_id)

    def event_pump(self, timeout_ms: int = 100) -> None:
        self._backend.event_pump(timeout_ms)

    # ── Logging ───────────────────────────────────────────────────────────────

    def log_set_handler(self,
                        cb: Optional[Callable[[IpadLogLevel, str, str, object], None]],
                        user_ctx: object = None) -> None:
        self._backend.log_set_handler(cb, user_ctx)

    def log_set_level(self, level: IpadLogLevel) -> None:
        self._backend.log_set_level(level)

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def diag_export_json(self) -> str:
        return self._backend.diag_export_json()

    # ── Utilities (static / class methods) ───────────────────────────────────

    @staticmethod
    def iccid_to_str(iccid: bytes) -> str:
        return iccid_to_str(iccid)

    @staticmethod
    def eid_to_str(eid: bytes) -> str:
        return eid_to_str(eid)

    @staticmethod
    def strerror(status: int) -> str:
        return ipad_strerror(status)
