"""Abstract backend interface."""

from __future__ import annotations

import abc
from typing import Callable, List, Optional, Tuple

from .types import (
    IpadConfig, IpadDlParams, IpadEuiccInfo, IpadEvent,
    IpadLogLevel, IpadProfile, IpadProfileState, IpadVersion,
    IpadStatus,
)


class IpadBackend(abc.ABC):
    """Interface that concrete backends (mock, C-library) must implement."""

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    @abc.abstractmethod
    def init(self, cfg: IpadConfig) -> None: ...

    @abc.abstractmethod
    def deinit(self) -> None: ...

    @abc.abstractmethod
    def configure(self, cfg: IpadConfig) -> None: ...

    # ── Version / self-test ───────────────────────────────────────────────────
    @abc.abstractmethod
    def get_version(self) -> IpadVersion: ...

    @abc.abstractmethod
    def selftest(self) -> int: ...

    # ── eUICC identity ────────────────────────────────────────────────────────
    @abc.abstractmethod
    def get_eid(self) -> bytes: ...

    @abc.abstractmethod
    def get_euicc_info(self) -> IpadEuiccInfo: ...

    # ── Profile management ────────────────────────────────────────────────────
    @abc.abstractmethod
    def profile_list(self) -> List[IpadProfile]: ...

    @abc.abstractmethod
    def profile_get(self, iccid: bytes) -> IpadProfile: ...

    @abc.abstractmethod
    def profile_download(self, params: IpadDlParams) -> bytes: ...

    @abc.abstractmethod
    def profile_enable(self, iccid: bytes) -> None: ...

    @abc.abstractmethod
    def profile_disable(self, iccid: bytes) -> None: ...

    @abc.abstractmethod
    def profile_delete(self, iccid: bytes) -> None: ...

    @abc.abstractmethod
    def profile_set_nickname(self, iccid: bytes, nickname: str) -> None: ...

    @abc.abstractmethod
    def profile_get_state(self, iccid: bytes) -> IpadProfileState: ...

    # ── Events ────────────────────────────────────────────────────────────────
    @abc.abstractmethod
    def event_subscribe(self, mask: int,
                        cb: Callable[["IpadHandle", IpadEvent], None],
                        user_ctx: object) -> int: ...

    @abc.abstractmethod
    def event_unsubscribe(self, sub_id: int) -> None: ...

    @abc.abstractmethod
    def event_pump(self, timeout_ms: int) -> None: ...

    # ── Logging ───────────────────────────────────────────────────────────────
    @abc.abstractmethod
    def log_set_handler(self,
                        cb: Optional[Callable[[IpadLogLevel, str, str], None]],
                        user_ctx: object) -> None: ...

    @abc.abstractmethod
    def log_set_level(self, level: IpadLogLevel) -> None: ...

    # ── Diagnostics ───────────────────────────────────────────────────────────
    @abc.abstractmethod
    def diag_export_json(self) -> str: ...
