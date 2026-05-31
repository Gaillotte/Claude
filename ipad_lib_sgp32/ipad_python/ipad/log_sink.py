"""
Log sink module — Python port of ipad_log.h / ipad_log.cpp.

Provides serial-port and TCP client sinks with three user-facing log levels.

Typical usage::

    from ipad import IpadHandle, IpadConfig, IpadLogLevel
    from ipad.log_sink import log_sink_tcp, IpadUserLogLevel

    cfg = IpadConfig(timeout_ms=5000, log_level=IpadLogLevel.DEBUG)
    with IpadHandle(cfg) as hdl:
        sink = log_sink_tcp("127.0.0.1", 9000)
        sink.attach(hdl, IpadUserLogLevel.SIMPLE)

        # ... do work ...

        sink.detach(hdl)
        sink.close()
"""

from __future__ import annotations

import datetime
import enum
import socket
import threading
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .handle import IpadHandle

from .types import IpadError, IpadLogLevel, IpadStatus


# ── User-facing log levels ────────────────────────────────────────────────────
class IpadUserLogLevel(enum.IntEnum):
    NONE   = 0  # no output
    SIMPLE = 1  # timestamp + module + short message
    DETAIL = 3  # full detail, sub-millisecond timestamp


# ── Sink type ─────────────────────────────────────────────────────────────────
class IpadSinkType(enum.IntEnum):
    SERIAL = 1
    TCP    = 2


# ── Level mapping ─────────────────────────────────────────────────────────────
_USER_TO_INTERNAL = {
    IpadUserLogLevel.SIMPLE: IpadLogLevel.INFO,
    IpadUserLogLevel.DETAIL: IpadLogLevel.DEBUG,
    IpadUserLogLevel.NONE:   IpadLogLevel.NONE,
}

_LEVEL_TAG = {
    IpadLogLevel.ERROR: "ERROR",
    IpadLogLevel.WARN:  "WARN ",
    IpadLogLevel.INFO:  "INFO ",
    IpadLogLevel.DEBUG: "DEBUG",
}


def _build_line(level: IpadLogLevel, module: str, message: str,
                user_lvl: IpadUserLogLevel) -> str:
    now = datetime.datetime.now()
    if user_lvl >= IpadUserLogLevel.DETAIL:
        ts = now.strftime("%Y-%m-%d %H:%M:%S") + f".{now.microsecond // 1000:03d}"
    else:
        ts = now.strftime("%Y-%m-%d %H:%M:%S")
    tag = _LEVEL_TAG.get(level, "?    ")
    return f"[{ts}] [{tag}] [{module}] {message}\n"


# ── Sink descriptor ───────────────────────────────────────────────────────────
class IpadLogSink:
    """
    Opaque sink descriptor.  Do not construct directly; use
    :func:`log_sink_serial` or :func:`log_sink_tcp`.
    """

    def __init__(self, sink_type: IpadSinkType):
        self.type = sink_type
        self._sock:      Optional[socket.socket] = None
        self._serial_fd: Optional[object] = None   # io.RawIOBase
        self._user_lvl:  IpadUserLogLevel = IpadUserLogLevel.NONE
        self._lock = threading.Lock()

    # ── Callback installed into the backend ──────────────────────────────────

    def _callback(self, level: IpadLogLevel, module: str,
                  message: str, _ctx: object) -> None:
        line = _build_line(level, module, message, self._user_lvl)
        data = line.encode()
        with self._lock:
            try:
                if self._sock is not None:
                    self._sock.sendall(data)
                elif self._serial_fd is not None:
                    self._serial_fd.write(data)
            except OSError:
                pass  # drop on broken pipe / disconnection

    # ── attach / detach ───────────────────────────────────────────────────────

    def attach(self, hdl: "IpadHandle",
               level: IpadUserLogLevel = IpadUserLogLevel.SIMPLE) -> None:
        """Attach this sink to *hdl* at the given user log level."""
        self._user_lvl = level
        if level == IpadUserLogLevel.NONE:
            hdl.log_set_level(IpadLogLevel.NONE)
            hdl.log_set_handler(None)
            return
        hdl.log_set_level(_USER_TO_INTERNAL[level])
        hdl.log_set_handler(self._callback)

    def detach(self, hdl: "IpadHandle") -> None:
        """Detach this sink and restore silent mode."""
        hdl.log_set_handler(None)
        hdl.log_set_level(IpadLogLevel.NONE)

    def close(self) -> None:
        """Close the underlying transport."""
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
            if self._serial_fd is not None:
                try:
                    self._serial_fd.close()
                except OSError:
                    pass
                self._serial_fd = None


# ── Constructors ──────────────────────────────────────────────────────────────

def log_sink_serial(device: str, baudrate: int = 115200) -> IpadLogSink:
    """
    Open a serial-port sink.

    :param device:   Path to tty device, e.g. ``"/dev/ttyUSB0"``.
    :param baudrate: Baud rate (9600, 115200, 921600 …).
    :raises IpadError: ``ERR_INVALID_PARAM`` for bad arguments,
                       ``ERR_HAL_FAILURE`` if the port cannot be opened.
    """
    if not device:
        raise IpadError(IpadStatus.ERR_INVALID_PARAM, "device required")

    try:
        import serial  # type: ignore[import]
    except ImportError:
        raise IpadError(IpadStatus.ERR_NOT_SUPPORTED,
                        "pyserial not installed (pip install pyserial)")

    try:
        ser = serial.Serial(device, baudrate, timeout=None)
    except serial.SerialException as e:
        raise IpadError(IpadStatus.ERR_HAL_FAILURE, str(e)) from e

    sink = IpadLogSink(IpadSinkType.SERIAL)
    sink._serial_fd = ser
    return sink


def log_sink_tcp(host: str, port: int) -> IpadLogSink:
    """
    Connect a TCP client sink.

    :param host: Remote host (IPv4 / hostname).
    :param port: Remote TCP port (1-65535).
    :raises IpadError: ``ERR_INVALID_PARAM`` or ``ERR_TRANSPORT``.
    """
    if not host:
        raise IpadError(IpadStatus.ERR_INVALID_PARAM, "host required")
    if not (1 <= port <= 65535):
        raise IpadError(IpadStatus.ERR_INVALID_PARAM,
                        f"port must be 1-65535, got {port}")

    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(None)  # blocking from here on
    except OSError as e:
        raise IpadError(IpadStatus.ERR_TRANSPORT, str(e)) from e

    sink = IpadLogSink(IpadSinkType.TCP)
    sink._sock = sock
    return sink
