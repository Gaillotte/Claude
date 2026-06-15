"""
Tests for the log sink module (ipad_log.py).
Mirrors test_ipad_log.cpp.
"""

import socket
import threading
import pytest

from ipad import IpadConfig, IpadHandle, IpadLogLevel, MockBackend
from ipad.log_sink import (
    IpadUserLogLevel, log_sink_tcp, log_sink_serial,
)
from ipad.types import IpadError, IpadStatus
from ipad.mock_backend import MockConfig
from ipad import IpadDlParams


def make_handle(delay_ms: int = 10) -> IpadHandle:
    cfg = IpadConfig(timeout_ms=5000, log_level=IpadLogLevel.DEBUG)
    mock_cfg = MockConfig(download_delay_ms=delay_ms)
    return IpadHandle(cfg, backend=MockBackend(mock_cfg))


# ── Loopback TCP server ────────────────────────────────────────────────────────
class LoopbackServer:
    """Minimal one-connection TCP listener running in a background thread."""

    def __init__(self, port: int):
        self.port = port
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", port))
        self._server.listen(1)
        self._client: socket.socket | None = None
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self):
        self._client, _ = self._server.accept()

    def read_all(self, timeout_ms: int = 1000) -> str:
        self._thread.join(timeout=timeout_ms / 1000.0 + 1)
        if self._client is None:
            return ""
        self._client.settimeout(timeout_ms / 1000.0)
        data = b""
        try:
            while True:
                chunk = self._client.recv(256)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        return data.decode(errors="replace")

    def close(self):
        if self._client:
            try:
                self._client.close()
            except OSError:
                pass
        try:
            self._server.close()
        except OSError:
            pass


# ── TC-SINK-NULL ──────────────────────────────────────────────────────────────
class TestSinkNullParams:
    def test_tcp_empty_host(self):
        with pytest.raises(IpadError) as exc:
            log_sink_tcp("", 9001)
        assert exc.value.status == IpadStatus.ERR_INVALID_PARAM

    def test_tcp_port_zero(self):
        with pytest.raises(IpadError) as exc:
            log_sink_tcp("127.0.0.1", 0)
        assert exc.value.status == IpadStatus.ERR_INVALID_PARAM

    def test_tcp_port_too_large(self):
        with pytest.raises(IpadError) as exc:
            log_sink_tcp("127.0.0.1", 70000)
        assert exc.value.status == IpadStatus.ERR_INVALID_PARAM

    def test_serial_empty_device(self):
        with pytest.raises(IpadError) as exc:
            log_sink_serial("")
        assert exc.value.status == IpadStatus.ERR_INVALID_PARAM


# ── TC-SINK-SERIAL ────────────────────────────────────────────────────────────
class TestSinkSerial:
    def test_serial_bad_device(self):
        """Non-existent device → HAL_FAILURE (or NOT_SUPPORTED without pyserial)."""
        with pytest.raises(IpadError) as exc:
            log_sink_serial("/dev/nonexistent_tty_xyz_abc")
        assert exc.value.status in (
            IpadStatus.ERR_HAL_FAILURE,
            IpadStatus.ERR_NOT_SUPPORTED,
        )


# ── TC-SINK-TCP ───────────────────────────────────────────────────────────────
class TestSinkTcp:
    def test_connect_failure_no_listener(self):
        with pytest.raises(IpadError) as exc:
            log_sink_tcp("127.0.0.1", 19990)
        assert exc.value.status == IpadStatus.ERR_TRANSPORT

    def test_simple_level_receives_timestamped_lines(self):
        port = 19921
        srv = LoopbackServer(port)
        try:
            sink = log_sink_tcp("127.0.0.1", port)
            with make_handle(delay_ms=5) as hdl:
                sink.attach(hdl, IpadUserLogLevel.SIMPLE)
                hdl.profile_download(IpadDlParams(
                    activation_code="LPA:1$smdp.test.io$LOG_SIMPLE"))
                sink.detach(hdl)
            sink.close()

            received = srv.read_all(1000)
            assert received, "No data received on TCP sink"
            assert "20" in received, "No timestamp found"
            assert "INFO" in received, "No INFO tag"
            assert "DEBUG" not in received, "Unexpected DEBUG at SIMPLE level"
        finally:
            srv.close()

    def test_detail_level_has_sub_ms_timestamp(self):
        port = 19922
        srv = LoopbackServer(port)
        try:
            sink = log_sink_tcp("127.0.0.1", port)
            with make_handle(delay_ms=5) as hdl:
                sink.attach(hdl, IpadUserLogLevel.DETAIL)
                hdl.profile_download(IpadDlParams(
                    activation_code="LPA:1$smdp.test.io$LOG_DETAIL"))
                sink.detach(hdl)
            sink.close()

            received = srv.read_all(1000)
            assert received
            assert "." in received, "No sub-ms timestamp dot found"
        finally:
            srv.close()

    def test_none_level_produces_no_output(self):
        port = 19923
        srv = LoopbackServer(port)
        try:
            sink = log_sink_tcp("127.0.0.1", port)
            with make_handle(delay_ms=5) as hdl:
                sink.attach(hdl, IpadUserLogLevel.NONE)
                hdl.profile_download(IpadDlParams(
                    activation_code="LPA:1$smdp.test.io$LOG_NONE"))
                sink.detach(hdl)
            sink.close()

            received = srv.read_all(200)
            assert received == "", f"Got unexpected output: {received!r}"
        finally:
            srv.close()

    def test_detach_restores_silence(self):
        port = 19924
        srv = LoopbackServer(port)
        try:
            sink = log_sink_tcp("127.0.0.1", port)
            with make_handle(delay_ms=5) as hdl:
                sink.attach(hdl, IpadUserLogLevel.SIMPLE)
                sink.detach(hdl)
                sink.close()

                # After detach, handler should be gone; count via custom handler
                count = [0]
                hdl.log_set_handler(
                    lambda lvl, mod, msg, ctx: count.__setitem__(0, count[0] + 1)
                )
                hdl.log_set_level(IpadLogLevel.DEBUG)
                hdl.profile_download(IpadDlParams(
                    activation_code="LPA:1$smdp.test.io$LOG_DETACH"))

            assert count[0] > 0, "Custom handler received no calls"

            # Original sink (already detached) should have received nothing
            received = srv.read_all(200)
            assert received == ""
        finally:
            srv.close()
