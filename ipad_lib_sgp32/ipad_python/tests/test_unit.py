"""
Unit tests mirroring the C++ test_ipad_unit.cpp test suite.
Run with: pytest tests/test_unit.py -v
"""

import threading
import pytest

from ipad import (
    IpadConfig, IpadDlParams, IpadError, IpadEventType, IpadHandle,
    IpadLogLevel, IpadProfileState, IpadStatus, IpadVersion,
    MockBackend, iccid_to_str, eid_to_str, ipad_strerror,
    IPAD_EID_LEN, IPAD_ICCID_LEN,
)
from ipad.mock_backend import MockConfig, IpadProfile
from ipad.types import IpadTransport


# ── Helpers ───────────────────────────────────────────────────────────────────
def make_handle(**kw) -> IpadHandle:
    cfg = IpadConfig(timeout_ms=5000, log_level=IpadLogLevel.DEBUG)
    mock_cfg = MockConfig(**kw) if kw else MockConfig()
    return IpadHandle(cfg, backend=MockBackend(mock_cfg))


# ── TC-INIT ───────────────────────────────────────────────────────────────────
class TestInit:
    def test_init_ok(self):
        hdl = make_handle()
        hdl.deinit()

    def test_init_subsystem_not_ready(self):
        with pytest.raises(IpadError) as exc:
            make_handle(subsystem_ready=False)
        assert exc.value.status == IpadStatus.ERR_TELSDK

    def test_init_subsystem_timeout(self):
        with pytest.raises(IpadError) as exc:
            make_handle(subsystem_ready_timeout=True)
        assert exc.value.status == IpadStatus.ERR_TIMEOUT

    def test_context_manager(self):
        cfg = IpadConfig(timeout_ms=5000)
        with IpadHandle(cfg, backend=MockBackend()) as hdl:
            assert hdl.get_version().major == 1

    def test_configure_updates_settings(self):
        with make_handle() as hdl:
            new_cfg = IpadConfig(timeout_ms=10000, log_level=IpadLogLevel.INFO)
            hdl.configure(new_cfg)  # must not raise


# ── TC-VERSION ────────────────────────────────────────────────────────────────
class TestVersion:
    def test_get_version_fields(self):
        with make_handle() as hdl:
            v = hdl.get_version()
            assert isinstance(v, IpadVersion)
            assert v.major == 1
            assert v.minor == 0
            assert v.patch == 0
            assert "SGP.32" in v.sgp32_revision
            assert v.telsdk_version == "mock-1.0"

    def test_selftest_returns_bitmask(self):
        with make_handle() as hdl:
            result = hdl.selftest()
            assert isinstance(result, int)
            assert result > 0


# ── TC-EID ────────────────────────────────────────────────────────────────────
class TestEid:
    def test_get_eid_length(self):
        with make_handle() as hdl:
            eid = hdl.get_eid()
            assert len(eid) == IPAD_EID_LEN

    def test_get_euicc_info_fields(self):
        with make_handle() as hdl:
            info = hdl.get_euicc_info()
            assert len(info.eid) == IPAD_EID_LEN
            assert len(info.eid_str) == 32
            assert info.profile_capacity > 0

    def test_eid_to_str_roundtrip(self):
        eid = bytes(range(IPAD_EID_LEN))
        s = eid_to_str(eid)
        assert len(s) == 32
        assert s == eid.hex().upper()

    def test_iccid_to_str_length(self):
        iccid = bytes(IPAD_ICCID_LEN)
        s = iccid_to_str(iccid)
        assert len(s) == 20

    def test_iccid_to_str_wrong_length_raises(self):
        with pytest.raises(ValueError):
            iccid_to_str(b"\x00" * 5)

    def test_eid_to_str_wrong_length_raises(self):
        with pytest.raises(ValueError):
            eid_to_str(b"\x00" * 5)


# ── TC-STRERROR ───────────────────────────────────────────────────────────────
class TestStrerror:
    def test_ok_message(self):
        assert "success" in ipad_strerror(IpadStatus.OK).lower()

    def test_invalid_param_message(self):
        msg = ipad_strerror(IpadStatus.ERR_INVALID_PARAM)
        assert msg  # non-empty

    def test_unknown_status(self):
        assert "unknown" in ipad_strerror(-999).lower()

    def test_status_mapping_failed(self):
        assert "telsdk" in ipad_strerror(IpadStatus.ERR_TELSDK).lower()

    def test_status_mapping_not_supported(self):
        assert ipad_strerror(IpadStatus.ERR_NOT_SUPPORTED)


# ── TC-PROFILE-LIST ───────────────────────────────────────────────────────────
class TestProfileList:
    def test_list_empty(self):
        with make_handle() as hdl:
            profiles = hdl.profile_list()
            assert profiles == []

    def test_list_with_initial_profiles(self):
        p = IpadProfile(iccid=bytes(IPAD_ICCID_LEN),
                        state=IpadProfileState.ENABLED,
                        nickname="test", provider="op",
                        profile_name="pn")
        mock_cfg = MockConfig(initial_profiles=[p])
        cfg = IpadConfig(timeout_ms=5000)
        with IpadHandle(cfg, backend=MockBackend(mock_cfg)) as hdl:
            lst = hdl.profile_list()
            assert len(lst) == 1

    def test_list_fails_on_telsdk_error(self):
        with make_handle(fail_get_profiles=True) as hdl:
            with pytest.raises(IpadError) as exc:
                hdl.profile_list()
            assert exc.value.status == IpadStatus.ERR_TELSDK


# ── TC-PROFILE-DOWNLOAD ───────────────────────────────────────────────────────
class TestProfileDownload:
    def test_download_basic(self):
        with make_handle(download_delay_ms=5) as hdl:
            params = IpadDlParams(
                activation_code="LPA:1$smdp.test.io$MATCHID001",
            )
            iccid = hdl.profile_download(params)
            assert len(iccid) == IPAD_ICCID_LEN

    def test_download_no_activation_code_raises(self):
        with make_handle() as hdl:
            with pytest.raises(IpadError) as exc:
                hdl.profile_download(IpadDlParams())
            assert exc.value.status == IpadStatus.ERR_INVALID_PARAM

    def test_download_adds_to_list(self):
        with make_handle(download_delay_ms=5) as hdl:
            params = IpadDlParams(activation_code="LPA:1$x$y")
            iccid = hdl.profile_download(params)
            profiles = hdl.profile_list()
            assert any(bytes(p.iccid) == bytes(iccid) for p in profiles)

    def test_download_fail_add_profile(self):
        with make_handle(fail_add_profile=True) as hdl:
            with pytest.raises(IpadError) as exc:
                hdl.profile_download(IpadDlParams(
                    activation_code="LPA:1$x$y"))
            assert exc.value.status == IpadStatus.ERR_TELSDK

    def test_download_fail_status(self):
        with make_handle(fail_add_profile_status=True) as hdl:
            with pytest.raises(IpadError) as exc:
                hdl.profile_download(IpadDlParams(
                    activation_code="LPA:1$x$y"))
            assert exc.value.status == IpadStatus.ERR_EIM_REJECTED

    def test_download_error_at_end(self):
        with make_handle(download_error_at_end=True) as hdl:
            with pytest.raises(IpadError) as exc:
                hdl.profile_download(IpadDlParams(
                    activation_code="LPA:1$x$y"))
            assert exc.value.status == IpadStatus.ERR_TRANSPORT

    def test_download_auto_enable(self):
        with make_handle(download_delay_ms=5) as hdl:
            params = IpadDlParams(activation_code="LPA:1$x$y",
                                  auto_enable=True)
            iccid = hdl.profile_download(params)
            state = hdl.profile_get_state(iccid)
            assert state == IpadProfileState.ENABLED

    def test_download_async(self):
        results = []
        event = threading.Event()

        def cb(status, iccid, ctx):
            results.append((status, iccid))
            event.set()

        with make_handle(download_delay_ms=5) as hdl:
            params = IpadDlParams(activation_code="LPA:1$x$y")
            hdl.profile_download_async(params, cb)
            assert event.wait(timeout=3)
            assert results[0][0] == IpadStatus.OK
            assert len(results[0][1]) == IPAD_ICCID_LEN


# ── TC-PROFILE-ENABLE/DISABLE/DELETE ─────────────────────────────────────────
class TestProfileOps:
    def _setup_profile(self, hdl) -> bytes:
        params = IpadDlParams(activation_code="LPA:1$x$y")
        return hdl.profile_download(params)

    def test_enable(self):
        with make_handle(download_delay_ms=5) as hdl:
            iccid = self._setup_profile(hdl)
            hdl.profile_enable(iccid)
            assert hdl.profile_get_state(iccid) == IpadProfileState.ENABLED

    def test_disable(self):
        with make_handle(download_delay_ms=5) as hdl:
            iccid = self._setup_profile(hdl)
            hdl.profile_enable(iccid)
            hdl.profile_disable(iccid)
            assert hdl.profile_get_state(iccid) == IpadProfileState.DISABLED

    def test_delete(self):
        with make_handle(download_delay_ms=5) as hdl:
            iccid = self._setup_profile(hdl)
            hdl.profile_delete(iccid)
            with pytest.raises(IpadError) as exc:
                hdl.profile_get(iccid)
            assert exc.value.status == IpadStatus.ERR_PROFILE_NOT_FOUND

    def test_enable_not_found(self):
        with make_handle() as hdl:
            with pytest.raises(IpadError) as exc:
                hdl.profile_enable(bytes(IPAD_ICCID_LEN))
            assert exc.value.status == IpadStatus.ERR_PROFILE_NOT_FOUND

    def test_delete_not_found(self):
        with make_handle() as hdl:
            with pytest.raises(IpadError) as exc:
                hdl.profile_delete(bytes(IPAD_ICCID_LEN))
            assert exc.value.status == IpadStatus.ERR_PROFILE_NOT_FOUND

    def test_set_nickname(self):
        with make_handle(download_delay_ms=5) as hdl:
            iccid = self._setup_profile(hdl)
            hdl.profile_set_nickname(iccid, "MyNick")
            p = hdl.profile_get(iccid)
            assert p.nickname == "MyNick"

    def test_enable_fail_telsdk(self):
        with make_handle(download_delay_ms=5, fail_set_profile=True) as hdl:
            # Need a profile but fail_set_profile blocks enable — create directly
            backend = hdl._backend
            backend.mock_cfg.fail_set_profile = False
            iccid = hdl.profile_download(IpadDlParams(
                activation_code="LPA:1$x$y"))
            backend.mock_cfg.fail_set_profile = True
            with pytest.raises(IpadError) as exc:
                hdl.profile_enable(iccid)
            assert exc.value.status == IpadStatus.ERR_TELSDK

    def test_delete_fail_telsdk(self):
        with make_handle(download_delay_ms=5) as hdl:
            iccid = hdl.profile_download(IpadDlParams(
                activation_code="LPA:1$x$y"))
            hdl._backend.mock_cfg.fail_delete_profile = True
            with pytest.raises(IpadError) as exc:
                hdl.profile_delete(iccid)
            assert exc.value.status == IpadStatus.ERR_TELSDK


# ── TC-EVENTS ─────────────────────────────────────────────────────────────────
class TestEvents:
    def test_subscribe_and_receive(self):
        received = []

        with make_handle(download_delay_ms=5) as hdl:
            def cb(evt, ctx):
                received.append(evt)

            sub_id = hdl.event_subscribe(IpadEventType.ALL, cb)
            hdl.profile_download(IpadDlParams(activation_code="LPA:1$x$y"))
            hdl.event_unsubscribe(sub_id)

        assert any(e.type == IpadEventType.PROFILE_INSTALLED
                   for e in received)

    def test_unsubscribe_stops_events(self):
        received = []

        with make_handle(download_delay_ms=5) as hdl:
            def cb(evt, ctx):
                received.append(evt)

            sub_id = hdl.event_subscribe(IpadEventType.ALL, cb)
            hdl.event_unsubscribe(sub_id)
            hdl.profile_download(IpadDlParams(activation_code="LPA:1$x$y"))

        assert received == []

    def test_event_pump_no_raise(self):
        with make_handle() as hdl:
            hdl.event_pump(10)


# ── TC-LOGGING ────────────────────────────────────────────────────────────────
class TestLogging:
    def test_log_handler_receives_messages(self):
        records = []

        with make_handle(download_delay_ms=5) as hdl:
            hdl.log_set_handler(
                lambda lvl, mod, msg, ctx: records.append((lvl, mod, msg)),
            )
            hdl.log_set_level(IpadLogLevel.DEBUG)
            hdl.profile_download(IpadDlParams(activation_code="LPA:1$x$y"))

        assert records  # at least one message logged

    def test_log_handler_none_silences(self):
        records = []

        with make_handle(download_delay_ms=5) as hdl:
            hdl.log_set_handler(
                lambda lvl, mod, msg, ctx: records.append(msg),
            )
            hdl.log_set_level(IpadLogLevel.DEBUG)
            hdl.log_set_handler(None)
            hdl.profile_download(IpadDlParams(activation_code="LPA:1$x$y"))

        assert records == []

    def test_log_level_filters(self):
        records = []

        with make_handle(download_delay_ms=5) as hdl:
            hdl.log_set_handler(
                lambda lvl, mod, msg, ctx: records.append(lvl),
            )
            hdl.log_set_level(IpadLogLevel.INFO)  # only INFO and above
            hdl.profile_download(IpadDlParams(activation_code="LPA:1$x$y"))

        for lvl in records:
            assert lvl.value <= IpadLogLevel.INFO.value


# ── TC-DIAGNOSTICS ────────────────────────────────────────────────────────────
class TestDiagnostics:
    def test_diag_export_json_valid(self):
        import json

        with make_handle(download_delay_ms=5) as hdl:
            hdl.profile_download(IpadDlParams(activation_code="LPA:1$x$y"))
            js = hdl.diag_export_json()
            data = json.loads(js)
            assert "profile_count" in data
            assert data["profile_count"] == 1
