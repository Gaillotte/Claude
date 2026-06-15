/**
 * @file test_ipad_integration.cpp
 * @brief IPAd library — Integration tests (end-to-end workflows)
 *
 * These tests exercise full SGP.32 workflows:
 *  - TC-WF-01: Download → Enable → Disable → Delete
 *  - TC-WF-02: Multiple profiles coexistence
 *  - TC-WF-03: Event-driven download
 *  - TC-WF-04: Recovery from backend failures
 *  - TC-WF-05: Concurrent operations
 */

#include <gtest/gtest.h>
#include <array>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include "ipad/ipad.h"
#include "mocks/mock_telsdk.h"

using MockMgr = telux::tel::ISimProfileManager;

/* ──────────────────────────────────────────────────────────────────────────────
 * Fixture
 * ────────────────────────────────────────────────────────────────────────── */
class IpadIntegration : public ::testing::Test {
protected:
    ipad_handle_t hdl{nullptr};
    MockMgr      *mock{nullptr};

    void SetUp() override {
        auto &f = telux::tel::PhoneFactory::getInstance();
        f.sim_mgr_  = std::make_shared<MockMgr>();
        f.card_mgr_ = std::make_shared<telux::tel::ICardManager>();
        mock = f.sim_mgr_.get();
        mock->mock_cfg.download_delay_ms = 80;

        ipad_config_t cfg{};
        cfg.timeout_ms = 8000;
        cfg.log_level  = IPAD_LOG_INFO;
        ASSERT_EQ(IPAD_OK, ipad_init(&cfg, &hdl));
    }

    void TearDown() override {
        if (hdl) { ipad_deinit(hdl); hdl = nullptr; }
    }

    std::array<uint8_t, IPAD_ICCID_LEN> download_profile(const std::string &ac) {
        ipad_dl_params_t p{};
        p.activation_code = ac.c_str();
        p.auto_enable     = false;
        std::array<uint8_t, IPAD_ICCID_LEN> iccid{};
        EXPECT_EQ(IPAD_OK, ipad_profile_download(hdl, &p, iccid.data()));
        return iccid;
    }
};

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-WF-01: Full lifecycle — Download → Enable → Disable → Delete
 * ══════════════════════════════════════════════════════════════════════════ */
TEST_F(IpadIntegration, TC_WF_01_FullLifecycle) {
    /* 1. Download */
    ipad_dl_params_t params{};
    params.activation_code = "LPA:1$smdp.carrier.io$WF01TEST";
    ipad_iccid_t iccid{};
    ASSERT_EQ(IPAD_OK, ipad_profile_download(hdl, &params, iccid));

    /* 2. Verify installed and disabled */
    ipad_profile_state_t state;
    ASSERT_EQ(IPAD_OK, ipad_profile_get_state(hdl, iccid, &state));
    EXPECT_EQ(IPAD_PROFILE_DISABLED, state);

    /* 3. Enable */
    ASSERT_EQ(IPAD_OK, ipad_profile_enable(hdl, iccid));
    ASSERT_EQ(IPAD_OK, ipad_profile_get_state(hdl, iccid, &state));
    EXPECT_EQ(IPAD_PROFILE_ENABLED, state);

    /* 4. Disable */
    ASSERT_EQ(IPAD_OK, ipad_profile_disable(hdl, iccid));
    ASSERT_EQ(IPAD_OK, ipad_profile_get_state(hdl, iccid, &state));
    EXPECT_EQ(IPAD_PROFILE_DISABLED, state);

    /* 5. Delete */
    ASSERT_EQ(IPAD_OK, ipad_profile_delete(hdl, iccid));
    ipad_profile_t p{};
    EXPECT_EQ(IPAD_ERR_PROFILE_NOT_FOUND, ipad_profile_get(hdl, iccid, &p));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-WF-02: Multiple profiles, only one active at a time
 * ══════════════════════════════════════════════════════════════════════════ */
TEST_F(IpadIntegration, TC_WF_02_MultipleProfiles_Exclusivity) {
    auto iccid_a = download_profile("LPA:1$smdp.carrier.io$PROFILEA");
    auto iccid_b = download_profile("LPA:1$smdp.carrier.io$PROFILEB");
    auto iccid_c = download_profile("LPA:1$smdp.carrier.io$PROFILEC");

    /* Enable A */
    ASSERT_EQ(IPAD_OK, ipad_profile_enable(hdl, iccid_a.data()));

    /* Enable B — A should become disabled */
    ASSERT_EQ(IPAD_OK, ipad_profile_enable(hdl, iccid_b.data()));

    ipad_profile_state_t sa, sb, sc;
    ASSERT_EQ(IPAD_OK, ipad_profile_get_state(hdl, iccid_a.data(), &sa));
    ASSERT_EQ(IPAD_OK, ipad_profile_get_state(hdl, iccid_b.data(), &sb));
    ASSERT_EQ(IPAD_OK, ipad_profile_get_state(hdl, iccid_c.data(), &sc));

    EXPECT_EQ(IPAD_PROFILE_DISABLED, sa);
    EXPECT_EQ(IPAD_PROFILE_ENABLED,  sb);
    EXPECT_EQ(IPAD_PROFILE_DISABLED, sc);

    /* Count total profiles */
    uint8_t count = 16;
    ipad_profile_t list[16];
    ASSERT_EQ(IPAD_OK, ipad_profile_list(hdl, list, &count));
    EXPECT_EQ(3, count);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-WF-03: Event-driven download with progress monitoring
 * ══════════════════════════════════════════════════════════════════════════ */
TEST_F(IpadIntegration, TC_WF_03_EventDrivenDownload) {
    struct EvtCtx {
        std::atomic<int> installed{0};
        std::atomic<int> progress_updates{0};
        std::atomic<int> enabled{0};
    } ctx;

    ipad_sub_id_t sub = ipad_event_subscribe(hdl, IPAD_EVT_ALL,
        [](ipad_handle_t h, const ipad_event_t *e, void *uctx) {
            auto *c = static_cast<EvtCtx*>(uctx);
            switch (e->type) {
                case IPAD_EVT_PROFILE_INSTALLED: c->installed++;     break;
                case IPAD_EVT_DOWNLOAD_PROGRESS: c->progress_updates++; break;
                case IPAD_EVT_PROFILE_ENABLED:   c->enabled++;       break;
                default: break;
            }
        }, &ctx);

    mock->mock_cfg.download_delay_ms = 200;

    ipad_dl_params_t params{};
    params.activation_code = "LPA:1$smdp.carrier.io$EVTTEST";
    params.auto_enable     = true;
    ipad_iccid_t iccid{};
    ASSERT_EQ(IPAD_OK, ipad_profile_download(hdl, &params, iccid));

    EXPECT_GE(ctx.installed.load(), 1);
    EXPECT_GE(ctx.progress_updates.load(), 1);

    ipad_event_unsubscribe(hdl, sub);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-WF-04: Recovery after backend failure
 * ══════════════════════════════════════════════════════════════════════════ */
TEST_F(IpadIntegration, TC_WF_04_RecoveryAfterFailure) {
    /* First attempt fails */
    mock->mock_cfg.fail_add_profile = true;
    ipad_dl_params_t params{};
    params.activation_code = "LPA:1$smdp.carrier.io$RECOVER";
    EXPECT_EQ(IPAD_ERR_TELSDK, ipad_profile_download(hdl, &params, nullptr));

    /* Recover — retry succeeds */
    mock->mock_cfg.fail_add_profile = false;
    ipad_iccid_t iccid{};
    EXPECT_EQ(IPAD_OK, ipad_profile_download(hdl, &params, iccid));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-WF-05: Concurrent list reads during download
 * ══════════════════════════════════════════════════════════════════════════ */
TEST_F(IpadIntegration, TC_WF_05_ConcurrentListDuringDownload) {
    mock->mock_cfg.download_delay_ms = 300;
    std::atomic<int> errors{0};

    /* Launch download asynchronously */
    std::thread downloader([this, &errors] {
        ipad_dl_params_t p{};
        p.activation_code = "LPA:1$smdp.carrier.io$CONCURRENT";
        ipad_status_t rc = ipad_profile_download(hdl, &p, nullptr);
        if (rc != IPAD_OK) errors++;
    });

    /* Concurrently list profiles 5 times during download */
    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        uint8_t count = 16;
        ipad_profile_t list[16];
        ipad_status_t rc = ipad_profile_list(hdl, list, &count);
        if (rc != IPAD_OK) errors++;
    }
    downloader.join();
    EXPECT_EQ(0, errors.load());
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-WF-06: Nickname persistence
 * ══════════════════════════════════════════════════════════════════════════ */
TEST_F(IpadIntegration, TC_WF_06_NicknamePersistence) {
    auto iccid = download_profile("LPA:1$smdp.carrier.io$NICKNAMETEST");
    ASSERT_EQ(IPAD_OK, ipad_profile_set_nickname(hdl, iccid.data(), "MyOperator"));

    ipad_profile_t p{};
    ASSERT_EQ(IPAD_OK, ipad_profile_get(hdl, iccid.data(), &p));
    EXPECT_STREQ("MyOperator", p.nickname);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-WF-07: Diagnostic JSON after state changes
 * ══════════════════════════════════════════════════════════════════════════ */
TEST_F(IpadIntegration, TC_WF_07_DiagnosticAfterChanges) {
    download_profile("LPA:1$smdp.carrier.io$DIAG1");
    download_profile("LPA:1$smdp.carrier.io$DIAG2");

    char buf[1024];
    ASSERT_EQ(IPAD_OK, ipad_diag_export_json(hdl, buf, sizeof(buf)));

    /* Should mention profile_count >= 2 */
    std::string json(buf);
    EXPECT_NE(std::string::npos, json.find("\"profile_count\""));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
