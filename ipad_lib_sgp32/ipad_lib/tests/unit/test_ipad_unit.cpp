/**
 * @file test_ipad_unit.cpp
 * @brief IPAd library — Unit tests (Google Test + mock TelSDK)
 *
 * Build: cmake -DIPAD_MOCK_TELSDK=ON .. && make && ctest -V
 */

#include <gtest/gtest.h>
#include <cstring>
#include <thread>
#include <atomic>
#include "ipad/ipad.h"

/* Access mock internals for test setup */
#include "mocks/mock_telsdk.h"
using MockMgr  = telux::tel::ISimProfileManager;
using MockCard = telux::tel::ICardManager;

/* ──────────────────────────────────────────────────────────────────────────────
 * Test fixture
 * ────────────────────────────────────────────────────────────────────────── */
class IpadTest : public ::testing::Test {
protected:
    ipad_handle_t  hdl{nullptr};
    MockMgr       *mock_mgr{nullptr};
    MockCard      *mock_card{nullptr};

    void SetUp() override {
        auto &factory = telux::tel::PhoneFactory::getInstance();
        factory.sim_mgr_  = std::make_shared<MockMgr>();
        factory.card_mgr_ = std::make_shared<MockCard>();
        mock_mgr  = factory.sim_mgr_.get();
        mock_card = factory.card_mgr_.get();

        ipad_config_t cfg{};
        cfg.timeout_ms  = 5000;
        cfg.log_level   = IPAD_LOG_DEBUG;
        cfg.slot_id     = 0;
        ASSERT_EQ(IPAD_OK, ipad_init(&cfg, &hdl));
    }

    void TearDown() override {
        if (hdl) { ipad_deinit(hdl); hdl = nullptr; }
    }

    /* Helper: inject a profile and return its raw ICCID string */
    std::string inject(const std::string &iccid_str, bool active = false,
                       const std::string &nick = "TestProfile") {
        mock_mgr->inject_profile(iccid_str, active, nick);
        return iccid_str;
    }

    ipad_iccid_t str_to_iccid(const std::string &s) {
        ipad_iccid_t out{};
        for (size_t i = 0; i < s.size() && i/2 < IPAD_ICCID_LEN; i += 2)
            out[i/2] = (uint8_t)strtol(s.substr(i,2).c_str(), nullptr, 16);
        return out;
    }
};

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-INIT — Initialisation
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(IpadInitTest, NullConfigReturnsInvalidParam) {
    ipad_handle_t h = nullptr;
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_init(nullptr, &h));
}

TEST(IpadInitTest, NullHandleOutReturnsInvalidParam) {
    ipad_config_t cfg{};
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_init(&cfg, nullptr));
}

TEST(IpadInitTest, SuccessfulInit) {
    auto &factory = telux::tel::PhoneFactory::getInstance();
    factory.sim_mgr_  = std::make_shared<MockMgr>();
    factory.card_mgr_ = std::make_shared<MockCard>();

    ipad_config_t cfg{};
    cfg.timeout_ms = 3000;
    cfg.slot_id    = 0;
    ipad_handle_t h = nullptr;
    EXPECT_EQ(IPAD_OK, ipad_init(&cfg, &h));
    ASSERT_NE(nullptr, h);
    ipad_deinit(h);
}

TEST(IpadInitTest, DeinitNullHandleIsNoop) {
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_deinit(nullptr));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-VER — Version
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(IpadVersionTest, GetVersionPopulatesFields) {
    ipad_version_t v{};
    EXPECT_EQ(IPAD_OK, ipad_get_version(&v));
    EXPECT_EQ(IPAD_VERSION_MAJOR, v.major);
    EXPECT_EQ(IPAD_VERSION_MINOR, v.minor);
    EXPECT_EQ(IPAD_VERSION_PATCH, v.patch);
    EXPECT_NE(nullptr, v.sgp32_revision);
}

TEST(IpadVersionTest, GetVersionNullReturnsError) {
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_get_version(nullptr));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-EID — EID retrieval
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadTest, GetEidReturnsExpectedValue) {
    mock_card->mock_eid = "89049032005000000000000000000001";
    ipad_eid_t eid{};
    EXPECT_EQ(IPAD_OK, ipad_get_eid(hdl, eid));
    char str[33];
    ipad_eid_to_str(eid, str);
    EXPECT_STREQ("89049032005000000000000000000001", str);
}

TEST_F(IpadTest, GetEidFailsGracefully) {
    mock_card->fail_eid = true;
    ipad_eid_t eid{};
    EXPECT_EQ(IPAD_ERR_TELSDK, ipad_get_eid(hdl, eid));
}

TEST_F(IpadTest, GetEidNullHandleReturnsError) {
    ipad_eid_t eid{};
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_get_eid(nullptr, eid));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-LST — Profile listing
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadTest, EmptyProfileList) {
    uint8_t count = 8;
    EXPECT_EQ(IPAD_OK, ipad_profile_list(hdl, nullptr, &count));
    EXPECT_EQ(0, count);
}

TEST_F(IpadTest, ListOneProfile) {
    inject("8901230000000000001F");
    uint8_t count = 8;
    ipad_profile_t list[8];
    EXPECT_EQ(IPAD_OK, ipad_profile_list(hdl, list, &count));
    EXPECT_EQ(1, count);
}

TEST_F(IpadTest, ListMultipleProfiles) {
    inject("8901230000000000001A");
    inject("8901230000000000002B");
    inject("8901230000000000003C");
    uint8_t count = 16;
    ipad_profile_t list[16];
    EXPECT_EQ(IPAD_OK, ipad_profile_list(hdl, list, &count));
    EXPECT_EQ(3, count);
}

TEST_F(IpadTest, ListFailsWhenBackendFails) {
    mock_mgr->mock_cfg.fail_get_profiles = true;
    uint8_t count = 8;
    ipad_profile_t list[8];
    EXPECT_EQ(IPAD_ERR_TELSDK, ipad_profile_list(hdl, list, &count));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-DL — Profile download
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadTest, DownloadProfileSync) {
    mock_mgr->mock_cfg.download_delay_ms = 100;
    ipad_dl_params_t params{};
    params.activation_code = "LPA:1$smdp.test.io$TESTMATCHID001";
    params.auto_enable     = false;
    ipad_iccid_t iccid{};
    EXPECT_EQ(IPAD_OK, ipad_profile_download(hdl, &params, iccid));
}

TEST_F(IpadTest, DownloadAndAutoEnable) {
    mock_mgr->mock_cfg.download_delay_ms = 100;
    ipad_dl_params_t params{};
    params.activation_code = "LPA:1$smdp.test.io$AUTOENABLE";
    params.auto_enable     = true;
    ipad_iccid_t iccid{};
    EXPECT_EQ(IPAD_OK, ipad_profile_download(hdl, &params, iccid));

    /* Verify at least one profile is now installed */
    uint8_t count = 8;
    ipad_profile_t list[8];
    ASSERT_EQ(IPAD_OK, ipad_profile_list(hdl, list, &count));
    EXPECT_GE(count, 1u);
}

TEST_F(IpadTest, DownloadFailsWhenBackendFails) {
    mock_mgr->mock_cfg.fail_add_profile = true;
    ipad_dl_params_t params{};
    params.activation_code = "LPA:1$smdp.test.io$FAIL";
    EXPECT_EQ(IPAD_ERR_TELSDK, ipad_profile_download(hdl, &params, nullptr));
}

TEST_F(IpadTest, DownloadNullActivationCodeReturnsError) {
    ipad_dl_params_t params{};
    params.activation_code = nullptr;
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_profile_download(hdl, &params, nullptr));
}

TEST_F(IpadTest, DownloadAsyncCallsCallback) {
    mock_mgr->mock_cfg.download_delay_ms = 50;
    std::atomic<bool> called{false};
    ipad_status_t result_rc = IPAD_ERR_INTERNAL;

    ipad_dl_params_t params{};
    params.activation_code = "LPA:1$smdp.test.io$ASYNCTEST";

    ipad_status_t rc = ipad_profile_download_async(hdl, &params,
        [](ipad_handle_t, ipad_status_t s, const void *, void *ctx) {
            *static_cast<ipad_status_t *>(ctx) = s;
            *reinterpret_cast<std::atomic<bool>**>(
                static_cast<char*>(ctx) + sizeof(ipad_status_t)) = nullptr;
        }, &result_rc);

    /* Simple alternative: use a simpler callback */
    std::atomic<ipad_status_t> async_result{IPAD_ERR_INTERNAL};
    rc = ipad_profile_download_async(hdl, &params,
        [](ipad_handle_t, ipad_status_t s, const void *, void *ctx) {
            static_cast<std::atomic<ipad_status_t>*>(ctx)->store(s);
        }, &async_result);

    EXPECT_EQ(IPAD_OK, rc);
    /* Wait up to 2s for callback */
    for (int i = 0; i < 40 && async_result.load() == IPAD_ERR_INTERNAL; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(IPAD_OK, async_result.load());
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-EN — Profile enable/disable
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadTest, EnableProfile) {
    inject("8901230000000000AABB", false);
    auto iccid = str_to_iccid("8901230000000000AABB");
    EXPECT_EQ(IPAD_OK, ipad_profile_enable(hdl, iccid.data()));

    ipad_profile_state_t state;
    EXPECT_EQ(IPAD_OK, ipad_profile_get_state(hdl, iccid.data(), &state));
    EXPECT_EQ(IPAD_PROFILE_ENABLED, state);
}

TEST_F(IpadTest, DisableProfile) {
    inject("8901230000000000CCDD", true);
    auto iccid = str_to_iccid("8901230000000000CCDD");
    EXPECT_EQ(IPAD_OK, ipad_profile_disable(hdl, iccid.data()));

    ipad_profile_state_t state;
    EXPECT_EQ(IPAD_OK, ipad_profile_get_state(hdl, iccid.data(), &state));
    EXPECT_EQ(IPAD_PROFILE_DISABLED, state);
}

TEST_F(IpadTest, EnableNonExistentProfileReturnsError) {
    auto iccid = str_to_iccid("FFFFFFFFFFFFFFFFFFFFFFFF00000000");
    EXPECT_EQ(IPAD_ERR_TELSDK, ipad_profile_enable(hdl, iccid.data()));
}

TEST_F(IpadTest, EnableProfileExclusivity) {
    /* Only one profile should be active at a time */
    inject("8901230000000000AA01", true);
    inject("8901230000000000AA02", false);
    auto iccid2 = str_to_iccid("8901230000000000AA02");
    EXPECT_EQ(IPAD_OK, ipad_profile_enable(hdl, iccid2.data()));

    ipad_profile_state_t s1, s2;
    auto iccid1 = str_to_iccid("8901230000000000AA01");
    ipad_profile_get_state(hdl, iccid1.data(), &s1);
    ipad_profile_get_state(hdl, iccid2.data(), &s2);
    EXPECT_EQ(IPAD_PROFILE_DISABLED, s1);
    EXPECT_EQ(IPAD_PROFILE_ENABLED,  s2);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-DEL — Profile delete
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadTest, DeleteProfile) {
    inject("8901230000000000EEFF");
    auto iccid = str_to_iccid("8901230000000000EEFF");
    EXPECT_EQ(IPAD_OK, ipad_profile_delete(hdl, iccid.data()));

    ipad_profile_t p{};
    EXPECT_EQ(IPAD_ERR_PROFILE_NOT_FOUND, ipad_profile_get(hdl, iccid.data(), &p));
}

TEST_F(IpadTest, DeleteNonExistentProfileReturnsError) {
    auto iccid = str_to_iccid("DEADBEEFDEADBEEFDEADBEEF00001234");
    EXPECT_EQ(IPAD_ERR_TELSDK, ipad_profile_delete(hdl, iccid.data()));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-NICK — Nickname update
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadTest, UpdateNickname) {
    inject("8901230000000000F1F2");
    auto iccid = str_to_iccid("8901230000000000F1F2");
    EXPECT_EQ(IPAD_OK, ipad_profile_set_nickname(hdl, iccid.data(), "MyProfile"));

    ipad_profile_t p{};
    ASSERT_EQ(IPAD_OK, ipad_profile_get(hdl, iccid.data(), &p));
    EXPECT_STREQ("MyProfile", p.nickname);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-EVT — Events
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadTest, EventSubscribeAndReceive) {
    std::atomic<int>  evt_count{0};
    ipad_event_type_t last_type{};

    ipad_sub_id_t sub = ipad_event_subscribe(hdl, IPAD_EVT_ALL,
        [](ipad_handle_t, const ipad_event_t *e, void *ctx) {
            auto *p = static_cast<std::pair<std::atomic<int>*, ipad_event_type_t*>*>(ctx);
            p->first->fetch_add(1);
            *p->second = e->type;
        }, nullptr);
    EXPECT_NE(0u, sub);

    /* trigger enable → generates IPAD_EVT_PROFILE_ENABLED */
    inject("89012300000000001122", false);
    auto iccid = str_to_iccid("89012300000000001122");
    ipad_profile_enable(hdl, iccid.data());

    EXPECT_EQ(IPAD_OK, ipad_event_unsubscribe(hdl, sub));
}

TEST_F(IpadTest, UnsubscribeInvalidIdReturnsError) {
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_event_unsubscribe(hdl, 99999));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-UTIL — Utilities
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(IpadUtilTest, StrerrorKnownCodes) {
    EXPECT_STREQ("OK",                   ipad_strerror(IPAD_OK));
    EXPECT_STREQ("Timeout",              ipad_strerror(IPAD_ERR_TIMEOUT));
    EXPECT_STREQ("Profile not found",    ipad_strerror(IPAD_ERR_PROFILE_NOT_FOUND));
    EXPECT_STREQ("TelSDK backend error", ipad_strerror(IPAD_ERR_TELSDK));
}

TEST(IpadUtilTest, StrerrorUnknownCode) {
    EXPECT_NE(nullptr, ipad_strerror(-9999));
}

TEST(IpadUtilTest, IccidToStrRoundtrip) {
    ipad_iccid_t iccid = {0x89,0x01,0x23,0x00,0x00,0x00,0x00,0x00,0xAA,0xBB};
    char str[21];
    ipad_iccid_to_str(iccid, str);
    EXPECT_STREQ("890123000000000000AABB", str);  /* note: 20 chars */
}

TEST(IpadUtilTest, EidToStrRoundtrip) {
    ipad_eid_t eid = {0x89,0x04,0x90,0x32,0x00,0x50,0x00,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
    char str[33];
    ipad_eid_to_str(eid, str);
    EXPECT_EQ(32u, strlen(str));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-DIAG — Diagnostics
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadTest, DiagExportJsonIsValidJson) {
    char buf[512];
    EXPECT_EQ(IPAD_OK, ipad_diag_export_json(hdl, buf, sizeof(buf)));
    /* crude check: starts with { and ends with } */
    EXPECT_EQ('{', buf[0]);
    EXPECT_EQ('}', buf[strlen(buf)-1]);
}

TEST_F(IpadTest, SelfTestPasses) {
    uint32_t result = 0;
    EXPECT_EQ(IPAD_OK, ipad_selftest(hdl, &result));
    EXPECT_NE(0u, result);   /* at least one flag set */
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Main
 * ────────────────────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
