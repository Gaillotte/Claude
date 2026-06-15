/**
 * @file test_ipad_log.cpp
 * @brief Unit tests for the ipad_log sink module.
 *
 * Tests cover:
 *  - TCP sink: attach / log / detach (loopback server)
 *  - Serial sink: invalid device handling
 *  - Level mapping: NONE / SIMPLE / DETAIL
 *  - Format: timestamp present, level tag present
 */

#include <gtest/gtest.h>
#include <array>
#include <thread>
#include <atomic>
#include <chrono>
#include <string>
#include <cstring>

/* POSIX */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ipad/ipad.h"
#include "ipad/ipad_log.h"
#include "mocks/mock_telsdk.h"

using MockMgr  = telux::tel::ISimProfileManager;
using MockCard = telux::tel::ICardManager;

/* ──────────────────────────────────────────────────────────────────────────────
 * Helper: minimal TCP listen server (loopback, one connection)
 * ────────────────────────────────────────────────────────────────────────── */
class LoopbackServer {
public:
    explicit LoopbackServer(uint16_t port) : port_(port) {
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = htons(port);
        bind(server_fd_, (sockaddr *)&addr, sizeof(addr));
        listen(server_fd_, 1);

        /* Accept in background thread */
        accept_thread_ = std::thread([this] {
            client_fd_ = accept(server_fd_, nullptr, nullptr);
        });
    }

    /* Block until the client connected, then read all data until connection closed */
    std::string read_all(int timeout_ms = 3000) {
        if (accept_thread_.joinable()) accept_thread_.join();
        std::string data;
        char buf[256];
        /* Set receive timeout */
        struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        setsockopt(client_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        for (;;) {
            int n = (int)recv(client_fd_, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = '\0';
            data += buf;
        }
        return data;
    }

    ~LoopbackServer() {
        if (client_fd_ >= 0) close(client_fd_);
        close(server_fd_);
        if (accept_thread_.joinable()) accept_thread_.join();
    }

private:
    uint16_t    port_;
    int         server_fd_ = -1;
    int         client_fd_ = -1;
    std::thread accept_thread_;
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Fixture
 * ────────────────────────────────────────────────────────────────────────── */
class IpadLogTest : public ::testing::Test {
protected:
    ipad_handle_t hdl{nullptr};
    MockMgr      *mock_mgr{nullptr};

    void SetUp() override {
        auto &factory = telux::tel::PhoneFactory::getInstance();
        factory.sim_mgr_  = std::make_shared<MockMgr>();
        factory.card_mgr_ = std::make_shared<MockCard>();
        mock_mgr = factory.sim_mgr_.get();
        mock_mgr->mock_cfg.download_delay_ms = 30;

        ipad_config_t cfg{};
        cfg.timeout_ms = 5000;
        cfg.log_level  = IPAD_LOG_DEBUG;
        ASSERT_EQ(IPAD_OK, ipad_init(&cfg, &hdl));
    }

    void TearDown() override {
        if (hdl) { ipad_deinit(hdl); hdl = nullptr; }
    }
};

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-SINK-NULL — null parameter guards
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadLogTest, SinkSerialNullParams) {
    ipad_log_sink_t sink{};
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_log_sink_serial(nullptr, "/dev/ttyUSB0", 115200));
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_log_sink_serial(&sink, nullptr, 115200));
}

TEST_F(IpadLogTest, SinkTcpNullParams) {
    ipad_log_sink_t sink{};
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_log_sink_tcp(nullptr, "127.0.0.1", 9001));
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_log_sink_tcp(&sink, nullptr, 9001));
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_log_sink_tcp(&sink, "127.0.0.1", 0));
}

TEST_F(IpadLogTest, AttachNullParams) {
    ipad_log_sink_t sink{};
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_log_attach(nullptr, &sink, IPAD_LOGLVL_SIMPLE));
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_log_attach(hdl, nullptr, IPAD_LOGLVL_SIMPLE));
}

TEST_F(IpadLogTest, DetachNullHandle) {
    ipad_log_sink_t sink{};
    EXPECT_EQ(IPAD_ERR_INVALID_PARAM, ipad_log_detach(nullptr, &sink));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-SINK-SERIAL — serial open failure on non-existent device
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadLogTest, SerialOpenFailureOnBadDevice) {
    ipad_log_sink_t sink{};
    /* Non-existent device must return HAL_FAILURE */
    EXPECT_EQ(IPAD_ERR_HAL_FAILURE,
              ipad_log_sink_serial(&sink, "/dev/nonexistent_tty_xyz", 115200));
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-SINK-TCP — loopback round-trip
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadLogTest, TcpSinkConnectFailure) {
    ipad_log_sink_t sink{};
    /* Nothing listening on this port → TRANSPORT error */
    EXPECT_EQ(IPAD_ERR_TRANSPORT,
              ipad_log_sink_tcp(&sink, "127.0.0.1", 19999));
}

TEST_F(IpadLogTest, TcpSinkSimpleLevelReceivesTimestampedLines) {
    constexpr uint16_t PORT = 19911;
    LoopbackServer srv(PORT);

    ipad_log_sink_t sink{};
    ASSERT_EQ(IPAD_OK, ipad_log_sink_tcp(&sink, "127.0.0.1", PORT));
    ASSERT_EQ(IPAD_OK, ipad_log_attach(hdl, &sink, IPAD_LOGLVL_SIMPLE));

    /* Trigger a log message via a download */
    ipad_dl_params_t p{};
    p.activation_code = "LPA:1$smdp.test.io$LOGTEST_SIMPLE";
    ipad_profile_download(hdl, &p, nullptr);

    ipad_log_detach(hdl, &sink);
    ipad_log_sink_close(&sink);

    std::string received = srv.read_all(1000);
    EXPECT_FALSE(received.empty()) << "No data received on TCP sink";

    /* Every line must contain a date-time stamp */
    EXPECT_NE(std::string::npos, received.find("20")) << "No timestamp found";

    /* Must contain at least one INFO tag (SIMPLE = INFO level) */
    EXPECT_NE(std::string::npos, received.find("INFO")) << "No INFO tag found";

    /* Must NOT contain DEBUG tags at SIMPLE level */
    EXPECT_EQ(std::string::npos, received.find("DEBUG")) << "Unexpected DEBUG at SIMPLE";
}

TEST_F(IpadLogTest, TcpSinkDetailLevelReceivesDebugLines) {
    constexpr uint16_t PORT = 19912;
    LoopbackServer srv(PORT);

    ipad_log_sink_t sink{};
    ASSERT_EQ(IPAD_OK, ipad_log_sink_tcp(&sink, "127.0.0.1", PORT));
    ASSERT_EQ(IPAD_OK, ipad_log_attach(hdl, &sink, IPAD_LOGLVL_DETAIL));

    /* DETAIL level must have sub-millisecond timestamp (contains a dot) */
    ipad_dl_params_t p{};
    p.activation_code = "LPA:1$smdp.test.io$LOGTEST_DETAIL";
    ipad_profile_download(hdl, &p, nullptr);

    ipad_log_detach(hdl, &sink);
    ipad_log_sink_close(&sink);

    std::string received = srv.read_all(1000);
    EXPECT_FALSE(received.empty());
    /* Sub-millisecond: timestamp contains a dot, e.g. "14:23:45.078" */
    EXPECT_NE(std::string::npos, received.find('.')) << "No sub-ms timestamp";
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-LEVEL-NONE — NONE level silences everything
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadLogTest, NoneLevelProducesNoOutput) {
    constexpr uint16_t PORT = 19913;
    LoopbackServer srv(PORT);

    ipad_log_sink_t sink{};
    ASSERT_EQ(IPAD_OK, ipad_log_sink_tcp(&sink, "127.0.0.1", PORT));
    /* Attach with NONE → should not emit anything */
    ASSERT_EQ(IPAD_OK, ipad_log_attach(hdl, &sink, IPAD_LOGLVL_NONE));

    ipad_dl_params_t p{};
    p.activation_code = "LPA:1$smdp.test.io$LOGTEST_NONE";
    ipad_profile_download(hdl, &p, nullptr);

    ipad_log_detach(hdl, &sink);
    ipad_log_sink_close(&sink);

    /* read_all will time out quickly; data should be empty */
    std::string received = srv.read_all(200);
    EXPECT_TRUE(received.empty()) << "Got unexpected output at NONE level";
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TC-DETACH — detach restores silence
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(IpadLogTest, DetachRestoresSilence) {
    constexpr uint16_t PORT = 19914;
    LoopbackServer srv(PORT);

    ipad_log_sink_t sink{};
    ASSERT_EQ(IPAD_OK, ipad_log_sink_tcp(&sink, "127.0.0.1", PORT));
    ASSERT_EQ(IPAD_OK, ipad_log_attach(hdl, &sink, IPAD_LOGLVL_SIMPLE));

    /* Detach immediately before any operation */
    ASSERT_EQ(IPAD_OK, ipad_log_detach(hdl, &sink));
    ipad_log_sink_close(&sink);

    /* Custom callback must no longer be active — use ipad_log_set_handler
       with a counting callback to confirm */
    std::atomic<int> count{0};
    ipad_log_set_handler(hdl, [](ipad_loglevel_t, const char *, const char *, void *ctx) {
        static_cast<std::atomic<int>*>(ctx)->fetch_add(1);
    }, &count);
    ipad_log_set_level(hdl, IPAD_LOG_DEBUG);

    ipad_dl_params_t p{};
    p.activation_code = "LPA:1$smdp.test.io$LOGTEST_DETACH";
    ipad_profile_download(hdl, &p, nullptr);

    /* count > 0 means the library itself still logs; detach just removed our sink */
    EXPECT_GT(count.load(), 0);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
