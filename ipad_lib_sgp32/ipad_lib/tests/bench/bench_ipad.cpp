/**
 * @file bench_ipad.cpp
 * @brief Micro-benchmark suite for the IPAd library.
 *
 * Measures latency (µs) and throughput for every public API call using the
 * mock backend. Results are written to stdout as JSON so gen_kpi_report.py
 * can parse and embed them in the PDF KPI report.
 *
 * Build target: added automatically when BUILD_TESTS=ON.
 */

#define IPAD_MOCK_TELSDK 1

#include <gtest/gtest.h>
#include <chrono>
#include <numeric>
#include <vector>
#include <cstdio>
#include <cstring>
#include <algorithm>

#include "ipad/ipad.h"
#include "mocks/mock_telsdk.h"

using Clock = std::chrono::steady_clock;
using us    = std::chrono::microseconds;

/* ── helpers ─────────────────────────────────────────────────────────────── */
static double median_us(std::vector<double> &v) {
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    return (n % 2) ? v[n/2] : (v[n/2-1] + v[n/2]) / 2.0;
}
static double mean_us(const std::vector<double> &v) {
    return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
}
static double p99_us(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    return v[std::min((size_t)(v.size() * 0.99), v.size() - 1)];
}

struct BenchResult {
    const char *name;
    double      mean_us;
    double      median_us;
    double      p99_us;
    double      min_us;
    double      max_us;
    int         iterations;
};

static std::vector<BenchResult> g_results;

template<typename Fn>
static BenchResult bench(const char *name, int iters, Fn &&fn) {
    /* Warm-up */
    for (int i = 0; i < 3; ++i) fn();

    std::vector<double> samples;
    samples.reserve(iters);
    for (int i = 0; i < iters; ++i) {
        auto t0 = Clock::now();
        fn();
        auto t1 = Clock::now();
        samples.push_back(
            (double)std::chrono::duration_cast<us>(t1 - t0).count());
    }
    BenchResult r;
    r.name       = name;
    r.mean_us    = mean_us(samples);
    r.median_us  = median_us(samples);
    r.p99_us     = p99_us(samples);
    r.min_us     = *std::min_element(samples.begin(), samples.end());
    r.max_us     = *std::max_element(samples.begin(), samples.end());
    r.iterations = iters;
    g_results.push_back(r);
    return r;
}

/* ── fixture ─────────────────────────────────────────────────────────────── */
class BenchSuite : public ::testing::Test {
protected:
    ipad_handle_t hdl{nullptr};

    void SetUp() override {
        auto &f = telux::tel::PhoneFactory::getInstance();
        f.sim_mgr_  = std::make_shared<telux::tel::ISimProfileManager>();
        f.card_mgr_ = std::make_shared<telux::tel::ICardManager>();
        f.sim_mgr_->mock_cfg.download_delay_ms = 1; /* minimal delay for benchmarks */

        ipad_config_t cfg{};
        cfg.timeout_ms = 5000;
        cfg.log_level  = IPAD_LOG_NONE;
        ASSERT_EQ(IPAD_OK, ipad_init(&cfg, &hdl));
    }

    void TearDown() override {
        if (hdl) { ipad_deinit(hdl); hdl = nullptr; }
    }
};

/* ════════════════════════════════════════════════════════════════════════════
 * BM-INIT — library init / deinit cycle
 * ════════════════════════════════════════════════════════════════════════════ */
TEST(BenchInit, InitDeinitCycle) {
    auto &f = telux::tel::PhoneFactory::getInstance();
    f.sim_mgr_  = std::make_shared<telux::tel::ISimProfileManager>();
    f.card_mgr_ = std::make_shared<telux::tel::ICardManager>();

    bench("ipad_init + ipad_deinit", 50, [&]{
        ipad_config_t cfg{};
        cfg.timeout_ms = 2000;
        cfg.log_level  = IPAD_LOG_NONE;
        ipad_handle_t h;
        ipad_init(&cfg, &h);
        ipad_deinit(h);
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 * BM-EID — get EID / eUICC info
 * ════════════════════════════════════════════════════════════════════════════ */
TEST_F(BenchSuite, GetEid) {
    ipad_eid_t eid;
    bench("ipad_get_eid", 1000, [&]{ ipad_get_eid(hdl, eid); });
}

TEST_F(BenchSuite, GetEuiccInfo) {
    ipad_euicc_info_t info;
    bench("ipad_get_euicc_info", 1000, [&]{ ipad_get_euicc_info(hdl, &info); });
}

/* ════════════════════════════════════════════════════════════════════════════
 * BM-PROFILE-LIST — list profiles (0, 1, 8 profiles)
 * ════════════════════════════════════════════════════════════════════════════ */
TEST_F(BenchSuite, ProfileListEmpty) {
    ipad_profile_t buf[16];
    uint8_t count;
    bench("ipad_profile_list (0 profiles)", 1000, [&]{
        count = 16;
        ipad_profile_list(hdl, buf, &count);
    });
}

TEST_F(BenchSuite, ProfileListEight) {
    /* Install 8 profiles first */
    for (int i = 0; i < 8; ++i) {
        ipad_dl_params_t p{};
        char ac[64]; snprintf(ac, sizeof(ac), "LPA:1$x$BENCH%d", i);
        p.activation_code = ac;
        ipad_profile_download(hdl, &p, nullptr);
    }
    ipad_profile_t buf[16];
    uint8_t count;
    bench("ipad_profile_list (8 profiles)", 1000, [&]{
        count = 16;
        ipad_profile_list(hdl, buf, &count);
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 * BM-PROFILE-DOWNLOAD — synchronous download
 * ════════════════════════════════════════════════════════════════════════════ */
TEST_F(BenchSuite, ProfileDownload) {
    bench("ipad_profile_download (mock, 1 ms delay)", 20, [&]{
        ipad_dl_params_t p{};
        p.activation_code = "LPA:1$smdp.bench$BENCH";
        ipad_profile_download(hdl, &p, nullptr);
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 * BM-PROFILE-ENABLE/DISABLE — state transitions
 * ════════════════════════════════════════════════════════════════════════════ */
TEST_F(BenchSuite, ProfileEnableDisable) {
    ipad_dl_params_t p{};
    p.activation_code = "LPA:1$x$BENCH_ENABLE";
    ipad_iccid_t iccid{};
    ipad_profile_download(hdl, &p, iccid);

    bench("ipad_profile_enable", 200, [&]{ ipad_profile_enable(hdl, iccid); });
    bench("ipad_profile_disable", 200, [&]{ ipad_profile_disable(hdl, iccid); });
}

/* ════════════════════════════════════════════════════════════════════════════
 * BM-EVENTS — subscribe / unsubscribe, event delivery latency
 * ════════════════════════════════════════════════════════════════════════════ */
static void noop_cb(ipad_handle_t, const ipad_event_t *, void *) {}

TEST_F(BenchSuite, EventSubscribeUnsubscribe) {
    bench("ipad_event_subscribe + unsubscribe", 5000, [&]{
        ipad_sub_id_t sid = ipad_event_subscribe(hdl, IPAD_EVT_ALL, noop_cb, nullptr);
        ipad_event_unsubscribe(hdl, sid);
    });
}

/* Static callback context for latency measurement */
struct LatCtx {
    Clock::time_point t_event;
    bool              got{false};
};
static void latency_cb(ipad_handle_t, const ipad_event_t *, void *ctx) {
    auto *c    = static_cast<LatCtx *>(ctx);
    c->t_event = Clock::now();
    c->got     = true;
}

TEST_F(BenchSuite, EventDeliveryLatency) {
    std::vector<double> latencies;
    latencies.reserve(20);

    for (int i = 0; i < 20; ++i) {
        LatCtx ctx;
        ipad_sub_id_t sid = ipad_event_subscribe(
            hdl, IPAD_EVT_PROFILE_INSTALLED, latency_cb, &ctx);

        ipad_dl_params_t p{};
        char ac[64]; snprintf(ac, sizeof(ac), "LPA:1$x$LAT%d", i);
        p.activation_code = ac;
        auto t_start = Clock::now();
        ipad_profile_download(hdl, &p, nullptr);

        if (ctx.got)
            latencies.push_back(
                (double)std::chrono::duration_cast<us>(ctx.t_event - t_start).count());

        ipad_event_unsubscribe(hdl, sid);
    }

    BenchResult r;
    r.name       = "event delivery latency (download->callback)";
    r.mean_us    = latencies.empty() ? 0 : mean_us(latencies);
    r.median_us  = latencies.empty() ? 0 : median_us(latencies);
    r.p99_us     = latencies.empty() ? 0 : p99_us(latencies);
    r.min_us     = latencies.empty() ? 0 : *std::min_element(latencies.begin(), latencies.end());
    r.max_us     = latencies.empty() ? 0 : *std::max_element(latencies.begin(), latencies.end());
    r.iterations = (int)latencies.size();
    g_results.push_back(r);
    SUCCEED();
}

/* ════════════════════════════════════════════════════════════════════════════
 * BM-DIAG — JSON export
 * ════════════════════════════════════════════════════════════════════════════ */
TEST_F(BenchSuite, DiagExportJson) {
    char buf[4096];
    bench("ipad_diag_export_json", 500, [&]{
        ipad_diag_export_json(hdl, buf, sizeof(buf));
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 * BM-LOG — log handler overhead
 * ════════════════════════════════════════════════════════════════════════════ */
TEST_F(BenchSuite, LogSetHandler) {
    bench("ipad_log_set_handler (install/remove)", 10000, [&]{
        ipad_log_set_handler(hdl,
            [](ipad_loglevel_t, const char *, const char *, void *){},
            nullptr);
        ipad_log_set_handler(hdl, nullptr, nullptr);
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 * Print JSON results at the end of the run
 * ════════════════════════════════════════════════════════════════════════════ */
class JsonPrinter : public ::testing::EmptyTestEventListener {
public:
    void OnTestProgramEnd(const ::testing::UnitTest &) override {
        printf("\n__BENCH_JSON_BEGIN__\n[\n");
        for (size_t i = 0; i < g_results.size(); ++i) {
            const auto &r = g_results[i];
            printf(
                "  {\"name\":\"%s\","
                "\"mean_us\":%.2f,"
                "\"median_us\":%.2f,"
                "\"p99_us\":%.2f,"
                "\"min_us\":%.2f,"
                "\"max_us\":%.2f,"
                "\"iterations\":%d}%s\n",
                r.name, r.mean_us, r.median_us, r.p99_us,
                r.min_us, r.max_us, r.iterations,
                (i + 1 < g_results.size()) ? "," : "");
        }
        printf("]\n__BENCH_JSON_END__\n");
    }
};

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new JsonPrinter);
    return RUN_ALL_TESTS();
}
