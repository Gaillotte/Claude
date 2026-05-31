/**
 * @file ipad_telsdk_backend.h
 * @brief Internal: TelSDK (telux::tel) backend declarations for ipad library.
 *
 * This header is NOT part of the public API. It wraps the Qualcomm Telematics
 * SDK C++11 interfaces used by the SA525 module:
 *
 *   telux::tel::PhoneFactory
 *   telux::tel::ISimProfileManager
 *   telux::tel::ISimProfileListener
 *   telux::tel::SimProfile
 *   telux::tel::ICardManager
 *
 * TelSDK headers are expected at: $(TELSDK_ROOT)/include/
 */

#pragma once

#include "ipad.h"

/* ── TelSDK headers (provided by Qualcomm SA525 BSP) ─────────────────────── */
#ifdef IPAD_MOCK_TELSDK
#  include "mock_telsdk.h"
#else
#  include <telux/tel/PhoneFactory.hpp>
#  include <telux/tel/SimProfileManager.hpp>
#  include <telux/tel/CardManager.hpp>
#  include <telux/common/Status.hpp>
#endif

#include <mutex>
#include <condition_variable>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <queue>
#include <map>

namespace ipad_internal {

/* ──────────────────────────────────────────────────────────────────────────────
 * TelSDK status → ipad_status_t mapping
 * ────────────────────────────────────────────────────────────────────────── */
ipad_status_t telsdk_status_to_ipad(telux::common::Status ts);

/* ──────────────────────────────────────────────────────────────────────────────
 * Profile listener — bridges TelSDK callbacks into ipad events
 * ────────────────────────────────────────────────────────────────────────── */
class IpadProfileListener : public telux::tel::ISimProfileListener {
public:
    explicit IpadProfileListener(struct ipad_ctx_s *ctx) : ctx_(ctx) {}

    /* ISimProfileListener overrides */
    void onDownloadStatus(telux::tel::DownloadStatus status,
                          int                        percentage,
                          int                        slotId) override;

    void onUserDisplayInfo(int  slotId,
                           bool userConsentRequired,
                           bool policyRulesRequired) override;

    void serviceStatus(telux::common::ServiceStatus serviceStatus) override;

private:
    struct ipad_ctx_s *ctx_;
};

/* ──────────────────────────────────────────────────────────────────────────────
 * Subscription entry
 * ────────────────────────────────────────────────────────────────────────── */
struct Subscription {
    ipad_sub_id_t   id;
    uint32_t        mask;
    ipad_event_cb_t cb;
    void           *user_ctx;
};

} // namespace ipad_internal

/* ──────────────────────────────────────────────────────────────────────────────
 * Main library context  (global namespace — matches ipad.h forward declaration)
 * ────────────────────────────────────────────────────────────────────────── */
struct ipad_ctx_s {
    /* Configuration */
    ipad_config_t cfg;

    /* TelSDK handles */
    std::shared_ptr<telux::tel::ISimProfileManager>       sim_mgr;
    std::shared_ptr<telux::tel::ICardManager>             card_mgr;
    std::shared_ptr<ipad_internal::IpadProfileListener>   listener;

    /* Event queue */
    std::mutex               evt_mutex;
    std::condition_variable  evt_cv;
    std::queue<ipad_event_t> evt_queue;

    /* Subscriptions */
    std::mutex                              sub_mutex;
    std::vector<ipad_internal::Subscription> subscriptions;
    std::atomic<ipad_sub_id_t>              next_sub_id{1};

    /* Async operation tracking */
    std::mutex                           op_mutex;
    std::condition_variable              op_cv;
    std::atomic<bool>                    op_pending{false};
    ipad_status_t                        op_result{IPAD_OK};
    ipad_iccid_t                         op_iccid{};

    /* Log handler */
    std::mutex    log_mutex;
    ipad_log_cb_t log_cb{nullptr};
    void         *log_ctx{nullptr};

    /* State */
    std::atomic<bool> initialized{false};

    /* Internal helpers */
    void push_event(const ipad_event_t &evt);
    void dispatch_events();
    void log(ipad_loglevel_t level, const char *module, const char *fmt, ...);
};
