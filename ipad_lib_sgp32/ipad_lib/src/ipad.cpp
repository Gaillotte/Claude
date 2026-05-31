/**
 * @file ipad.cpp
 * @brief IPAd Abstraction Library — Core implementation
 *
 * Wraps Qualcomm TelSDK telux::tel::ISimProfileManager for SA525.
 */

#include "ipad/ipad_telsdk_backend.h"
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <chrono>
#include <sstream>

using namespace ipad_internal;

/* ──────────────────────────────────────────────────────────────────────────────
 * Helpers
 * ────────────────────────────────────────────────────────────────────────── */

static bool valid_hdl(ipad_handle_t hdl) {
    return hdl != nullptr && hdl->initialized.load();
}

void ipad_ctx_s::log(ipad_loglevel_t level, const char *module,
                      const char *fmt, ...) {
    if (level > cfg.log_level) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lk(log_mutex);
    if (log_cb) {
        log_cb(level, module, buf, log_ctx);
    } else {
        static const char *lvl_str[] = {"NONE","ERROR","WARN","INFO","DEBUG"};
        fprintf(stderr, "[IPAD][%s][%s] %s\n",
                lvl_str[level < 5 ? level : 4], module, buf);
    }
}

void ipad_ctx_s::push_event(const ipad_event_t &evt) {
    {
        std::lock_guard<std::mutex> lk(evt_mutex);
        evt_queue.push(evt);
    }
    evt_cv.notify_one();
    dispatch_events();
}

void ipad_ctx_s::dispatch_events() {
    std::vector<ipad_event_t> pending;
    {
        std::lock_guard<std::mutex> lk(evt_mutex);
        while (!evt_queue.empty()) {
            pending.push_back(evt_queue.front());
            evt_queue.pop();
        }
    }
    for (auto &evt : pending) {
        std::vector<Subscription> subs_copy;
        {
            std::lock_guard<std::mutex> lk(sub_mutex);
            subs_copy = subscriptions;
        }
        for (auto &sub : subs_copy) {
            if (sub.mask & static_cast<uint32_t>(evt.type)) {
                sub.cb(this, &evt, sub.user_ctx);
            }
        }
    }
}

/* ──────────────────────────────────────────────────────────────────────────────
 * TelSDK status mapping
 * ────────────────────────────────────────────────────────────────────────── */
ipad_status_t ipad_internal::telsdk_status_to_ipad(telux::common::Status ts) {
    switch (ts) {
        case telux::common::Status::SUCCESS:        return IPAD_OK;
        case telux::common::Status::FAILED:         return IPAD_ERR_TELSDK;
        case telux::common::Status::INVALID_PARAM:  return IPAD_ERR_INVALID_PARAM;
        case telux::common::Status::NOT_SUPPORTED:  return IPAD_ERR_NOT_SUPPORTED;
        default:                                    return IPAD_ERR_TELSDK;
    }
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Profile Listener callbacks
 * ────────────────────────────────────────────────────────────────────────── */
void IpadProfileListener::onDownloadStatus(
        telux::tel::DownloadStatus status,
        int percentage,
        int /*slotId*/) {

    ipad_event_t evt{};
    if (percentage < 100) {
        evt.type         = IPAD_EVT_DOWNLOAD_PROGRESS;
        evt.progress_pct = static_cast<uint8_t>(percentage);
        snprintf(evt.detail, sizeof(evt.detail), "Download %d%%", percentage);
        evt.status = IPAD_PENDING;
    } else {
        /* Map TelSDK DownloadStatus enum */
        if (status == telux::tel::DownloadStatus::DOWNLOADED) {
            evt.type   = IPAD_EVT_PROFILE_INSTALLED;
            evt.status = IPAD_OK;
            snprintf(evt.detail, sizeof(evt.detail), "Profile installed");
        } else {
            evt.type   = IPAD_EVT_ERROR;
            evt.status = IPAD_ERR_TELSDK;
            snprintf(evt.detail, sizeof(evt.detail),
                     "Download failed, TelSDK status=%d", static_cast<int>(status));
        }
    }
    ctx_->push_event(evt);

    /* Wake up synchronous waiters */
    if (percentage == 100 || status != telux::tel::DownloadStatus::DOWNLOADING) {
        std::lock_guard<std::mutex> lk(ctx_->op_mutex);
        ctx_->op_result  = evt.status;
        ctx_->op_pending = false;
        ctx_->op_cv.notify_all();
    }
}

void IpadProfileListener::onUserDisplayInfo(
        int /*slotId*/, bool userConsentRequired, bool /*policyRulesRequired*/) {
    if (userConsentRequired) {
        ctx_->log(IPAD_LOG_INFO, "listener",
                  "User consent required — auto-providing consent");
        ctx_->sim_mgr->provideUserConsent(true, ctx_->cfg.slot_id,
            [](telux::common::ErrorCode) {});
    }
}

void IpadProfileListener::serviceStatus(telux::common::ServiceStatus ss) {
    ipad_event_t evt{};
    if (ss == telux::common::ServiceStatus::SERVICE_AVAILABLE) {
        evt.type   = IPAD_EVT_EIM_CONNECTED;
        evt.status = IPAD_OK;
        snprintf(evt.detail, sizeof(evt.detail), "TelSDK SimProfileManager available");
    } else {
        evt.type   = IPAD_EVT_EIM_DISCONNECTED;
        evt.status = IPAD_ERR_TELSDK;
        snprintf(evt.detail, sizeof(evt.detail), "TelSDK SimProfileManager unavailable");
    }
    ctx_->push_event(evt);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * Public API implementation
 * ══════════════════════════════════════════════════════════════════════════ */

ipad_status_t ipad_init(const ipad_config_t *cfg, ipad_handle_t *hdl_out) {
    if (!cfg || !hdl_out) return IPAD_ERR_INVALID_PARAM;

    auto *ctx = new (std::nothrow) ipad_ctx_s();
    if (!ctx) return IPAD_ERR_NO_MEMORY;

    ctx->cfg = *cfg;
    ctx->cfg.timeout_ms   = cfg->timeout_ms   ? cfg->timeout_ms   : 30000;
    ctx->cfg.retry_count  = cfg->retry_count  ? cfg->retry_count  : 3;

    /* ── Connect to TelSDK PhoneFactory ──────────────────────────────────── */
    auto &factory = telux::tel::PhoneFactory::getInstance();

    /* Wait for card manager */
    ctx->card_mgr = factory.getCardManager();
    if (!ctx->card_mgr) {
        delete ctx;
        return IPAD_ERR_TELSDK;
    }

    /* Wait for sim profile manager */
    ctx->sim_mgr = factory.getSimProfileManager(cfg->slot_id);
    if (!ctx->sim_mgr) {
        delete ctx;
        return IPAD_ERR_TELSDK;
    }

    /* Wait for subsystem ready with timeout */
    auto timeout = std::chrono::milliseconds(ctx->cfg.timeout_ms);
    auto ready   = ctx->sim_mgr->onSubsystemReady().wait_for(timeout);
    if (ready == std::future_status::timeout) {
        delete ctx;
        return IPAD_ERR_TIMEOUT;
    }

    /* Register listener */
    ctx->listener = std::make_shared<IpadProfileListener>(ctx);
    ctx->sim_mgr->registerListener(ctx->listener);

    ctx->initialized = true;
    *hdl_out = ctx;
    ctx->log(IPAD_LOG_INFO, "init", "IPAd initialized (TelSDK slot %u)", cfg->slot_id);
    return IPAD_OK;
}

ipad_status_t ipad_deinit(ipad_handle_t hdl) {
    if (!hdl) return IPAD_ERR_INVALID_PARAM;
    hdl->initialized = false;
    if (hdl->sim_mgr && hdl->listener) {
        hdl->sim_mgr->deregisterListener(hdl->listener);
    }
    delete hdl;
    return IPAD_OK;
}

ipad_status_t ipad_configure(ipad_handle_t hdl, const ipad_config_t *cfg) {
    if (!hdl || !cfg) return IPAD_ERR_INVALID_PARAM;
    std::lock_guard<std::mutex> lk(hdl->log_mutex);
    hdl->cfg.log_level   = cfg->log_level;
    hdl->cfg.retry_count = cfg->retry_count;
    hdl->cfg.timeout_ms  = cfg->timeout_ms;
    return IPAD_OK;
}

ipad_status_t ipad_get_version(ipad_version_t *ver_out) {
    if (!ver_out) return IPAD_ERR_INVALID_PARAM;
    ver_out->major          = IPAD_VERSION_MAJOR;
    ver_out->minor          = IPAD_VERSION_MINOR;
    ver_out->patch          = IPAD_VERSION_PATCH;
    ver_out->sgp32_revision = "SGP.32 v1.0";
    ver_out->telsdk_version = TELSDK_VERSION_STRING; /* injected by build */
    return IPAD_OK;
}

ipad_status_t ipad_selftest(ipad_handle_t hdl, uint32_t *result) {
    if (!valid_hdl(hdl) || !result) return IPAD_ERR_INVALID_PARAM;
    *result = 0;
    if (hdl->sim_mgr && hdl->sim_mgr->isSubsystemReady()) *result |= (1u << 0);
    if (hdl->card_mgr)                                    *result |= (1u << 1);
    return IPAD_OK;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * eUICC identity
 * ────────────────────────────────────────────────────────────────────────── */
ipad_status_t ipad_get_eid(ipad_handle_t hdl, ipad_eid_t eid_out) {
    if (!valid_hdl(hdl) || !eid_out) return IPAD_ERR_INVALID_PARAM;

    ipad_status_t rc = IPAD_ERR_TELSDK;
    std::string   eid_str;
    std::mutex    mtx;
    std::condition_variable cv;
    bool done = false;

    auto status = hdl->card_mgr->requestEid(hdl->cfg.slot_id,
        [&](telux::common::ErrorCode ec, std::string eid) {
            std::lock_guard<std::mutex> lk(mtx);
            if (ec == telux::common::ErrorCode::SUCCESS) {
                eid_str = eid;
                rc = IPAD_OK;
            }
            done = true;
            cv.notify_one();
        });
    if (status != telux::common::Status::SUCCESS) return telsdk_status_to_ipad(status);

    std::unique_lock<std::mutex> lk(mtx);
    cv.wait_for(lk, std::chrono::milliseconds(hdl->cfg.timeout_ms),
                [&]{ return done; });
    if (!done) return IPAD_ERR_TIMEOUT;
    if (rc != IPAD_OK) return rc;

    /* Decode hex string into binary */
    memset(eid_out, 0, IPAD_EID_LEN);
    for (size_t i = 0; i < eid_str.size() && i/2 < IPAD_EID_LEN; i += 2) {
        eid_out[i/2] = (uint8_t)strtol(eid_str.substr(i, 2).c_str(), nullptr, 16);
    }
    return IPAD_OK;
}

ipad_status_t ipad_get_euicc_info(ipad_handle_t hdl, ipad_euicc_info_t *info_out) {
    if (!valid_hdl(hdl) || !info_out) return IPAD_ERR_INVALID_PARAM;
    memset(info_out, 0, sizeof(*info_out));

    ipad_status_t rc = ipad_get_eid(hdl, info_out->eid);
    if (rc != IPAD_OK) return rc;
    ipad_eid_to_str(info_out->eid, info_out->eid_str);

    /* TelSDK does not expose OS version via SimProfileManager;
     * fill what we can and leave remainder at zero. */
    snprintf(info_out->os_version, sizeof(info_out->os_version),
             "SA525-TelSDK");
    info_out->profile_capacity = 8;   /* SA525 typical value */
    return IPAD_OK;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Profile management helpers
 * ────────────────────────────────────────────────────────────────────────── */
static ipad_profile_state_t telsdk_profile_state(
        const telux::tel::SimProfile &sp) {
    return sp.isActive() ? IPAD_PROFILE_ENABLED : IPAD_PROFILE_DISABLED;
}

static void fill_profile(ipad_profile_t &dst, const telux::tel::SimProfile &src) {
    memset(&dst, 0, sizeof(dst));
    /* ICCID: TelSDK returns ASCII string */
    std::string iccid_str = src.getIccid();
    for (size_t i = 0; i < iccid_str.size() && i/2 < IPAD_ICCID_LEN; i += 2)
        dst.iccid[i/2] = (uint8_t)strtol(iccid_str.substr(i,2).c_str(), nullptr, 16);

    dst.state = telsdk_profile_state(src);
    strncpy(dst.nickname,      src.getNickName().c_str(),   IPAD_STR_MAX - 1);
    strncpy(dst.provider,      src.getServiceProviderName().c_str(), IPAD_STR_MAX - 1);
    strncpy(dst.profile_name,  src.getName().c_str(),       IPAD_STR_MAX - 1);
    dst.is_test_profile =
        (src.getProfileClass() == telux::tel::ProfileClass::TESTING);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Profile listing
 * ────────────────────────────────────────────────────────────────────────── */
ipad_status_t ipad_profile_list(ipad_handle_t  hdl,
                                 ipad_profile_t *list_out,
                                 uint8_t        *count_inout) {
    if (!valid_hdl(hdl) || !count_inout) return IPAD_ERR_INVALID_PARAM;

    std::vector<std::shared_ptr<telux::tel::SimProfile>> profiles;
    ipad_status_t rc = IPAD_ERR_TELSDK;
    std::mutex mtx; std::condition_variable cv; bool done = false;

    auto st = hdl->sim_mgr->getProfiles(hdl->cfg.slot_id,
        [&](telux::common::ErrorCode ec,
            std::vector<std::shared_ptr<telux::tel::SimProfile>> profs) {
            std::lock_guard<std::mutex> lk(mtx);
            if (ec == telux::common::ErrorCode::SUCCESS) {
                profiles = std::move(profs);
                rc = IPAD_OK;
            }
            done = true; cv.notify_one();
        });
    if (st != telux::common::Status::SUCCESS) return telsdk_status_to_ipad(st);

    std::unique_lock<std::mutex> lk(mtx);
    cv.wait_for(lk, std::chrono::milliseconds(hdl->cfg.timeout_ms),
                [&]{ return done; });
    if (!done) return IPAD_ERR_TIMEOUT;
    if (rc != IPAD_OK) return rc;

    uint8_t actual = static_cast<uint8_t>(profiles.size());
    if (!list_out) { *count_inout = actual; return IPAD_OK; }

    uint8_t cap = *count_inout;
    *count_inout = std::min(actual, cap);
    for (uint8_t i = 0; i < *count_inout; ++i)
        fill_profile(list_out[i], *profiles[i]);
    return IPAD_OK;
}

ipad_status_t ipad_profile_get(ipad_handle_t      hdl,
                                const ipad_iccid_t iccid,
                                ipad_profile_t    *profile_out) {
    if (!valid_hdl(hdl) || !iccid || !profile_out) return IPAD_ERR_INVALID_PARAM;
    char iccid_hex[21] = {};
    ipad_iccid_to_str(iccid, iccid_hex);

    uint8_t count = 16;
    ipad_profile_t list[16];
    ipad_status_t rc = ipad_profile_list(hdl, list, &count);
    if (rc != IPAD_OK) return rc;

    for (uint8_t i = 0; i < count; ++i) {
        char cur[21] = {};
        ipad_iccid_to_str(list[i].iccid, cur);
        if (strcmp(cur, iccid_hex) == 0) {
            *profile_out = list[i];
            return IPAD_OK;
        }
    }
    return IPAD_ERR_PROFILE_NOT_FOUND;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Profile download (synchronous)
 * ────────────────────────────────────────────────────────────────────────── */
ipad_status_t ipad_profile_download(ipad_handle_t          hdl,
                                     const ipad_dl_params_t *params,
                                     ipad_iccid_t            iccid_out) {
    if (!valid_hdl(hdl) || !params || !params->activation_code)
        return IPAD_ERR_INVALID_PARAM;

    hdl->log(IPAD_LOG_INFO, "download", "Starting profile download: %s",
             params->activation_code);

    /* Mark operation pending */
    {
        std::lock_guard<std::mutex> lk(hdl->op_mutex);
        hdl->op_pending = true;
        hdl->op_result  = IPAD_ERR_TIMEOUT;
    }

    auto st = hdl->sim_mgr->addProfile(
        hdl->cfg.slot_id,
        params->activation_code,
        params->confirmation_code ? params->confirmation_code : "",
        params->auto_enable,
        [hdl](telux::common::ErrorCode ec) {
            std::lock_guard<std::mutex> lk(hdl->op_mutex);
            hdl->op_result  = (ec == telux::common::ErrorCode::SUCCESS)
                               ? IPAD_OK : IPAD_ERR_TELSDK;
            hdl->op_pending = false;
            hdl->op_cv.notify_all();
        });

    if (st != telux::common::Status::SUCCESS) {
        hdl->op_pending = false;
        return telsdk_status_to_ipad(st);
    }

    /* Wait for completion */
    auto timeout_ms = params->timeout_ms ? params->timeout_ms : hdl->cfg.timeout_ms;
    std::unique_lock<std::mutex> lk(hdl->op_mutex);
    hdl->op_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                         [hdl]{ return !hdl->op_pending.load(); });

    if (hdl->op_pending) return IPAD_ERR_TIMEOUT;
    if (hdl->op_result != IPAD_OK) return hdl->op_result;

    /* Copy out ICCID if requested */
    if (iccid_out) memcpy(iccid_out, hdl->op_iccid, IPAD_ICCID_LEN);
    hdl->log(IPAD_LOG_INFO, "download", "Profile download completed");
    return IPAD_OK;
}

ipad_status_t ipad_profile_download_async(ipad_handle_t           hdl,
                                           const ipad_dl_params_t *params,
                                           ipad_callback_t         cb,
                                           void                   *cb_ctx) {
    if (!valid_hdl(hdl) || !params) return IPAD_ERR_INVALID_PARAM;

    auto st = hdl->sim_mgr->addProfile(
        hdl->cfg.slot_id,
        params->activation_code,
        params->confirmation_code ? params->confirmation_code : "",
        params->auto_enable,
        [hdl, cb, cb_ctx](telux::common::ErrorCode ec) {
            ipad_status_t rc = (ec == telux::common::ErrorCode::SUCCESS)
                               ? IPAD_OK : IPAD_ERR_TELSDK;
            if (cb) cb(hdl, rc, nullptr, cb_ctx);
        });

    return telsdk_status_to_ipad(st);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Profile enable / disable / delete
 * ────────────────────────────────────────────────────────────────────────── */
static ipad_status_t profile_set_state(ipad_handle_t hdl,
                                        const ipad_iccid_t iccid,
                                        bool enable) {
    if (!valid_hdl(hdl)) return IPAD_ERR_INVALID_PARAM;
    char iccid_str[21]; ipad_iccid_to_str(iccid, iccid_str);

    ipad_status_t rc = IPAD_ERR_TELSDK;
    std::mutex mtx; std::condition_variable cv; bool done = false;

    telux::tel::ProfileState state = enable
        ? telux::tel::ProfileState::ENABLED
        : telux::tel::ProfileState::DISABLED;

    auto st = hdl->sim_mgr->setProfile(
        hdl->cfg.slot_id, iccid_str, state,
        [&](telux::common::ErrorCode ec) {
            std::lock_guard<std::mutex> lk(mtx);
            rc = (ec == telux::common::ErrorCode::SUCCESS) ? IPAD_OK : IPAD_ERR_TELSDK;
            done = true; cv.notify_one();
        });
    if (st != telux::common::Status::SUCCESS) return telsdk_status_to_ipad(st);

    std::unique_lock<std::mutex> lk(mtx);
    cv.wait_for(lk, std::chrono::milliseconds(hdl->cfg.timeout_ms), [&]{ return done; });
    if (!done) return IPAD_ERR_TIMEOUT;

    if (rc == IPAD_OK) {
        ipad_event_t evt{};
        evt.type   = enable ? IPAD_EVT_PROFILE_ENABLED : IPAD_EVT_PROFILE_DISABLED;
        evt.status = IPAD_OK;
        memcpy(evt.iccid, iccid, IPAD_ICCID_LEN);
        hdl->push_event(evt);
    }
    return rc;
}

ipad_status_t ipad_profile_enable(ipad_handle_t hdl, const ipad_iccid_t iccid) {
    return profile_set_state(hdl, iccid, true);
}

ipad_status_t ipad_profile_disable(ipad_handle_t hdl, const ipad_iccid_t iccid) {
    return profile_set_state(hdl, iccid, false);
}

ipad_status_t ipad_profile_delete(ipad_handle_t hdl, const ipad_iccid_t iccid) {
    if (!valid_hdl(hdl)) return IPAD_ERR_INVALID_PARAM;
    char iccid_str[21]; ipad_iccid_to_str(iccid, iccid_str);

    ipad_status_t rc = IPAD_ERR_TELSDK;
    std::mutex mtx; std::condition_variable cv; bool done = false;

    auto st = hdl->sim_mgr->deleteProfile(
        hdl->cfg.slot_id, iccid_str,
        [&](telux::common::ErrorCode ec) {
            std::lock_guard<std::mutex> lk(mtx);
            rc = (ec == telux::common::ErrorCode::SUCCESS) ? IPAD_OK : IPAD_ERR_TELSDK;
            done = true; cv.notify_one();
        });
    if (st != telux::common::Status::SUCCESS) return telsdk_status_to_ipad(st);

    std::unique_lock<std::mutex> lk(mtx);
    cv.wait_for(lk, std::chrono::milliseconds(hdl->cfg.timeout_ms), [&]{ return done; });
    if (!done) return IPAD_ERR_TIMEOUT;

    if (rc == IPAD_OK) {
        ipad_event_t evt{};
        evt.type = IPAD_EVT_PROFILE_DELETED;
        evt.status = IPAD_OK;
        memcpy(evt.iccid, iccid, IPAD_ICCID_LEN);
        hdl->push_event(evt);
    }
    return rc;
}

ipad_status_t ipad_profile_set_nickname(ipad_handle_t      hdl,
                                         const ipad_iccid_t iccid,
                                         const char        *nickname) {
    if (!valid_hdl(hdl) || !nickname) return IPAD_ERR_INVALID_PARAM;
    char iccid_str[21]; ipad_iccid_to_str(iccid, iccid_str);

    ipad_status_t rc = IPAD_ERR_TELSDK;
    std::mutex mtx; std::condition_variable cv; bool done = false;

    auto st = hdl->sim_mgr->updateNickName(
        hdl->cfg.slot_id, iccid_str, nickname,
        [&](telux::common::ErrorCode ec) {
            std::lock_guard<std::mutex> lk(mtx);
            rc = (ec == telux::common::ErrorCode::SUCCESS) ? IPAD_OK : IPAD_ERR_TELSDK;
            done = true; cv.notify_one();
        });
    if (st != telux::common::Status::SUCCESS) return telsdk_status_to_ipad(st);

    std::unique_lock<std::mutex> lk(mtx);
    cv.wait_for(lk, std::chrono::milliseconds(hdl->cfg.timeout_ms), [&]{ return done; });
    return done ? rc : IPAD_ERR_TIMEOUT;
}

ipad_status_t ipad_profile_get_state(ipad_handle_t        hdl,
                                      const ipad_iccid_t   iccid,
                                      ipad_profile_state_t *state_out) {
    ipad_profile_t p{};
    ipad_status_t rc = ipad_profile_get(hdl, iccid, &p);
    if (rc == IPAD_OK && state_out) *state_out = p.state;
    return rc;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Events
 * ────────────────────────────────────────────────────────────────────────── */
ipad_sub_id_t ipad_event_subscribe(ipad_handle_t   hdl,
                                    uint32_t         mask,
                                    ipad_event_cb_t  cb,
                                    void            *user_ctx) {
    if (!hdl || !cb) return 0;
    Subscription sub;
    sub.id       = hdl->next_sub_id.fetch_add(1);
    sub.mask     = mask;
    sub.cb       = cb;
    sub.user_ctx = user_ctx;
    std::lock_guard<std::mutex> lk(hdl->sub_mutex);
    hdl->subscriptions.push_back(sub);
    return sub.id;
}

ipad_status_t ipad_event_unsubscribe(ipad_handle_t hdl, ipad_sub_id_t sub_id) {
    if (!hdl) return IPAD_ERR_INVALID_PARAM;
    std::lock_guard<std::mutex> lk(hdl->sub_mutex);
    auto &subs = hdl->subscriptions;
    auto it = std::remove_if(subs.begin(), subs.end(),
                              [sub_id](const Subscription &s){ return s.id == sub_id; });
    if (it == subs.end()) return IPAD_ERR_INVALID_PARAM;
    subs.erase(it, subs.end());
    return IPAD_OK;
}

ipad_status_t ipad_event_pump(ipad_handle_t hdl, uint32_t timeout_ms) {
    if (!hdl) return IPAD_ERR_INVALID_PARAM;
    std::unique_lock<std::mutex> lk(hdl->evt_mutex);
    hdl->evt_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                          [hdl]{ return !hdl->evt_queue.empty(); });
    lk.unlock();
    hdl->dispatch_events();
    return IPAD_OK;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Diagnostics
 * ────────────────────────────────────────────────────────────────────────── */
ipad_status_t ipad_log_set_handler(ipad_handle_t hdl,
                                    ipad_log_cb_t  cb,
                                    void          *user_ctx) {
    if (!hdl) return IPAD_ERR_INVALID_PARAM;
    std::lock_guard<std::mutex> lk(hdl->log_mutex);
    hdl->log_cb  = cb;
    hdl->log_ctx = user_ctx;
    return IPAD_OK;
}

ipad_status_t ipad_log_set_level(ipad_handle_t hdl, ipad_loglevel_t level) {
    if (!hdl) return IPAD_ERR_INVALID_PARAM;
    hdl->cfg.log_level = level;
    return IPAD_OK;
}

ipad_status_t ipad_diag_export_json(ipad_handle_t hdl,
                                     char         *buf,
                                     size_t        buf_len) {
    if (!hdl || !buf || buf_len < 2) return IPAD_ERR_INVALID_PARAM;
    ipad_euicc_info_t info{};
    ipad_get_euicc_info(hdl, &info);
    uint8_t count = 16;
    ipad_profile_t profiles[16];
    ipad_profile_list(hdl, profiles, &count);

    std::ostringstream os;
    os << "{\"eid\":\"" << info.eid_str << "\","
       << "\"profile_count\":" << (int)count << ","
       << "\"telsdk_ready\":"
       << (hdl->sim_mgr && hdl->sim_mgr->isSubsystemReady() ? "true" : "false")
       << "}";
    strncpy(buf, os.str().c_str(), buf_len - 1);
    buf[buf_len - 1] = '\0';
    return IPAD_OK;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Utilities
 * ────────────────────────────────────────────────────────────────────────── */
const char *ipad_strerror(ipad_status_t s) {
    switch (s) {
        case IPAD_OK:                    return "OK";
        case IPAD_PENDING:               return "Pending";
        case IPAD_ERR_INVALID_PARAM:     return "Invalid parameter";
        case IPAD_ERR_NOT_INITIALIZED:   return "Not initialized";
        case IPAD_ERR_HAL_FAILURE:       return "HAL failure";
        case IPAD_ERR_TRANSPORT:         return "Transport error";
        case IPAD_ERR_TLS_HANDSHAKE:     return "TLS handshake failed";
        case IPAD_ERR_EIM_REJECTED:      return "eIM rejected request";
        case IPAD_ERR_PROFILE_NOT_FOUND: return "Profile not found";
        case IPAD_ERR_PROFILE_ACTIVE:    return "Profile is active";
        case IPAD_ERR_NO_MEMORY:         return "Out of memory";
        case IPAD_ERR_CRYPTO:            return "Cryptographic error";
        case IPAD_ERR_TIMEOUT:           return "Timeout";
        case IPAD_ERR_BUSY:              return "Resource busy";
        case IPAD_ERR_NOT_SUPPORTED:     return "Not supported";
        case IPAD_ERR_TELSDK:            return "TelSDK backend error";
        case IPAD_ERR_INTERNAL:          return "Internal error";
        default:                         return "Unknown error";
    }
}

void ipad_iccid_to_str(const ipad_iccid_t iccid, char *str_out) {
    for (int i = 0; i < IPAD_ICCID_LEN; ++i)
        sprintf(str_out + i*2, "%02X", iccid[i]);
    str_out[IPAD_ICCID_LEN * 2] = '\0';
}

void ipad_eid_to_str(const ipad_eid_t eid, char *str_out) {
    for (int i = 0; i < IPAD_EID_LEN; ++i)
        sprintf(str_out + i*2, "%02X", eid[i]);
    str_out[IPAD_EID_LEN * 2] = '\0';
}
