/**
 * @file mock_telsdk.h
 * @brief Mock Qualcomm TelSDK interfaces for unit/integration testing.
 *
 * Replaces the real telux:: headers when building with -DIPAD_MOCK_TELSDK=1.
 * Simulates ISimProfileManager, ICardManager and related types.
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <future>
#include <map>
#include <mutex>

/* ──────────────────────────────────────────────────────────────────────────────
 * telux::common stubs
 * ────────────────────────────────────────────────────────────────────────── */
namespace telux { namespace common {

enum class Status   { SUCCESS, FAILED, INVALID_PARAM, NOT_SUPPORTED };
enum class ErrorCode { SUCCESS, FAILED, INVALID_PARAM, NOT_SUPPORTED };
enum class ServiceStatus { SERVICE_AVAILABLE, SERVICE_UNAVAILABLE };

} } // telux::common

/* ──────────────────────────────────────────────────────────────────────────────
 * telux::tel stubs
 * ────────────────────────────────────────────────────────────────────────── */
namespace telux { namespace tel {

enum class DownloadStatus  { DOWNLOADING, DOWNLOADED, ERROR };
enum class ProfileState    { ENABLED, DISABLED };
enum class ProfileClass    { OPERATIONAL, TESTING, PROVISIONING };
enum class ProfileType     { REGULAR };
using SlotId = uint32_t;

/* ── SimProfile ─────────────────────────────────────────────────────────── */
class SimProfile {
public:
    SimProfile(std::string iccid, bool active, std::string nick,
               std::string spn, std::string name, ProfileClass pc)
        : iccid_(iccid), active_(active), nick_(nick),
          spn_(spn), name_(name), class_(pc) {}

    std::string  getIccid()             const { return iccid_; }
    bool         isActive()             const { return active_; }
    std::string  getNickName()          const { return nick_; }
    std::string  getServiceProviderName() const { return spn_; }
    std::string  getName()              const { return name_; }
    ProfileClass getProfileClass()      const { return class_; }

    void setActive(bool a)              { active_ = a; }
    void setNickName(const std::string &n) { nick_ = n; }

private:
    std::string  iccid_, nick_, spn_, name_;
    bool         active_;
    ProfileClass class_;
};

/* ── ISimProfileListener ────────────────────────────────────────────────── */
class ISimProfileListener {
public:
    virtual ~ISimProfileListener() = default;
    virtual void onDownloadStatus(DownloadStatus, int pct, int slotId) = 0;
    virtual void onUserDisplayInfo(int slotId, bool consent, bool policy) = 0;
    virtual void serviceStatus(telux::common::ServiceStatus) = 0;
};

/* ── ISimProfileManager (mock implementation) ────────────────────────────── */
class ISimProfileManager {
public:
    /* ── Mock state ─────────────────────────────────────────────────────── */
    struct MockConfig {
        bool   subsystem_ready      = true;
        bool   fail_add_profile     = false;
        bool   fail_delete_profile  = false;
        bool   fail_set_profile     = false;
        bool   fail_get_profiles    = false;
        bool   require_user_consent = false;
        int    download_delay_ms    = 50;
        std::string forced_eid      = "89049032005000000000000000000001";
    };

    MockConfig mock_cfg;

    bool isSubsystemReady() const { return mock_cfg.subsystem_ready; }

    std::future<void> onSubsystemReady() {
        std::promise<void> p;
        p.set_value();
        return p.get_future();
    }

    void registerListener(std::shared_ptr<ISimProfileListener> l) {
        std::lock_guard<std::mutex> lk(mtx_);
        listener_ = l;
    }
    void deregisterListener(std::shared_ptr<ISimProfileListener>) {
        std::lock_guard<std::mutex> lk(mtx_);
        listener_.reset();
    }

    /* addProfile: simulate async download */
    telux::common::Status addProfile(
            SlotId, const std::string &ac, const std::string &,
            bool auto_enable,
            std::function<void(telux::common::ErrorCode)> cb) {
        if (mock_cfg.fail_add_profile) {
            std::thread([cb]{ cb(telux::common::ErrorCode::FAILED); }).detach();
            return telux::common::Status::SUCCESS;
        }

        /* Simulate user consent if required */
        auto self = this;
        int delay = mock_cfg.download_delay_ms;
        bool consent = mock_cfg.require_user_consent;

        std::thread([this, self, ac, auto_enable, cb, delay, consent] {
            auto listener = self->get_listener();
            if (listener && consent)
                listener->onUserDisplayInfo(0, true, false);

            /* progress ticks */
            if (listener) {
                for (int p : {20, 50, 80}) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(delay/4));
                    listener->onDownloadStatus(DownloadStatus::DOWNLOADING, p, 0);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));

            /* Generate fake ICCID from activation code hash */
            std::string iccid = "8901230000000000";
            iccid += std::to_string(std::hash<std::string>{}(ac) % 10000);
            iccid = iccid.substr(0, 20);

            {
                std::lock_guard<std::mutex> lk(self->mtx_);
                auto p = std::make_shared<SimProfile>(
                    iccid, auto_enable, "Downloaded", "TestSPN", "TestProfile",
                    ProfileClass::OPERATIONAL);
                self->profiles_.push_back(p);
            }
            if (listener)
                listener->onDownloadStatus(DownloadStatus::DOWNLOADED, 100, 0);
            cb(telux::common::ErrorCode::SUCCESS);
        }).detach();

        return telux::common::Status::SUCCESS;
    }

    telux::common::Status getProfiles(SlotId,
            std::function<void(telux::common::ErrorCode,
                std::vector<std::shared_ptr<SimProfile>>)> cb) {
        if (mock_cfg.fail_get_profiles) {
            cb(telux::common::ErrorCode::FAILED, {});
            return telux::common::Status::SUCCESS;
        }
        std::lock_guard<std::mutex> lk(mtx_);
        cb(telux::common::ErrorCode::SUCCESS, profiles_);
        return telux::common::Status::SUCCESS;
    }

    telux::common::Status deleteProfile(SlotId, const std::string &iccid,
            std::function<void(telux::common::ErrorCode)> cb) {
        if (mock_cfg.fail_delete_profile) {
            cb(telux::common::ErrorCode::FAILED);
            return telux::common::Status::SUCCESS;
        }
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = std::remove_if(profiles_.begin(), profiles_.end(),
            [&iccid](const std::shared_ptr<SimProfile> &p){ return p->getIccid() == iccid; });
        if (it == profiles_.end()) { cb(telux::common::ErrorCode::FAILED); return telux::common::Status::SUCCESS; }
        profiles_.erase(it, profiles_.end());
        cb(telux::common::ErrorCode::SUCCESS);
        return telux::common::Status::SUCCESS;
    }

    telux::common::Status setProfile(SlotId, const std::string &iccid,
            ProfileState state,
            std::function<void(telux::common::ErrorCode)> cb) {
        if (mock_cfg.fail_set_profile) {
            cb(telux::common::ErrorCode::FAILED);
            return telux::common::Status::SUCCESS;
        }
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto &p : profiles_) {
            if (state == ProfileState::ENABLED) p->setActive(false);
        }
        for (auto &p : profiles_) {
            if (p->getIccid() == iccid) {
                p->setActive(state == ProfileState::ENABLED);
                cb(telux::common::ErrorCode::SUCCESS);
                return telux::common::Status::SUCCESS;
            }
        }
        cb(telux::common::ErrorCode::FAILED);
        return telux::common::Status::SUCCESS;
    }

    telux::common::Status updateNickName(SlotId, const std::string &iccid,
            const std::string &nick,
            std::function<void(telux::common::ErrorCode)> cb) {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto &p : profiles_) {
            if (p->getIccid() == iccid) { p->setNickName(nick); cb(telux::common::ErrorCode::SUCCESS); return telux::common::Status::SUCCESS; }
        }
        cb(telux::common::ErrorCode::FAILED);
        return telux::common::Status::SUCCESS;
    }

    telux::common::Status provideUserConsent(bool, SlotId,
            std::function<void(telux::common::ErrorCode)> cb) {
        cb(telux::common::ErrorCode::SUCCESS);
        return telux::common::Status::SUCCESS;
    }

    /* ── Test helpers ────────────────────────────────────────────────────── */
    void inject_profile(const std::string &iccid, bool active = false,
                        const std::string &nick = "Test",
                        ProfileClass pc = ProfileClass::OPERATIONAL) {
        std::lock_guard<std::mutex> lk(mtx_);
        profiles_.push_back(std::make_shared<SimProfile>(
            iccid, active, nick, "TestSPN", "TestProfile", pc));
    }

    void clear_profiles() {
        std::lock_guard<std::mutex> lk(mtx_);
        profiles_.clear();
    }

    std::shared_ptr<ISimProfileListener> get_listener() {
        std::lock_guard<std::mutex> lk(mtx_);
        return listener_;
    }

private:
    std::mutex mtx_;
    std::vector<std::shared_ptr<SimProfile>>   profiles_;
    std::shared_ptr<ISimProfileListener>       listener_;
};

/* ── ICardManager (mock) ──────────────────────────────────────────────────── */
class ICardManager {
public:
    std::string mock_eid = "89049032005000000000000000000001";
    bool        fail_eid = false;

    telux::common::Status requestEid(SlotId,
            std::function<void(telux::common::ErrorCode, std::string)> cb) {
        if (fail_eid) { cb(telux::common::ErrorCode::FAILED, ""); return telux::common::Status::SUCCESS; }
        cb(telux::common::ErrorCode::SUCCESS, mock_eid);
        return telux::common::Status::SUCCESS;
    }
};

/* ── PhoneFactory (mock singleton) ─────────────────────────────────────────── */
class PhoneFactory {
public:
    static PhoneFactory &getInstance() {
        static PhoneFactory instance;
        return instance;
    }

    std::shared_ptr<ISimProfileManager> getSimProfileManager(SlotId = 0) {
        return sim_mgr_;
    }
    std::shared_ptr<ICardManager> getCardManager() {
        return card_mgr_;
    }

    /* Access for test setup */
    std::shared_ptr<ISimProfileManager> sim_mgr_ =
        std::make_shared<ISimProfileManager>();
    std::shared_ptr<ICardManager> card_mgr_ =
        std::make_shared<ICardManager>();
};

} } // telux::tel
