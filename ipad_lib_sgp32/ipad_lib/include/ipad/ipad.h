/**
 * @file ipad.h
 * @brief IPAd Abstraction Library — Public API
 *
 * Abstraction layer over Qualcomm Telematics SDK (TelSDK) for the SA525 module.
 * Implements GSMA SGP.32 IoT Profile Assistant Device (IPAd) semantics.
 *
 * TelSDK backend: telux::tel::ISimProfileManager / ICardManager
 *
 * @version 1.0.0
 *
 * Requirements traceability
 * ─────────────────────────
 * Each public symbol is tagged [REQ-xxx] referencing the requirement it
 * fulfils.  The full Requirements Traceability Matrix is in:
 *   doc/IPAd_Requirements_Traceability_Matrix.docx
 *
 * Requirement IDs derive from GSMA SGP.32 v1.0:
 *   REQ-001..005  Lifecycle & initialisation      SGP.32 §3.1
 *   REQ-010..011  eUICC identity                  SGP.32 §3.2
 *   REQ-020..024  Profile download                SGP.32 §3.3
 *   REQ-030..037  Profile management              SGP.32 §3.4
 *   REQ-040..043  Transport                       SGP.32 §4
 *   REQ-050..052  Security / TLS                  SGP.32 §5
 *   REQ-060..064  Event system                    SGP.32 §6
 *   REQ-070..072  Error handling                  SGP.32 §7
 *   REQ-080..082  Diagnostics & logging           SGP.32 §8
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ──────────────────────────────────────────────────────────────────────────────
 * Version                                                          [REQ-004]
 * ────────────────────────────────────────────────────────────────────────── */
#define IPAD_VERSION_MAJOR  1
#define IPAD_VERSION_MINOR  0
#define IPAD_VERSION_PATCH  0
#define IPAD_VERSION_STRING "1.0.0"

/* ──────────────────────────────────────────────────────────────────────────────
 * Status codes                                                     [REQ-070]
 * ────────────────────────────────────────────────────────────────────────── */
typedef int32_t ipad_status_t;

#define IPAD_OK                     ((ipad_status_t)  0)
#define IPAD_PENDING                ((ipad_status_t)  1)
#define IPAD_ERR_INVALID_PARAM      ((ipad_status_t) -1)
#define IPAD_ERR_NOT_INITIALIZED    ((ipad_status_t) -2)
#define IPAD_ERR_HAL_FAILURE        ((ipad_status_t) -3)
#define IPAD_ERR_TRANSPORT          ((ipad_status_t) -4)
#define IPAD_ERR_TLS_HANDSHAKE      ((ipad_status_t) -5)
#define IPAD_ERR_EIM_REJECTED       ((ipad_status_t) -6)
#define IPAD_ERR_PROFILE_NOT_FOUND  ((ipad_status_t) -7)
#define IPAD_ERR_PROFILE_ACTIVE     ((ipad_status_t) -8)
#define IPAD_ERR_NO_MEMORY          ((ipad_status_t) -9)
#define IPAD_ERR_CRYPTO             ((ipad_status_t) -10)
#define IPAD_ERR_TIMEOUT            ((ipad_status_t) -11)
#define IPAD_ERR_BUSY               ((ipad_status_t) -12)
#define IPAD_ERR_NOT_SUPPORTED      ((ipad_status_t) -13)
#define IPAD_ERR_TELSDK             ((ipad_status_t) -14)  /**< TelSDK backend error */
#define IPAD_ERR_INTERNAL           ((ipad_status_t) -99)

/* ──────────────────────────────────────────────────────────────────────────────
 * Opaque handle
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct ipad_ctx_s *ipad_handle_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Base types
 * ────────────────────────────────────────────────────────────────────────── */
#define IPAD_EID_LEN    16   /**< 32 BCD digits stored as 16 bytes — [REQ-010] */
#define IPAD_ICCID_LEN  10   /**< 20 BCD digits stored as 10 bytes */
#define IPAD_STR_MAX    64

typedef uint8_t ipad_eid_t[IPAD_EID_LEN];
typedef uint8_t ipad_iccid_t[IPAD_ICCID_LEN];

/** Transport protocols supported by the eIM interface.          [REQ-040..043] */
typedef enum {
    IPAD_TRANSPORT_TCP  = 0,  /**< [REQ-040] TCP/IP to eIM  SGP.32 §4.1 */
    IPAD_TRANSPORT_COAP = 1,  /**< [REQ-041] CoAP to eIM    SGP.32 §4.2 */
    IPAD_TRANSPORT_MQTT = 2,  /**< [REQ-042] MQTT to eIM    SGP.32 §4.3 */
    IPAD_TRANSPORT_SMS  = 3,  /**< [REQ-043] SMS to eIM     SGP.32 §4.4 */
} ipad_transport_t;

/** Log levels.                                                   [REQ-081] */
typedef enum {
    IPAD_LOG_NONE  = 0,
    IPAD_LOG_ERROR = 1,
    IPAD_LOG_WARN  = 2,
    IPAD_LOG_INFO  = 3,
    IPAD_LOG_DEBUG = 4,
} ipad_loglevel_t;

/** Profile lifecycle states.                                [REQ-032..034] */
typedef enum {
    IPAD_PROFILE_ENABLED          = 0,  /**< [REQ-032] Active profile */
    IPAD_PROFILE_DISABLED         = 1,  /**< [REQ-034] Inactive profile */
    IPAD_PROFILE_PENDING_INSTALL  = 2,  /**< [REQ-023] Download in progress */
    IPAD_PROFILE_PENDING_ENABLE   = 3,
    IPAD_PROFILE_ERROR            = 4,
} ipad_profile_state_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Profile descriptor                                              [REQ-030]
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    ipad_iccid_t         iccid;
    ipad_profile_state_t state;
    char                 nickname[IPAD_STR_MAX];     /**< [REQ-036] */
    char                 provider[IPAD_STR_MAX];
    char                 profile_name[IPAD_STR_MAX];
    bool                 is_test_profile;
    uint32_t             slot_id;
} ipad_profile_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * eUICC info                                                      [REQ-011]
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    ipad_eid_t eid;              /**< [REQ-010] 16-byte binary EID */
    char       eid_str[33];      /**< null-terminated ASCII hex */
    char       os_version[IPAD_STR_MAX];
    uint32_t   profile_capacity; /**< max simultaneous profiles */
    uint32_t   free_mem_kb;
} ipad_euicc_info_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * TLS configuration                                          [REQ-050..052]
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    const char *ca_cert_path;    /**< [REQ-050] PEM CA bundle */
    const char *client_cert_path;/**< [REQ-051] mutual TLS — client certificate */
    const char *client_key_path; /**< [REQ-051] mutual TLS — client private key */
    bool        verify_peer;     /**< [REQ-052] enforce peer certificate check */
    uint16_t    tls_version_min; /**< [REQ-050] 0x0303=TLS 1.2, 0x0304=TLS 1.3 */
} ipad_tls_cfg_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Configuration                                               [REQ-001..003]
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    const char       *eim_url;        /**< eIM endpoint, e.g. "coaps://eim.host:5684" */
    uint16_t          eim_port;
    ipad_transport_t  transport;      /**< [REQ-040..043] */
    ipad_tls_cfg_t    tls;            /**< [REQ-050..052] */
    uint32_t          timeout_ms;     /**< [REQ-072] default: 30000 */
    uint8_t           retry_count;    /**< [REQ-071] default: 3     */
    ipad_loglevel_t   log_level;      /**< [REQ-081] */
    uint32_t          slot_id;        /**< SA525 SIM slot (0-based) */
    void             *user_ctx;
} ipad_config_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Download parameters                                         [REQ-020..024]
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    const char    *activation_code;  /**< [REQ-020] "LPA:1$host$matchid" */
    const char    *confirmation_code;/**< [REQ-021] optional */
    bool           auto_enable;      /**< [REQ-024] enable immediately after download */
    uint32_t       timeout_ms;       /**< [REQ-072] 0 = use global */
} ipad_dl_params_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Events                                                       [REQ-060..064]
 * ────────────────────────────────────────────────────────────────────────── */
typedef enum {
    IPAD_EVT_PROFILE_INSTALLED   = (1u << 0), /**< [REQ-061] download complete */
    IPAD_EVT_PROFILE_ENABLED     = (1u << 1), /**< [REQ-061] profile activated */
    IPAD_EVT_PROFILE_DISABLED    = (1u << 2), /**< [REQ-061] profile deactivated */
    IPAD_EVT_PROFILE_DELETED     = (1u << 3), /**< [REQ-061] profile removed */
    IPAD_EVT_EIM_CONNECTED       = (1u << 4), /**< [REQ-062] eIM link up */
    IPAD_EVT_EIM_DISCONNECTED    = (1u << 5), /**< [REQ-062] eIM link down */
    IPAD_EVT_NETWORK_ATTACHED    = (1u << 6),
    IPAD_EVT_NETWORK_DETACHED    = (1u << 7),
    IPAD_EVT_DOWNLOAD_PROGRESS   = (1u << 8), /**< [REQ-023] download % update */
    IPAD_EVT_ERROR               = (1u << 9),
    IPAD_EVT_ALL                 = 0xFFFFFFFFu,
} ipad_event_type_t;

typedef struct {
    ipad_event_type_t  type;
    ipad_iccid_t       iccid;         /**< relevant profile, if any */
    ipad_status_t      status;
    uint8_t            progress_pct;  /**< [REQ-023] for DOWNLOAD_PROGRESS */
    char               detail[128];   /**< human-readable detail  */
} ipad_event_t;

typedef void (*ipad_event_cb_t)(ipad_handle_t hdl,
                                 const ipad_event_t *evt,
                                 void *user_ctx);

typedef uint32_t ipad_sub_id_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Async callback                                                  [REQ-022]
 * ────────────────────────────────────────────────────────────────────────── */
typedef void (*ipad_callback_t)(ipad_handle_t  hdl,
                                 ipad_status_t  status,
                                 const void    *result,
                                 void          *cb_ctx);

/* ──────────────────────────────────────────────────────────────────────────────
 * Version info                                                    [REQ-004]
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint16_t    major, minor, patch;
    const char *sgp32_revision;   /**< supported SGP.32 spec revision */
    const char *telsdk_version;   /**< TelSDK version linked against    */
} ipad_version_t;

/* ══════════════════════════════════════════════════════════════════════════════
 * API — Lifecycle                                             [REQ-001..005]
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Initialise the IPAd library and connect to TelSDK.          [REQ-001]
 * Must be called before any other ipad_* function.
 */
ipad_status_t ipad_init(const ipad_config_t *cfg, ipad_handle_t *hdl_out);

/**
 * @brief Release all resources and disconnect from TelSDK.           [REQ-002]
 */
ipad_status_t ipad_deinit(ipad_handle_t hdl);

/**
 * @brief Update configuration at runtime (transport, log level, retry). [REQ-003]
 */
ipad_status_t ipad_configure(ipad_handle_t hdl, const ipad_config_t *cfg);

/**
 * @brief Retrieve library and TelSDK version information.            [REQ-004]
 */
ipad_status_t ipad_get_version(ipad_version_t *ver_out);

/**
 * @brief Run internal self-test (HAL, transport, crypto).            [REQ-005]
 * @param[out] result_bitmask  Bitfield of IPAD_SELFTEST_* flags.
 */
ipad_status_t ipad_selftest(ipad_handle_t hdl, uint32_t *result_bitmask);

/* ══════════════════════════════════════════════════════════════════════════════
 * API — eUICC identity                                        [REQ-010..011]
 * ══════════════════════════════════════════════════════════════════════════ */

/** @brief Retrieve the eUICC EID as a 32 BCD-digit (16-byte) value. [REQ-010] */
ipad_status_t ipad_get_eid(ipad_handle_t hdl, ipad_eid_t eid_out);

/** @brief Get eUICC info: EID, OS version, capacity, free memory.   [REQ-011] */
ipad_status_t ipad_get_euicc_info(ipad_handle_t hdl, ipad_euicc_info_t *info_out);

/* ══════════════════════════════════════════════════════════════════════════════
 * API — Profile management                                    [REQ-030..037]
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief List all profiles installed on the eUICC.                   [REQ-030]
 * @param[out] list_out   Caller-allocated array of at least *count_inout entries.
 *                        Pass NULL to query required count.
 * @param[inout] count    In: array capacity. Out: actual count returned.
 */
ipad_status_t ipad_profile_list(ipad_handle_t  hdl,
                                 ipad_profile_t *list_out,
                                 uint8_t        *count_inout);

/** @brief Get a single profile by ICCID.                             [REQ-031] */
ipad_status_t ipad_profile_get(ipad_handle_t   hdl,
                                const ipad_iccid_t iccid,
                                ipad_profile_t *profile_out);

/** @brief Synchronous profile download from SM-DP+ via activation code. [REQ-020] */
ipad_status_t ipad_profile_download(ipad_handle_t        hdl,
                                     const ipad_dl_params_t *params,
                                     ipad_iccid_t          iccid_out);

/** @brief Asynchronous download — returns IPAD_PENDING immediately.  [REQ-022] */
ipad_status_t ipad_profile_download_async(ipad_handle_t           hdl,
                                           const ipad_dl_params_t *params,
                                           ipad_callback_t         cb,
                                           void                   *cb_ctx);

/** @brief Activate a profile (TelSDK setProfile ENABLE).             [REQ-032] */
ipad_status_t ipad_profile_enable(ipad_handle_t hdl, const ipad_iccid_t iccid);

/** @brief Deactivate a profile (TelSDK setProfile DISABLE).          [REQ-034] */
ipad_status_t ipad_profile_disable(ipad_handle_t hdl, const ipad_iccid_t iccid);

/** @brief Permanently delete a profile (TelSDK deleteProfile).       [REQ-035] */
ipad_status_t ipad_profile_delete(ipad_handle_t hdl, const ipad_iccid_t iccid);

/** @brief Update profile nickname.                                   [REQ-036] */
ipad_status_t ipad_profile_set_nickname(ipad_handle_t      hdl,
                                         const ipad_iccid_t iccid,
                                         const char        *nickname);

/** @brief Query current state of a profile.                          [REQ-037] */
ipad_status_t ipad_profile_get_state(ipad_handle_t        hdl,
                                      const ipad_iccid_t   iccid,
                                      ipad_profile_state_t *state_out);

/* ══════════════════════════════════════════════════════════════════════════════
 * API — Events                                                [REQ-060..064]
 * ══════════════════════════════════════════════════════════════════════════ */

/** @brief Subscribe to a bitmask of event types. Returns subscription id. [REQ-060] */
ipad_sub_id_t ipad_event_subscribe(ipad_handle_t     hdl,
                                    uint32_t          event_mask,
                                    ipad_event_cb_t   cb,
                                    void             *user_ctx);

/** @brief Cancel a subscription.                                    [REQ-060] */
ipad_status_t ipad_event_unsubscribe(ipad_handle_t hdl, ipad_sub_id_t sub_id);

/**
 * @brief Pump the event loop for environments without a dedicated thread. [REQ-064]
 * Processes pending events for up to timeout_ms milliseconds.
 */
ipad_status_t ipad_event_pump(ipad_handle_t hdl, uint32_t timeout_ms);

/* ══════════════════════════════════════════════════════════════════════════════
 * API — Diagnostics                                           [REQ-080..082]
 * ══════════════════════════════════════════════════════════════════════════ */
typedef void (*ipad_log_cb_t)(ipad_loglevel_t level,
                               const char     *module,
                               const char     *message,
                               void           *user_ctx);

/** @brief Install a custom log handler.                              [REQ-082] */
ipad_status_t ipad_log_set_handler(ipad_handle_t hdl,
                                    ipad_log_cb_t  cb,
                                    void          *user_ctx);

/** @brief Change the active log level at runtime.                   [REQ-081] */
ipad_status_t ipad_log_set_level(ipad_handle_t hdl, ipad_loglevel_t level);

/** @brief Export diagnostic snapshot as a null-terminated JSON string. [REQ-080] */
ipad_status_t ipad_diag_export_json(ipad_handle_t hdl,
                                     char         *buf,
                                     size_t        buf_len);

/* ══════════════════════════════════════════════════════════════════════════════
 * Utilities
 * ══════════════════════════════════════════════════════════════════════════ */

/** @brief Human-readable string for a status code.                  [REQ-070] */
const char *ipad_strerror(ipad_status_t status);

/** @brief Convert binary ICCID to null-terminated ASCII hex string (21 bytes). */
void ipad_iccid_to_str(const ipad_iccid_t iccid, char *str_out);

/** @brief Convert binary EID to null-terminated ASCII hex string (33 bytes). */
void ipad_eid_to_str(const ipad_eid_t eid, char *str_out);

#ifdef __cplusplus
}
#endif
